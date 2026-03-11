// Gateway Protocol Reference
//
// The gateway is a headless qntm conversation participant. It has its own
// Ed25519 identity, joins conversations like any other participant, and
// processes gate.* messages to authorize and execute API requests on behalf
// of an organization.
//
// Message Types
//
//   gate.promote   — Sent by a conversation admin to register the conversation
//                    as gate-enabled. Contains the org_id, list of authorized
//                    signers (KID + Ed25519 public key), and threshold rules.
//                    The gateway builds its per-conversation state from this.
//
//   gate.secret    — Provisions an API credential to the gateway. The secret
//                    value is encrypted to the gateway's public key using NaCl
//                    box (X25519-XSalsa20-Poly1305, with Ed25519-to-X25519 key
//                    conversion). Only the gateway can decrypt it.
//
//   gate.config    — Updates threshold rules for an already-promoted
//                    conversation. Replaces the existing rule set.
//
//   gate.request   — Submits an API request for authorization. Contains the
//                    HTTP verb, target service/endpoint/URL, optional payload,
//                    expiration time, and the submitter's Ed25519 signature.
//                    Counts as the first approval signature.
//
//   gate.approval  — Adds a co-signature to a pending request. Contains the
//                    request_id and the approver's Ed25519 signature over a
//                    hash of the original request.
//
//   gate.executed  — Posted by the gateway after executing a request. Records
//                    the HTTP status code and timestamp. Prevents re-execution.
//
// Promotion Flow
//
//   1. Admin sends gate.promote with org_id, signers, and threshold rules.
//   2. Gateway stores per-conversation state (participants, rules, credentials).
//   3. Admin sends gate.secret messages to provision API credentials.
//
// Request/Approval/Execution Flow
//
//   1. Signer sends gate.request with a signed API request.
//   2. Other signers send gate.approval messages co-signing the request.
//   3. Gateway counts unique valid signatures against the threshold rule that
//      matches the request's (service, endpoint, verb) triple.
//   4. When M valid signatures are collected, the gateway:
//      a. Decrypts the credential for the target service.
//      b. Injects the credential into the HTTP request header.
//      c. Executes the HTTP request.
//      d. Posts gate.executed back to the conversation.
//
// Third-Party Implementation Requirements
//
//   A compatible gateway implementation must:
//   - Hold an Ed25519 identity and participate in qntm conversations.
//   - Process gate.promote to build per-conversation signer/rule state.
//   - Accept gate.secret and decrypt using NaCl box (Ed25519 -> X25519).
//   - Verify Ed25519 signatures on gate.request and gate.approval messages
//     using the canonical signable format (see gate/signing.go).
//   - Enforce threshold rules: match (service, endpoint, verb) with priority
//     exact > wildcard, require M unique valid signatures.
//   - Post gate.executed after successful execution to prevent re-execution.
//   - Never log or expose decrypted credential values.

package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

// GateMessageType constants for gateway-specific message types.
const (
	GateMessagePromote GateMessageType = "gate.promote"
	GateMessageSecret  GateMessageType = "gate.secret"
	GateMessageConfig  GateMessageType = "gate.config"
)

// ConversationGateState holds per-conversation gate state.
type ConversationGateState struct {
	ConversationID types.ConversationID
	OrgID          string
	Rules          []ThresholdRule
	Credentials    map[string]*Credential
	Participants   map[string]ed25519.PublicKey // kid (base64url) -> pubkey
}

// PromotePayload is the body of a gate.promote message.
type PromotePayload struct {
	OrgID   string          `json:"org_id"`
	Signers []Signer        `json:"signers"`
	Rules   []ThresholdRule `json:"rules"`
}

// ConfigPayload is the body of a gate.config message.
type ConfigPayload struct {
	Rules []ThresholdRule `json:"rules"`
}

// Gateway is a qntm conversation participant that polls its dropbox for
// encrypted gate.* messages, processes them, and executes authorized API
// requests when thresholds are met.
type Gateway struct {
	Identity      *types.Identity
	DropboxURL    string
	ConfigDir     string
	Conversations map[types.ConversationID]*ConversationGateState
	QntmConvs     map[types.ConversationID]*types.Conversation // qntm conversation objects for decrypt
	Catalogs      map[string]*RecipeCatalog

	// Vault for credential encryption at rest.
	Vault VaultProvider

	// PollInterval controls how often the gateway checks for new messages.
	PollInterval time.Duration

	// HealthAddr is the address for the optional health HTTP endpoint.
	// Empty string disables the health endpoint.
	HealthAddr string

	// Storage is the dropbox storage provider. If nil, the gateway creates
	// an HTTPStorageProvider from DropboxURL.
	Storage dropbox.StorageProvider

	// SequenceCursors tracks the last seen sequence per conversation.
	SequenceCursors map[types.ConversationID]int64

	// convMessageStores holds per-conversation in-memory gate message stores.
	convMessageStores map[types.ConversationID]*MemoryConversationStore

	mu sync.RWMutex
}

// NewGateway creates a new Gateway with the given identity.
func NewGateway(id *types.Identity) *Gateway {
	return &Gateway{
		Identity:          id,
		Conversations:     make(map[types.ConversationID]*ConversationGateState),
		QntmConvs:         make(map[types.ConversationID]*types.Conversation),
		Catalogs:          make(map[string]*RecipeCatalog),
		Vault:             NoopVault{},
		PollInterval:      5 * time.Second,
		SequenceCursors:   make(map[types.ConversationID]int64),
		convMessageStores: make(map[types.ConversationID]*MemoryConversationStore),
	}
}

// RegisterConversation adds a qntm conversation to the gateway's polling set.
func (gw *Gateway) RegisterConversation(conv *types.Conversation) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.QntmConvs[conv.ID] = conv
}

// GetConversationState returns the gate state for a conversation, or nil.
func (gw *Gateway) GetConversationState(convID types.ConversationID) *ConversationGateState {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.Conversations[convID]
}

// Run starts the gateway polling loop. It blocks until the context is cancelled.
func (gw *Gateway) Run(ctx context.Context) error {
	idMgr := identity.NewManager()
	log.Printf("[gateway] starting gateway kid=%s", idMgr.KeyIDToString(gw.Identity.KeyID))

	storage := gw.getStorage()
	dropboxMgr := dropbox.NewManager(storage)
	messageMgr := message.NewManager()

	// Start optional health endpoint
	if gw.HealthAddr != "" {
		go gw.serveHealth(ctx)
	}

	ticker := time.NewTicker(gw.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[gateway] shutting down: %v", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			gw.pollAllConversations(ctx, dropboxMgr, messageMgr)
		}
	}
}

// pollAllConversations polls every registered conversation for new messages.
func (gw *Gateway) pollAllConversations(ctx context.Context, dropboxMgr *dropbox.Manager, messageMgr *message.Manager) {
	gw.mu.RLock()
	convs := make([]*types.Conversation, 0, len(gw.QntmConvs))
	for _, conv := range gw.QntmConvs {
		convs = append(convs, conv)
	}
	gw.mu.RUnlock()

	for _, conv := range convs {
		if ctx.Err() != nil {
			return
		}

		gw.mu.RLock()
		fromSeq := gw.SequenceCursors[conv.ID]
		gw.mu.RUnlock()

		messages, upToSeq, err := dropboxMgr.ReceiveMessagesFromSequence(
			gw.Identity, conv, fromSeq, 200,
		)
		if err != nil {
			log.Printf("[gateway] poll error conv=%x: %v", conv.ID[:4], err)
			continue
		}

		gw.mu.Lock()
		gw.SequenceCursors[conv.ID] = upToSeq
		gw.mu.Unlock()

		for _, msg := range messages {
			if err := gw.processMessage(conv, msg, dropboxMgr); err != nil {
				log.Printf("[gateway] process error conv=%x body_type=%s: %v",
					conv.ID[:4], msg.Inner.BodyType, err)
			}
		}
	}
}

// processMessage routes a decrypted message to the appropriate handler based on body_type.
func (gw *Gateway) processMessage(conv *types.Conversation, msg *types.Message, dropboxMgr *dropbox.Manager) error {
	bodyType := GateMessageType(msg.Inner.BodyType)

	switch bodyType {
	case GateMessagePromote:
		return gw.handlePromote(conv, msg)
	case GateMessageSecret:
		return gw.handleSecret(conv, msg)
	case GateMessageConfig:
		return gw.handleConfig(conv, msg)
	case GateMessageRequest:
		return gw.handleRequest(conv, msg, dropboxMgr)
	case GateMessageApproval:
		return gw.handleApproval(conv, msg, dropboxMgr)
	default:
		// Ignore non-gate messages silently
		return nil
	}
}

// handlePromote registers a conversation as gate-enabled with threshold rules.
func (gw *Gateway) handlePromote(conv *types.Conversation, msg *types.Message) error {
	var payload PromotePayload
	if err := json.Unmarshal(msg.Inner.Body, &payload); err != nil {
		return fmt.Errorf("unmarshal promote payload: %w", err)
	}

	if payload.OrgID == "" {
		return fmt.Errorf("promote message missing org_id")
	}

	participants := make(map[string]ed25519.PublicKey)
	for _, s := range payload.Signers {
		kid := s.KID
		if kid == "" && len(s.PublicKey) > 0 {
			kid = KIDFromPublicKey(s.PublicKey)
		}
		participants[kid] = s.PublicKey
	}

	state := &ConversationGateState{
		ConversationID: conv.ID,
		OrgID:          payload.OrgID,
		Rules:          payload.Rules,
		Credentials:    make(map[string]*Credential),
		Participants:   participants,
	}

	gw.mu.Lock()
	gw.Conversations[conv.ID] = state
	gw.mu.Unlock()

	log.Printf("[gateway] PROMOTE conv=%x org=%s signers=%d rules=%d",
		conv.ID[:4], payload.OrgID, len(payload.Signers), len(payload.Rules))
	return nil
}

// handleSecret decrypts and stores a credential from a gate.secret message.
func (gw *Gateway) handleSecret(conv *types.Conversation, msg *types.Message) error {
	gw.mu.RLock()
	state := gw.Conversations[conv.ID]
	gw.mu.RUnlock()

	if state == nil {
		return fmt.Errorf("gate.secret received for non-promoted conversation")
	}

	// Look up sender's public key from the message's sender KID
	var payload SecretPayload
	if err := json.Unmarshal(msg.Inner.Body, &payload); err != nil {
		return fmt.Errorf("unmarshal secret payload: %w", err)
	}

	senderPubKey, ok := state.Participants[payload.SenderKID]
	if !ok {
		return fmt.Errorf("unknown sender kid %q in gate.secret", payload.SenderKID)
	}

	// Decrypt the secret using gateway's private key and sender's public key
	_, decryptedValue, err := ParseSecretPayload(
		gw.Identity.PrivateKey,
		senderPubKey,
		msg.Inner.Body,
	)
	if err != nil {
		return fmt.Errorf("parse/decrypt secret: %w", err)
	}

	// Store as a Credential in the conversation state
	cred := &Credential{
		ID:          payload.SecretID,
		Service:     payload.Service,
		HeaderName:  payload.HeaderName,
		HeaderValue: payload.HeaderTemplate,
	}

	// If a VaultProvider is available, encrypt the value at rest
	if gw.Vault != nil {
		encrypted, err := gw.Vault.Encrypt(decryptedValue)
		if err != nil {
			return fmt.Errorf("encrypt credential at rest: %w", err)
		}
		cred.Value = encrypted
	} else {
		cred.Value = decryptedValue
	}

	gw.mu.Lock()
	state.Credentials[payload.Service] = cred
	gw.mu.Unlock()

	log.Printf("[gateway] SECRET stored conv=%x org=%s service=%s secret_id=%s sender=%s",
		conv.ID[:4], state.OrgID, payload.Service, payload.SecretID, payload.SenderKID)
	return nil
}

// handleConfig updates threshold rules for a gate-enabled conversation.
func (gw *Gateway) handleConfig(conv *types.Conversation, msg *types.Message) error {
	gw.mu.RLock()
	state := gw.Conversations[conv.ID]
	gw.mu.RUnlock()

	if state == nil {
		return fmt.Errorf("gate.config received for non-promoted conversation")
	}

	var payload ConfigPayload
	if err := json.Unmarshal(msg.Inner.Body, &payload); err != nil {
		return fmt.Errorf("unmarshal config payload: %w", err)
	}

	gw.mu.Lock()
	state.Rules = payload.Rules
	gw.mu.Unlock()

	log.Printf("[gateway] CONFIG updated conv=%x org=%s rules=%d",
		conv.ID[:4], state.OrgID, len(payload.Rules))
	return nil
}

// handleRequest processes a gate.request message: validates the signature and
// checks if the threshold is already met (e.g., M=1).
func (gw *Gateway) handleRequest(conv *types.Conversation, msg *types.Message, dropboxMgr *dropbox.Manager) error {
	gw.mu.RLock()
	state := gw.Conversations[conv.ID]
	gw.mu.RUnlock()

	if state == nil {
		return fmt.Errorf("gate.request received for non-promoted conversation")
	}

	var gateMsg GateConversationMessage
	if err := json.Unmarshal(msg.Inner.Body, &gateMsg); err != nil {
		return fmt.Errorf("unmarshal gate.request body: %w", err)
	}
	gateMsg.OrgID = state.OrgID

	log.Printf("[gateway] REQUEST conv=%x org=%s req=%s verb=%s service=%s by=%s",
		conv.ID[:4], state.OrgID, gateMsg.RequestID, gateMsg.Verb,
		gateMsg.TargetService, gateMsg.SignerKID)

	// Store in per-conversation message store for threshold scanning
	if err := gw.StoreGateMessage(conv.ID, state.OrgID, &gateMsg); err != nil {
		return fmt.Errorf("store gate message: %w", err)
	}

	return gw.checkAndExecute(conv, state, gateMsg.RequestID, dropboxMgr)
}

// handleApproval processes a gate.approval message and checks if threshold is now met.
func (gw *Gateway) handleApproval(conv *types.Conversation, msg *types.Message, dropboxMgr *dropbox.Manager) error {
	gw.mu.RLock()
	state := gw.Conversations[conv.ID]
	gw.mu.RUnlock()

	if state == nil {
		return fmt.Errorf("gate.approval received for non-promoted conversation")
	}

	var gateMsg GateConversationMessage
	if err := json.Unmarshal(msg.Inner.Body, &gateMsg); err != nil {
		return fmt.Errorf("unmarshal gate.approval body: %w", err)
	}

	log.Printf("[gateway] APPROVAL conv=%x org=%s req=%s by=%s",
		conv.ID[:4], state.OrgID, gateMsg.RequestID, gateMsg.SignerKID)

	// Store in per-conversation message store for threshold scanning
	if err := gw.StoreGateMessage(conv.ID, state.OrgID, &gateMsg); err != nil {
		return fmt.Errorf("store gate message: %w", err)
	}

	return gw.checkAndExecute(conv, state, gateMsg.RequestID, dropboxMgr)
}

// checkAndExecute builds an Org from conversation gate state, collects all
// gate messages for the conversation, scans them, and executes if the
// threshold is met.
func (gw *Gateway) checkAndExecute(
	conv *types.Conversation,
	state *ConversationGateState,
	requestID string,
	dropboxMgr *dropbox.Manager,
) error {
	// Build an Org from conversation gate state
	org := gw.buildOrg(state)

	// Collect gate messages from the gateway's in-memory message store
	gw.mu.RLock()
	msgStore := gw.getConvMessageStore(conv.ID)
	gw.mu.RUnlock()

	// Use the existing ScanConversation + ExecuteIfReady infrastructure
	messages, err := msgStore.ReadGateMessages(state.OrgID)
	if err != nil {
		return fmt.Errorf("read gate messages: %w", err)
	}

	scan, err := ScanConversation(messages, requestID, org)
	if err != nil {
		return fmt.Errorf("scan conversation: %w", err)
	}

	if !scan.Found {
		log.Printf("[gateway] request %s not found in conversation state", requestID)
		return nil
	}

	if scan.Status == StatusExecuted {
		log.Printf("[gateway] request %s already executed", requestID)
		return nil
	}

	if scan.Expired {
		log.Printf("[gateway] request %s has expired", requestID)
		return nil
	}

	log.Printf("[gateway] request %s: %d/%d signatures, threshold_met=%v",
		requestID, len(scan.SignerKIDs), scan.Threshold, scan.ThresholdMet)

	if !scan.ThresholdMet {
		return nil
	}

	// Threshold met -- execute
	orgStore := gw.buildOrgStore(state)
	result, err := ExecuteIfReady(requestID, org, msgStore, orgStore, gw.Vault)
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}

	if result.Status == StatusExecuted {
		log.Printf("[gateway] EXECUTED request=%s service=%s status=%d",
			requestID, scan.Request.TargetService,
			result.ExecutionResult.StatusCode)

		// Post gate.executed back to the conversation
		executedMsg := GateConversationMessage{
			Type:                GateMessageExecuted,
			OrgID:               state.OrgID,
			RequestID:           requestID,
			ExecutedAt:          time.Now().UTC(),
			ExecutionStatusCode: result.ExecutionResult.StatusCode,
		}
		executedBody, err := json.Marshal(executedMsg)
		if err != nil {
			return fmt.Errorf("marshal executed message: %w", err)
		}

		if err := gw.sendMessage(conv, string(GateMessageExecuted), executedBody, dropboxMgr); err != nil {
			return fmt.Errorf("send executed message: %w", err)
		}
	}

	return nil
}

// sendMessage creates and sends an encrypted qntm message to a conversation.
func (gw *Gateway) sendMessage(conv *types.Conversation, bodyType string, body []byte, dropboxMgr *dropbox.Manager) error {
	messageMgr := message.NewManager()
	envelope, err := messageMgr.CreateMessage(
		gw.Identity,
		conv,
		bodyType,
		body,
		nil,
		messageMgr.DefaultTTL(),
	)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}

	if _, err := dropboxMgr.SendMessageWithSequence(envelope); err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	return nil
}

// buildOrg constructs an Org from the conversation gate state.
func (gw *Gateway) buildOrg(state *ConversationGateState) *Org {
	signers := make([]Signer, 0, len(state.Participants))
	for kid, pubkey := range state.Participants {
		signers = append(signers, Signer{
			KID:       kid,
			PublicKey: pubkey,
		})
	}

	creds := make(map[string]*Credential, len(state.Credentials))
	for k, v := range state.Credentials {
		cp := *v
		creds[k] = &cp
	}

	return &Org{
		ID:          state.OrgID,
		Signers:     signers,
		Rules:       state.Rules,
		Credentials: creds,
	}
}

// buildOrgStore creates a temporary OrganizationStore containing just this conversation's org.
func (gw *Gateway) buildOrgStore(state *ConversationGateState) OrganizationStore {
	store := NewOrgStore()
	org := gw.buildOrg(state)
	_ = store.Create(org)
	return store
}

// getConvMessageStore returns a MessageStore that maps gate messages for a
// conversation. The gateway accumulates gate messages in memory as it
// processes them.
func (gw *Gateway) getConvMessageStore(convID types.ConversationID) MessageStore {
	key := convID
	if _, ok := gw.convMessageStores[key]; !ok {
		if gw.convMessageStores == nil {
			gw.convMessageStores = make(map[types.ConversationID]*MemoryConversationStore)
		}
		gw.convMessageStores[key] = NewMemoryConversationStore()
	}
	return gw.convMessageStores[key]
}

// StoreGateMessage records a gate message in the per-conversation in-memory store.
// Called during message processing to accumulate conversation state.
func (gw *Gateway) StoreGateMessage(convID types.ConversationID, orgID string, msg *GateConversationMessage) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	store := gw.getConvMessageStore(convID)
	return store.WriteGateMessage(orgID, msg)
}

// getStorage returns the storage provider, creating an HTTP one if needed.
func (gw *Gateway) getStorage() dropbox.StorageProvider {
	if gw.Storage != nil {
		return gw.Storage
	}
	return dropbox.NewHTTPStorageProvider(gw.DropboxURL)
}

// serveHealth starts an HTTP health endpoint.
func (gw *Gateway) serveHealth(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		gw.mu.RLock()
		convCount := len(gw.QntmConvs)
		gateCount := len(gw.Conversations)
		gw.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "ok",
			"conversations":      convCount,
			"gate_conversations": gateCount,
		})
	})

	srv := &http.Server{Addr: gw.HealthAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[gateway] health endpoint on %s/health", gw.HealthAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("[gateway] health endpoint error: %v", err)
	}
}
