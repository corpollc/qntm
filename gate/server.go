package gate

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MemoryConversationStore implements ConversationReader and ConversationWriter
// using in-memory storage. For production, this would read from qntm group conversations.
type MemoryConversationStore struct {
	mu       sync.RWMutex
	messages map[string][]GateConversationMessage // org_id -> messages
}

// NewMemoryConversationStore creates a new in-memory conversation store.
func NewMemoryConversationStore() *MemoryConversationStore {
	return &MemoryConversationStore{
		messages: make(map[string][]GateConversationMessage),
	}
}

func (s *MemoryConversationStore) ReadGateMessages(orgID string) ([]GateConversationMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	msgs := s.messages[orgID]
	// Return a copy
	result := make([]GateConversationMessage, len(msgs))
	copy(result, msgs)
	return result, nil
}

func (s *MemoryConversationStore) WriteGateMessage(orgID string, msg *GateConversationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages[orgID] = append(s.messages[orgID], *msg)
	return nil
}

// Server is the qntm-gate HTTP server.
type Server struct {
	OrgStore   *OrgStore
	ConvStore  *MemoryConversationStore
	AdminToken string
	mux        *http.ServeMux
}

// NewServer creates a new gate server that requires an admin token.
// For production use, call NewServerWithToken(token) or set QNTM_GATE_TOKEN.
// This zero-arg constructor is kept for tests only — it starts with no auth
// (equivalent to --dev mode).
func NewServer() *Server {
	return NewServerWithToken("")
}

// NewServerWithToken creates a gate server requiring the given admin token for admin endpoints.
func NewServerWithToken(adminToken string) *Server {
	s := &Server{
		OrgStore:   NewOrgStore(),
		ConvStore:  NewMemoryConversationStore(),
		AdminToken: adminToken,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.AdminToken == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	expected := "Bearer " + s.AdminToken
	if auth != expected {
		writeErr(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func (s *Server) routes() {
	s.mux.HandleFunc("/v1/orgs", s.handleCreateOrg)
	s.mux.HandleFunc("/v1/orgs/", s.handleOrgs)
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	var req struct {
		ID      string          `json:"id"`
		Signers []Signer        `json:"signers"`
		Rules   []ThresholdRule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	o := &Org{ID: req.ID, Signers: req.Signers, Rules: req.Rules}
	if err := s.OrgStore.Create(o); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/orgs/")
	parts := strings.SplitN(path, "/", 4)

	if len(parts) < 1 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "org_id required")
		return
	}

	orgID := parts[0]

	if len(parts) >= 2 && parts[1] == "credentials" {
		s.handleCredentials(w, r, orgID)
		return
	}

	// POST /v1/orgs/{org_id}/messages — post a gate message to the conversation
	if len(parts) >= 2 && parts[1] == "messages" {
		s.handlePostMessage(w, r, orgID)
		return
	}

	// POST /v1/orgs/{org_id}/execute/{request_id} — scan conversation and execute if threshold met
	if len(parts) >= 3 && parts[1] == "execute" {
		requestID := parts[2]
		s.handleExecute(w, r, orgID, requestID)
		return
	}

	// GET /v1/orgs/{org_id}/scan/{request_id} — scan conversation without executing
	if len(parts) >= 3 && parts[1] == "scan" {
		requestID := parts[2]
		s.handleScan(w, r, orgID, requestID)
		return
	}

	if len(parts) == 1 {
		o, err := s.OrgStore.Get(orgID)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, o)
		return
	}

	writeErr(w, http.StatusNotFound, "not found")
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request, orgID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var cred Credential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := s.OrgStore.AddCredential(orgID, &cred); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "credential added", "id": cred.ID})
}

// handlePostMessage accepts a gate message (request or approval) and stores it in the conversation.
// In production, this would be posted to the qntm group directly. The HTTP endpoint
// provides a convenient way to feed messages into the conversation for the gate to scan.
func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request, orgID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Verify org exists
	org, err := s.OrgStore.Get(orgID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	var msg GateConversationMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	msg.OrgID = orgID

	// Validate the message
	if msg.Type == GateMessageRequest {
		// Verify request signature
		signer := org.FindSignerByKID(msg.SignerKID)
		if signer == nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown signer %q in org %q", msg.SignerKID, orgID))
			return
		}
		payloadHash := ComputePayloadHash(msg.Payload)
		signable := &GateSignable{
			OrgID: orgID, RequestID: msg.RequestID, Verb: msg.Verb,
			TargetEndpoint: msg.TargetEndpoint, TargetService: msg.TargetService,
			PayloadHash: payloadHash,
		}
		sigBytes, err := decodeBase64Flex(msg.Signature)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid signature encoding")
			return
		}
		if err := VerifyRequest(signer.PublicKey, signable, sigBytes); err != nil {
			writeErr(w, http.StatusBadRequest, "signature verification failed: "+err.Error())
			return
		}

		// Check for duplicate request ID
		existing, _ := s.ConvStore.ReadGateMessages(orgID)
		for _, m := range existing {
			if m.Type == GateMessageRequest && m.RequestID == msg.RequestID {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("request %q already exists (replay protection)", msg.RequestID))
				return
			}
		}

		log.Printf("[AUDIT] REQUEST org=%s req=%s verb=%s service=%s endpoint=%s by=%s",
			orgID, msg.RequestID, msg.Verb, msg.TargetService, msg.TargetEndpoint, msg.SignerKID)
	} else if msg.Type == GateMessageApproval {
		// Verify approval signature
		signer := org.FindSignerByKID(msg.SignerKID)
		if signer == nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown signer %q", msg.SignerKID))
			return
		}
		// We need the original request to verify the approval
		existing, _ := s.ConvStore.ReadGateMessages(orgID)
		var reqMsg *GateConversationMessage
		for i := range existing {
			if existing[i].Type == GateMessageRequest && existing[i].RequestID == msg.RequestID {
				reqMsg = &existing[i]
				break
			}
		}
		if reqMsg == nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("request %q not found", msg.RequestID))
			return
		}

		// Check expiration
		if reqMsg.ExpiresAt.Before(time.Now()) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("request %q has expired", msg.RequestID))
			return
		}

		payloadHash := ComputePayloadHash(reqMsg.Payload)
		signable := &GateSignable{
			OrgID: orgID, RequestID: msg.RequestID, Verb: reqMsg.Verb,
			TargetEndpoint: reqMsg.TargetEndpoint, TargetService: reqMsg.TargetService,
			PayloadHash: payloadHash,
		}
		reqHash, err := HashRequest(signable)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "hash request: "+err.Error())
			return
		}
		approvalSignable := &ApprovalSignable{
			OrgID: orgID, RequestID: msg.RequestID, RequestHash: reqHash,
		}
		sigBytes, err := decodeBase64Flex(msg.Signature)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid signature encoding")
			return
		}
		if err := VerifyApproval(signer.PublicKey, approvalSignable, sigBytes); err != nil {
			writeErr(w, http.StatusBadRequest, "approval signature verification failed: "+err.Error())
			return
		}

		log.Printf("[AUDIT] APPROVAL org=%s req=%s by=%s", orgID, msg.RequestID, msg.SignerKID)
	} else {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown message type %q", msg.Type))
		return
	}

	// Store in conversation
	if err := s.ConvStore.WriteGateMessage(orgID, &msg); err != nil {
		writeErr(w, http.StatusInternalServerError, "store message: "+err.Error())
		return
	}

	// Auto-execute: scan the conversation and execute if threshold met
	org2, _ := s.OrgStore.Get(orgID)
	result, err := ExecuteIfReady(msg.RequestID, org2, s.ConvStore, s.OrgStore)
	if err != nil {
		// Not an error if just pending or expired — return the scan result
		if result != nil {
			writeJSON(w, http.StatusAccepted, result)
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if result.Status == StatusExecuted {
		writeJSON(w, http.StatusOK, result)
	} else {
		writeJSON(w, http.StatusAccepted, result)
	}
}

// handleExecute scans the conversation for a request and executes if threshold met.
func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request, orgID, requestID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	org, err := s.OrgStore.Get(orgID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	result, err := ExecuteIfReady(requestID, org, s.ConvStore, s.OrgStore)
	if err != nil {
		if result != nil {
			writeJSON(w, http.StatusBadRequest, result)
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if result.Status == StatusExecuted {
		writeJSON(w, http.StatusOK, result)
	} else {
		writeJSON(w, http.StatusAccepted, result)
	}
}

// handleScan scans the conversation for a request without executing.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, orgID, requestID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	org, err := s.OrgStore.Get(orgID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	messages, err := s.ConvStore.ReadGateMessages(orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	scan, err := ScanConversation(messages, requestID, org)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !scan.Found {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("request %q not found in conversation", requestID))
		return
	}

	writeJSON(w, http.StatusOK, scan)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf("%s", msg)})
}
