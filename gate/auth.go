package gate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// RequestStatus tracks the state of an authorization request.
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusExecuted RequestStatus = "executed"
	StatusExpired  RequestStatus = "expired"
)

// GateMessageType distinguishes request vs approval messages in a conversation.
type GateMessageType string

const (
	GateMessageRequest  GateMessageType = "gate.request"
	GateMessageApproval GateMessageType = "gate.approval"
	GateMessageExecuted GateMessageType = "gate.executed"
)

// GateConversationMessage represents a parsed gate message from the qntm conversation.
// The gate server works with these — it never stores them. The conversation IS the state.
type GateConversationMessage struct {
	Type      GateMessageType `json:"type"`
	OrgID     string          `json:"org_id"`
	RequestID string          `json:"request_id"`

	// Request fields (only for GateMessageRequest)
	Verb                string          `json:"verb,omitempty"`
	TargetEndpoint      string          `json:"target_endpoint,omitempty"`
	TargetService       string          `json:"target_service,omitempty"`
	TargetURL           string          `json:"target_url,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
	ExpiresAt           time.Time       `json:"expires_at,omitempty"`
	ExecutedAt          time.Time       `json:"executed_at,omitempty"`
	ExecutionStatusCode int             `json:"execution_status_code,omitempty"`

	// Common fields
	SignerKID string `json:"signer_kid"`
	Signature string `json:"signature"` // base64url
}

// ScanResult is the result of scanning a conversation for a request.
type ScanResult struct {
	Found        bool                     `json:"found"`
	ThresholdMet bool                     `json:"threshold_met"`
	Expired      bool                     `json:"expired"`
	SignerKIDs   []string                 `json:"signer_kids"`
	Threshold    int                      `json:"threshold"`
	Request      *GateConversationMessage `json:"request,omitempty"`
	Status       RequestStatus            `json:"status"`
}

// ExecutionResult holds the result of forwarding the request.
type ExecutionResult struct {
	StatusCode    int    `json:"status_code"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length"`
}

// ExecuteResult is the full result returned from ExecuteIfReady.
type ExecuteResult struct {
	OrgID           string           `json:"org_id"`
	RequestID       string           `json:"request_id"`
	Verb            string           `json:"verb"`
	TargetEndpoint  string           `json:"target_endpoint"`
	TargetService   string           `json:"target_service"`
	Status          RequestStatus    `json:"status"`
	SignatureCount  int              `json:"signature_count"`
	SignerKIDs      []string         `json:"signer_kids"`
	Threshold       int              `json:"threshold"`
	ExpiresAt       time.Time        `json:"expires_at"`
	ExecutionResult *ExecutionResult `json:"execution_result,omitempty"`
}

// ConversationReader provides gate messages from a qntm conversation.
// Implementations read from local storage, dropbox, or any message source.
type ConversationReader interface {
	// ReadGateMessages returns all gate messages for the given org's conversation.
	ReadGateMessages(orgID string) ([]GateConversationMessage, error)
}

// ConversationWriter posts gate messages to a qntm conversation.
type ConversationWriter interface {
	// WriteGateMessage posts a gate message to the org's conversation.
	WriteGateMessage(orgID string, msg *GateConversationMessage) error
}

// ScanConversation scans conversation messages for a specific request,
// verifies signatures, checks expiration, and returns the authorization state.
// This is the core stateless function — no server-side state needed.
func ScanConversation(messages []GateConversationMessage, requestID string, org *Org) (*ScanResult, error) {
	result := &ScanResult{Status: StatusPending}

	// Find the original request
	var reqMsg *GateConversationMessage
	for i := range messages {
		if messages[i].Type == GateMessageRequest && messages[i].RequestID == requestID {
			reqMsg = &messages[i]
			break
		}
	}

	if reqMsg == nil {
		return &ScanResult{Found: false, Status: StatusPending}, nil
	}

	result.Found = true
	result.Request = reqMsg

	// Already executed? Conversation state is authoritative and should prevent
	// any additional downstream execution attempts, even after request expiry.
	for i := range messages {
		msg := &messages[i]
		if msg.Type == GateMessageExecuted && msg.RequestID == requestID {
			result.Status = StatusExecuted
			result.ThresholdMet = true
			return result, nil
		}
	}

	// Check expiration
	if time.Now().After(reqMsg.ExpiresAt) {
		result.Expired = true
		result.Status = StatusExpired
		return result, nil
	}

	// Look up threshold
	threshold, err := org.LookupThreshold(reqMsg.TargetService, reqMsg.TargetEndpoint, reqMsg.Verb)
	if err != nil {
		return nil, fmt.Errorf("lookup threshold: %w", err)
	}
	result.Threshold = threshold

	// Build signable for verification
	payloadHash := ComputePayloadHash(reqMsg.Payload)
	signable := &GateSignable{
		OrgID: reqMsg.OrgID, RequestID: requestID, Verb: reqMsg.Verb,
		TargetEndpoint: reqMsg.TargetEndpoint, TargetService: reqMsg.TargetService,
		TargetURL: reqMsg.TargetURL, ExpiresAtUnix: reqMsg.ExpiresAt.Unix(),
		PayloadHash: payloadHash,
	}

	// Collect valid, unique signatures
	validSigners := make(map[string]bool)

	// Verify the request submitter's signature
	reqSigner := org.FindSignerByKID(reqMsg.SignerKID)
	if reqSigner != nil {
		sigBytes, err := decodeBase64Flex(reqMsg.Signature)
		if err == nil {
			if VerifyRequest(reqSigner.PublicKey, signable, sigBytes) == nil {
				validSigners[reqMsg.SignerKID] = true
			}
		}
	}

	// Verify approval signatures
	reqHash, err := HashRequest(signable)
	if err != nil {
		return nil, fmt.Errorf("hash request: %w", err)
	}
	approvalSignable := &ApprovalSignable{
		OrgID: reqMsg.OrgID, RequestID: requestID, RequestHash: reqHash,
	}

	for i := range messages {
		msg := &messages[i]
		if msg.Type != GateMessageApproval || msg.RequestID != requestID {
			continue
		}
		if validSigners[msg.SignerKID] {
			continue // duplicate signer
		}
		signer := org.FindSignerByKID(msg.SignerKID)
		if signer == nil {
			continue // unknown signer
		}
		sigBytes, err := decodeBase64Flex(msg.Signature)
		if err != nil {
			continue
		}
		if VerifyApproval(signer.PublicKey, approvalSignable, sigBytes) == nil {
			validSigners[msg.SignerKID] = true
		}
	}

	result.SignerKIDs = make([]string, 0, len(validSigners))
	for kid := range validSigners {
		result.SignerKIDs = append(result.SignerKIDs, kid)
	}

	if len(validSigners) >= threshold {
		result.ThresholdMet = true
		result.Status = StatusApproved
	}

	return result, nil
}

// ExecuteIfReady scans the conversation, checks threshold, and executes if ready.
// Returns the result and records a gate.executed marker when execution occurs.
func ExecuteIfReady(requestID string, org *Org, reader ConversationReader, orgStore *OrgStore) (*ExecuteResult, error) {
	messages, err := reader.ReadGateMessages(org.ID)
	if err != nil {
		return nil, fmt.Errorf("read conversation: %w", err)
	}

	scan, err := ScanConversation(messages, requestID, org)
	if err != nil {
		return nil, err
	}

	if !scan.Found {
		return nil, fmt.Errorf("request %q not found in conversation", requestID)
	}

	reqMsg := scan.Request
	result := &ExecuteResult{
		OrgID:          reqMsg.OrgID,
		RequestID:      requestID,
		Verb:           reqMsg.Verb,
		TargetEndpoint: reqMsg.TargetEndpoint,
		TargetService:  reqMsg.TargetService,
		SignatureCount: len(scan.SignerKIDs),
		SignerKIDs:     scan.SignerKIDs,
		Threshold:      scan.Threshold,
		ExpiresAt:      reqMsg.ExpiresAt,
	}

	if scan.Status == StatusExecuted {
		result.Status = StatusExecuted
		return result, nil
	}

	if scan.Expired {
		result.Status = StatusExpired
		return result, fmt.Errorf("request %q has expired", requestID)
	}

	if !scan.ThresholdMet {
		result.Status = StatusPending
		return result, nil
	}

	// Threshold met — execute
	cred, err := orgStore.GetCredentialByService(org.ID, reqMsg.TargetService)
	if err != nil {
		result.Status = StatusApproved
		return result, fmt.Errorf("get credential: %w", err)
	}
	defer cred.Scrub() // zero credential material after use

	var bodyReader io.Reader
	if len(reqMsg.Payload) > 0 {
		bodyReader = strings.NewReader(string(reqMsg.Payload))
	}

	httpReq, err := http.NewRequest(reqMsg.Verb, reqMsg.TargetURL, bodyReader)
	if err != nil {
		result.Status = StatusApproved
		return result, fmt.Errorf("create http request: %w", err)
	}

	// Inject credential
	headerName := cred.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	headerValue := cred.HeaderValue
	if strings.Contains(headerValue, "{value}") {
		headerValue = strings.ReplaceAll(headerValue, "{value}", cred.Value)
	} else {
		headerValue = cred.Value
	}
	httpReq.Header.Set(headerName, headerValue)
	if len(reqMsg.Payload) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		result.Status = StatusApproved
		return result, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	result.Status = StatusExecuted
	result.ExecutionResult = &ExecutionResult{
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: int64(len(respBody)),
	}

	if writer, ok := reader.(ConversationWriter); ok {
		if err := writer.WriteGateMessage(org.ID, &GateConversationMessage{
			Type:                GateMessageExecuted,
			OrgID:               org.ID,
			RequestID:           requestID,
			ExecutedAt:          time.Now().UTC(),
			ExecutionStatusCode: resp.StatusCode,
		}); err != nil {
			return nil, fmt.Errorf("store execution marker: %w", err)
		}
	}

	log.Printf("[AUDIT] EXECUTION org=%s req=%s service=%s status=%d signers=%v (no credentials logged)",
		org.ID, requestID, reqMsg.TargetService, resp.StatusCode, scan.SignerKIDs)

	return result, nil
}

func decodeBase64Flex(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return b, err
}
