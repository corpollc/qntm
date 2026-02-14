package gate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
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

// AuthRequest represents a submitted authorization request.
type AuthRequest struct {
	OrgID           string            `json:"org_id"`
	RequestID       string            `json:"request_id"`
	Verb            string            `json:"verb"`
	TargetEndpoint  string            `json:"target_endpoint"`
	TargetService   string            `json:"target_service"`
	TargetURL       string            `json:"target_url"`
	Payload         json.RawMessage   `json:"payload,omitempty"`
	RequesterKID    string            `json:"requester_kid"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Status          RequestStatus     `json:"status"`
	SignatureCount  int               `json:"signature_count"`
	SignerKIDs      []string          `json:"signer_kids"`
	Threshold       int               `json:"threshold"`
	CreatedAt       time.Time         `json:"created_at"`
	ExecutionResult *ExecutionResult  `json:"execution_result,omitempty"`

	// Internal fields
	signature  []byte
	signatures map[string][]byte // kid -> sig
}

// ExecutionResult holds the result of forwarding the request.
type ExecutionResult struct {
	StatusCode int             `json:"status_code"`
	Body       json.RawMessage `json:"body,omitempty"`
}

// SubmitRequestBody is the JSON body for submitting a new request.
type SubmitRequestBody struct {
	RequestID      string          `json:"request_id"`
	Verb           string          `json:"verb"`
	TargetEndpoint string          `json:"target_endpoint"`
	TargetService  string          `json:"target_service"`
	TargetURL      string          `json:"target_url"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	RequesterKID   string          `json:"requester_kid"`
	Signature      string          `json:"signature"` // base64url
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
}

// ApproveRequestBody is the JSON body for approving a request.
type ApproveRequestBody struct {
	SignerKID string `json:"signer_kid"`
	Signature string `json:"signature"` // base64url
}

// AuthStore manages authorization requests.
type AuthStore struct {
	mu       sync.RWMutex
	requests map[string]map[string]*AuthRequest // org_id -> request_id -> request
	orgStore *OrgStore
}

// NewAuthStore creates a new auth store.
func NewAuthStore(orgStore *OrgStore) *AuthStore {
	return &AuthStore{
		requests: make(map[string]map[string]*AuthRequest),
		orgStore: orgStore,
	}
}

func (r *AuthRequest) updatePublicFields() {
	r.SignatureCount = len(r.signatures)
	r.SignerKIDs = make([]string, 0, len(r.signatures))
	for kid := range r.signatures {
		r.SignerKIDs = append(r.SignerKIDs, kid)
	}
}

// Submit submits a new authorization request.
func (s *AuthStore) Submit(orgID string, req *SubmitRequestBody) (*AuthRequest, error) {
	o, err := s.orgStore.Get(orgID)
	if err != nil {
		return nil, err
	}

	signer := o.FindSignerByKID(req.RequesterKID)
	if signer == nil {
		return nil, fmt.Errorf("unknown signer %q in org %q", req.RequesterKID, orgID)
	}

	payloadHash := ComputePayloadHash(req.Payload)
	signable := &GateSignable{
		OrgID: orgID, RequestID: req.RequestID, Verb: req.Verb,
		TargetEndpoint: req.TargetEndpoint, TargetService: req.TargetService,
		PayloadHash: payloadHash,
	}

	sigBytes, err := decodeBase64Flex(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if err := VerifyRequest(signer.PublicKey, signable, sigBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	threshold, err := o.LookupThreshold(req.TargetService, req.TargetEndpoint, req.Verb)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(1 * time.Hour) // default: 1 hour
	if req.ExpiresAt != nil {
		expiresAt = *req.ExpiresAt
	}
	if expiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("expires_at is in the past")
	}

	authReq := &AuthRequest{
		OrgID: orgID, RequestID: req.RequestID, Verb: req.Verb,
		TargetEndpoint: req.TargetEndpoint, TargetService: req.TargetService,
		TargetURL: req.TargetURL, Payload: req.Payload,
		RequesterKID: req.RequesterKID, ExpiresAt: expiresAt,
		Status: StatusPending, Threshold: threshold, CreatedAt: time.Now(),
		signature:  sigBytes,
		signatures: map[string][]byte{req.RequesterKID: sigBytes},
	}

	s.mu.Lock()
	if s.requests[orgID] == nil {
		s.requests[orgID] = make(map[string]*AuthRequest)
	}
	if _, exists := s.requests[orgID][req.RequestID]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("request %q already exists (replay protection)", req.RequestID)
	}
	s.requests[orgID][req.RequestID] = authReq
	s.mu.Unlock()

	log.Printf("[AUDIT] REQUEST org=%s req=%s verb=%s service=%s endpoint=%s by=%s threshold=%d",
		orgID, req.RequestID, req.Verb, req.TargetService, req.TargetEndpoint, req.RequesterKID, threshold)

	if len(authReq.signatures) >= authReq.Threshold {
		authReq.Status = StatusApproved
	}

	authReq.updatePublicFields()
	return authReq, nil
}

// Approve adds an approval signature to a request.
func (s *AuthStore) Approve(orgID, requestID string, approval *ApproveRequestBody) (*AuthRequest, error) {
	o, err := s.orgStore.Get(orgID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	reqs := s.requests[orgID]
	if reqs == nil {
		return nil, fmt.Errorf("no requests for org %q", orgID)
	}
	authReq := reqs[requestID]
	if authReq == nil {
		return nil, fmt.Errorf("request %q not found", requestID)
	}

	if time.Now().After(authReq.ExpiresAt) {
		authReq.Status = StatusExpired
		return nil, fmt.Errorf("request %q has expired", requestID)
	}
	if authReq.Status == StatusExecuted {
		return nil, fmt.Errorf("request %q already executed", requestID)
	}

	signer := o.FindSignerByKID(approval.SignerKID)
	if signer == nil {
		return nil, fmt.Errorf("unknown signer %q", approval.SignerKID)
	}
	if _, exists := authReq.signatures[approval.SignerKID]; exists {
		return nil, fmt.Errorf("signer %q already approved", approval.SignerKID)
	}

	// Rebuild signable to compute request hash
	payloadHash := ComputePayloadHash(authReq.Payload)
	signable := &GateSignable{
		OrgID: orgID, RequestID: requestID, Verb: authReq.Verb,
		TargetEndpoint: authReq.TargetEndpoint, TargetService: authReq.TargetService,
		PayloadHash: payloadHash,
	}
	requestHash, err := HashRequest(signable)
	if err != nil {
		return nil, fmt.Errorf("hash request: %w", err)
	}

	approvalSignable := &ApprovalSignable{
		OrgID: orgID, RequestID: requestID, RequestHash: requestHash,
	}

	sigBytes, err := decodeBase64Flex(approval.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if err := VerifyApproval(signer.PublicKey, approvalSignable, sigBytes); err != nil {
		return nil, fmt.Errorf("approval signature verification failed: %w", err)
	}

	authReq.signatures[approval.SignerKID] = sigBytes
	log.Printf("[AUDIT] APPROVAL org=%s req=%s by=%s (%d/%d)",
		orgID, requestID, approval.SignerKID, len(authReq.signatures), authReq.Threshold)

	if len(authReq.signatures) >= authReq.Threshold {
		authReq.Status = StatusApproved
	}

	authReq.updatePublicFields()
	return authReq, nil
}

// Get returns a request by ID, updating expiration status.
func (s *AuthStore) Get(orgID, requestID string) (*AuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reqs := s.requests[orgID]
	if reqs == nil {
		return nil, fmt.Errorf("no requests for org %q", orgID)
	}
	authReq := reqs[requestID]
	if authReq == nil {
		return nil, fmt.Errorf("request %q not found", requestID)
	}

	if authReq.Status == StatusPending && time.Now().After(authReq.ExpiresAt) {
		authReq.Status = StatusExpired
	}

	authReq.updatePublicFields()
	return authReq, nil
}

// Execute forwards an approved request to the target service, injecting credentials.
func (s *AuthStore) Execute(orgID, requestID string) (*AuthRequest, error) {
	s.mu.Lock()
	reqs := s.requests[orgID]
	if reqs == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("request %q not found", requestID)
	}
	authReq := reqs[requestID]
	if authReq == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("request %q not found", requestID)
	}

	if time.Now().After(authReq.ExpiresAt) {
		authReq.Status = StatusExpired
		s.mu.Unlock()
		return nil, fmt.Errorf("request %q has expired", requestID)
	}
	if authReq.Status != StatusApproved {
		s.mu.Unlock()
		return nil, fmt.Errorf("request %q not approved (status: %s)", requestID, authReq.Status)
	}

	authReq.Status = StatusExecuted // prevent double execution
	s.mu.Unlock()

	cred, err := s.orgStore.GetCredentialByService(orgID, authReq.TargetService)
	if err != nil {
		s.mu.Lock()
		authReq.Status = StatusApproved
		s.mu.Unlock()
		return nil, fmt.Errorf("get credential: %w", err)
	}

	var bodyReader io.Reader
	if len(authReq.Payload) > 0 {
		bodyReader = strings.NewReader(string(authReq.Payload))
	}

	httpReq, err := http.NewRequest(authReq.Verb, authReq.TargetURL, bodyReader)
	if err != nil {
		s.mu.Lock()
		authReq.Status = StatusApproved
		s.mu.Unlock()
		return nil, fmt.Errorf("create http request: %w", err)
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
	if len(authReq.Payload) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		s.mu.Lock()
		authReq.Status = StatusApproved
		s.mu.Unlock()
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	authReq.ExecutionResult = &ExecutionResult{
		StatusCode: resp.StatusCode,
		Body:       json.RawMessage(respBody),
	}

	log.Printf("[AUDIT] EXECUTION org=%s req=%s service=%s status=%d (no credentials logged)",
		orgID, requestID, authReq.TargetService, resp.StatusCode)

	authReq.updatePublicFields()
	return authReq, nil
}

func decodeBase64Flex(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return b, err
}
