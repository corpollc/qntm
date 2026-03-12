package gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/corpo/qntm/pkg/types"
)

// TestExpiredSecretGeneratesNotification verifies that when a credential's
// ExpiresAt is in the past, the gateway's checkExpiredCredentials method
// generates a gate.expired notification.
func TestExpiredSecretGeneratesNotification(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Promote the conversation
	signer := newTestSigner()
	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Store a credential with an expiry in the past
	state := gw.GetConversationState(convID)
	state.Credentials["stripe"] = &Credential{
		ID:        "cred-stripe",
		Service:   "stripe",
		Value:     "sk_test_123",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
	}

	// Check for expired credentials
	expired := gw.checkExpiredCredentials(convID, state)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired credential, got %d", len(expired))
	}
	if expired[0].SecretID != "cred-stripe" {
		t.Fatalf("expected secret_id=cred-stripe, got %s", expired[0].SecretID)
	}
	if expired[0].Service != "stripe" {
		t.Fatalf("expected service=stripe, got %s", expired[0].Service)
	}
}

// TestExpiredMessageFormat verifies the gate.expired payload structure.
func TestExpiredMessageFormat(t *testing.T) {
	expiredAt := time.Now().Add(-30 * time.Minute)
	payload := ExpiredPayload{
		SecretID:  "cred-stripe",
		Service:   "stripe",
		ExpiredAt: expiredAt.UTC().Format(time.RFC3339),
		Message:   "Secret 'cred-stripe' for service 'stripe' has expired. Please re-provision.",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal expired payload: %v", err)
	}

	var parsed ExpiredPayload
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal expired payload: %v", err)
	}

	if parsed.SecretID != "cred-stripe" {
		t.Fatalf("expected secret_id=cred-stripe, got %s", parsed.SecretID)
	}
	if parsed.Service != "stripe" {
		t.Fatalf("expected service=stripe, got %s", parsed.Service)
	}
	if parsed.ExpiredAt == "" {
		t.Fatal("expired_at should not be empty")
	}
	if parsed.Message == "" {
		t.Fatal("message should not be empty")
	}
}

// TestExpiredSecretPreventsExecution verifies that checkAndExecute returns a
// clear error when the credential for the target service has expired.
func TestExpiredSecretPreventsExecution(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "stripe", Endpoint: "*", Verb: "GET", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Store an expired credential
	state := gw.GetConversationState(convID)
	state.Credentials["stripe"] = &Credential{
		ID:          "cred-stripe",
		Service:     "stripe",
		Value:       "sk_test_123",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // expired
	}

	// Create a valid signed request
	payload := json.RawMessage(`{}`)
	targetURL := "https://api.stripe.com/v1/charges"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{
		OrgID: "test-org", RequestID: "req-exp", Verb: "GET",
		TargetEndpoint: "/v1/charges", TargetService: "stripe",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload),
	}
	sig, _ := SignRequest(signer.priv, signable)

	reqMsg := &GateConversationMessage{
		Type:           GateMessageRequest,
		OrgID:          "test-org",
		RequestID:      "req-exp",
		Verb:           "GET",
		TargetEndpoint: "/v1/charges",
		TargetService:  "stripe",
		TargetURL:      targetURL,
		Payload:        payload,
		SignerKID:      signer.kid,
		Signature:      base64.RawURLEncoding.EncodeToString(sig),
		ExpiresAt:      expiresAt,
	}
	_ = gw.StoreGateMessage(convID, "test-org", reqMsg)

	// checkAndExecute should fail with a credential expired error
	err := gw.checkAndExecute(conv, state, "req-exp", nil)
	if err == nil {
		t.Fatal("expected error for expired credential, got nil")
	}
	errStr := err.Error()
	if !stringContains(errStr, "expired") || !stringContains(errStr, "credential") {
		t.Fatalf("expected credential expired error, got: %v", err)
	}
}

// TestNonExpiredSecretAllowsExecution verifies that credentials without expiry
// or with future expiry do not block execution.
func TestNonExpiredSecretAllowsExecution(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "stripe", Endpoint: "*", Verb: "GET", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Credential with no expiry (zero value = no expiry)
	state := gw.GetConversationState(convID)
	state.Credentials["stripe"] = &Credential{
		ID:          "cred-stripe",
		Service:     "stripe",
		Value:       "sk_test_123",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
		// ExpiresAt is zero value -- no expiry
	}

	expired := gw.checkExpiredCredentials(convID, state)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired credentials, got %d", len(expired))
	}

	// Also test with future expiry
	state.Credentials["stripe"].ExpiresAt = time.Now().Add(24 * time.Hour)
	// Reset notification tracking
	gw.expiryNotified = make(map[string]bool)
	expired = gw.checkExpiredCredentials(convID, state)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired credentials for future expiry, got %d", len(expired))
	}
}

// TestGatewayDoesNotAutoRefreshSecrets verifies that the gateway does NOT
// attempt to re-provision secrets on its own when they expire.
func TestGatewayDoesNotAutoRefreshSecrets(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Store an expired credential
	state := gw.GetConversationState(convID)
	expiredCred := &Credential{
		ID:        "cred-expired",
		Service:   "github",
		Value:     "ghp_old_token",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	state.Credentials["github"] = expiredCred

	// Check expired credentials
	expired := gw.checkExpiredCredentials(convID, state)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired credential, got %d", len(expired))
	}

	// The credential should still be in the state with the same value
	// (gateway must NOT have replaced it with a new one)
	if state.Credentials["github"].Value != "ghp_old_token" {
		t.Fatal("gateway should not have modified the expired credential value")
	}

	// Check that the notification was recorded so it won't be sent again
	expired2 := gw.checkExpiredCredentials(convID, state)
	if len(expired2) != 0 {
		t.Fatalf("expected 0 expired on second check (already notified), got %d", len(expired2))
	}
}

// TestExpiredNotificationNotDuplicated verifies that the gateway tracks
// which expiry notifications have been sent and doesn't spam.
func TestExpiredNotificationNotDuplicated(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	state := gw.GetConversationState(convID)
	state.Credentials["svc"] = &Credential{
		ID: "cred-1", Service: "svc", Value: "v",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	// First check: should detect expiry
	expired1 := gw.checkExpiredCredentials(convID, state)
	if len(expired1) != 1 {
		t.Fatalf("expected 1 expired on first check, got %d", len(expired1))
	}

	// Second check: should NOT detect it again (already notified)
	expired2 := gw.checkExpiredCredentials(convID, state)
	if len(expired2) != 0 {
		t.Fatalf("expected 0 expired on second check, got %d", len(expired2))
	}
}

// TestGateMessageExpiredConstant verifies the gate.expired message type constant.
func TestGateMessageExpiredConstant(t *testing.T) {
	if GateMessageExpired != "gate.expired" {
		t.Fatalf("expected gate.expired, got %s", GateMessageExpired)
	}
}

// TestSecretPayloadTTL verifies that SecretPayload includes TTL field.
func TestSecretPayloadTTL(t *testing.T) {
	payload := SecretPayload{
		SecretID:       "cred-1",
		Service:        "stripe",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {value}",
		EncryptedBlob:  "base64data",
		SenderKID:      "kid123",
		TTL:            3600, // 1 hour
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed SecretPayload
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.TTL != 3600 {
		t.Fatalf("expected TTL=3600, got %d", parsed.TTL)
	}
}

// TestHandleSecretWithTTL verifies that when a gate.secret message includes
// a TTL, the stored credential gets an ExpiresAt timestamp.
func TestHandleSecretWithTTL(t *testing.T) {
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	senderKID := KIDFromPublicKey(senderPub)

	promotePayload := PromotePayload{
		OrgID:   "test-org",
		Signers: []Signer{{KID: senderKID, PublicKey: senderPub}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	payload, _ := BuildSecretPayload(
		senderPriv, senderPub,
		ed25519.PublicKey(gwIdentity.PublicKey),
		"cred-1", "stripe",
		"Authorization", "Bearer {value}",
		"sk_test_123",
	)
	// Set TTL to 1 hour
	payload.TTL = 3600

	secretBody, _ := json.Marshal(payload)
	beforeStore := time.Now()

	err := gw.handleSecret(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageSecret), Body: secretBody},
	})
	if err != nil {
		t.Fatalf("handleSecret with TTL: %v", err)
	}

	state := gw.GetConversationState(convID)
	cred := state.Credentials["stripe"]
	if cred == nil {
		t.Fatal("credential not stored")
	}

	if cred.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt should be set when TTL is provided")
	}

	// ExpiresAt should be approximately now + 3600 seconds
	expectedExpiry := beforeStore.Add(3600 * time.Second)
	diff := cred.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Fatalf("ExpiresAt is off by too much: got %v, expected ~%v", cred.ExpiresAt, expectedExpiry)
	}
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
