package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/corpo/qntm/pkg/types"
)

func newTestConversationID() types.ConversationID {
	var id types.ConversationID
	pub, _, _ := ed25519.GenerateKey(nil)
	copy(id[:], pub[:16])
	return id
}

func newTestIdentity() *types.Identity {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var kid types.KeyID
	// Simple kid derivation for tests (matches gate.KIDFromPublicKey logic)
	kidStr := KIDFromPublicKey(pub)
	_ = kid.UnmarshalText([]byte(kidStr))
	return &types.Identity{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      kid,
	}
}

func TestNewGateway(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	if gw.Identity != id {
		t.Fatal("identity not set")
	}
	if gw.Conversations == nil {
		t.Fatal("conversations map is nil")
	}
	if gw.QntmConvs == nil {
		t.Fatal("qntm convs map is nil")
	}
	if gw.SequenceCursors == nil {
		t.Fatal("sequence cursors map is nil")
	}
	if gw.PollInterval != 5*time.Second {
		t.Fatalf("unexpected poll interval: %v", gw.PollInterval)
	}
}

func TestRegisterConversation(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{
		ID:   convID,
		Type: types.ConversationTypeGroup,
	}

	gw.RegisterConversation(conv)

	if _, ok := gw.QntmConvs[convID]; !ok {
		t.Fatal("conversation not registered")
	}
}

func TestHandlePromote(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{
		ID:   convID,
		Type: types.ConversationTypeGroup,
	}
	gw.RegisterConversation(conv)

	promotePayload := PromotePayload{
		ConvID:     "test-org",
		GatewayKID: "gw-kid-test",
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 3},
		},
	}
	body, _ := json.Marshal(promotePayload)

	msg := &types.Message{
		Inner: &types.InnerPayload{
			BodyType: string(GateMessagePromote),
			Body:     body,
		},
	}

	err := gw.handlePromote(conv, msg)
	if err != nil {
		t.Fatalf("handlePromote failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state == nil {
		t.Fatal("conversation state not created")
	}
	if state.ConvID != "test-org" {
		t.Fatalf("unexpected conv_id: %s", state.ConvID)
	}
	if len(state.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(state.Rules))
	}
	if state.Rules[0].M != 2 {
		t.Fatalf("expected threshold M=2, got %d", state.Rules[0].M)
	}
	if state.GatewayKID != "gw-kid-test" {
		t.Fatalf("expected gateway_kid=gw-kid-test, got %s", state.GatewayKID)
	}
}

func TestHandleConfig(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// First promote the conversation
	promotePayload := PromotePayload{
		ConvID:     "test-org",
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Now send config update
	configPayload := ConfigPayload{
		Rules: []ThresholdRule{
			{Service: "stripe", Endpoint: "*", Verb: "*", M: 3, N: 5},
		},
	}
	configBody, _ := json.Marshal(configPayload)

	err := gw.handleConfig(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageConfig), Body: configBody},
	})
	if err != nil {
		t.Fatalf("handleConfig failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if len(state.Rules) != 1 {
		t.Fatalf("expected 1 rule after config, got %d", len(state.Rules))
	}
	if state.Rules[0].Service != "stripe" {
		t.Fatalf("expected service=stripe, got %s", state.Rules[0].Service)
	}
	if state.Rules[0].M != 3 {
		t.Fatalf("expected M=3, got %d", state.Rules[0].M)
	}
}

func TestHandleConfigWithoutPromote(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	configPayload := ConfigPayload{
		Rules: []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	configBody, _ := json.Marshal(configPayload)

	err := gw.handleConfig(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageConfig), Body: configBody},
	})
	if err == nil {
		t.Fatal("expected error for config without promote")
	}
}

func TestProcessMessageRouting(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Non-gate message should be silently ignored
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: "text", Body: []byte("hello")},
	}, nil)
	if err != nil {
		t.Fatalf("expected nil error for non-gate message, got: %v", err)
	}

	// gate.request without promote should fail
	requestBody, _ := json.Marshal(GateConversationMessage{
		Type:      GateMessageRequest,
		RequestID: "r1",
	})
	err = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRequest), Body: requestBody},
	}, nil)
	if err == nil {
		t.Fatal("expected error for request without promote")
	}
}

func TestStoreGateMessage(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	orgID := "test-org"

	msg := &GateConversationMessage{
		Type:           GateMessageRequest,
		ConvID:          orgID,
		RequestID:      "req-1",
		Verb:           "GET",
		TargetEndpoint: "/api/data",
		TargetService:  "data-api",
		SignerKID:      "kid-1",
	}

	if err := gw.StoreGateMessage(convID, orgID, msg); err != nil {
		t.Fatalf("store gate message failed: %v", err)
	}

	store := gw.getConvMessageStore(convID)
	messages, err := store.ReadGateMessages(orgID)
	if err != nil {
		t.Fatalf("read gate messages failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].RequestID != "req-1" {
		t.Fatalf("unexpected request ID: %s", messages[0].RequestID)
	}
}

func TestBuildOrg(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	signer := newTestSigner()
	state := &ConversationGateState{
		ConvID:     "org-1",
		GatewayKID: "gw-kid-test",
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 3},
		},
		Credentials: map[string]*Credential{
			"cred-1": {ID: "cred-1", Service: "stripe", Value: "sk_test_123"},
		},
		Participants: map[string]ed25519.PublicKey{
			signer.kid: signer.pub,
		},
	}

	org := gw.buildOrg(state)
	if org.ID != "org-1" {
		t.Fatalf("unexpected org ID: %s", org.ID)
	}
	if len(org.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(org.Signers))
	}
	if len(org.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(org.Rules))
	}
	if len(org.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(org.Credentials))
	}
	// Verify credential was copied, not shared
	org.Credentials["cred-1"].Value = "modified"
	if state.Credentials["cred-1"].Value == "modified" {
		t.Fatal("credential was not copied, shares reference with state")
	}
}

func TestGatewayRunCancellation(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)
	gw.PollInterval = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := gw.Run(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got: %v", err)
	}
}

func TestGetConversationStateNil(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	state := gw.GetConversationState(convID)
	if state != nil {
		t.Fatal("expected nil state for unregistered conversation")
	}
}

func TestHandleSecret(t *testing.T) {
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Generate sender identity
	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	senderKID := KIDFromPublicKey(senderPub)

	// Promote the conversation
	promotePayload := PromotePayload{
		ConvID:     "test-org",
		GatewayKID: "gw-kid-test",
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1},
		},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Add sender as participant (participants derived from conversation membership)
	state := gw.GetConversationState(convID)
	state.Participants[senderKID] = senderPub

	// Build and send a gate.secret message
	payload, err := BuildSecretPayload(
		senderPriv, senderPub,
		ed25519.PublicKey(gwIdentity.PublicKey),
		"cred-stripe", "stripe",
		"Authorization", "Bearer {value}",
		"sk_test_secretkey123",
	)
	if err != nil {
		t.Fatalf("BuildSecretPayload: %v", err)
	}

	secretBody, _ := json.Marshal(payload)

	err = gw.handleSecret(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageSecret), Body: secretBody},
	})
	if err != nil {
		t.Fatalf("handleSecret: %v", err)
	}

	// Verify the credential was stored
	state = gw.GetConversationState(convID)
	if state == nil {
		t.Fatal("conversation state is nil after secret")
	}

	cred, ok := state.Credentials["stripe"]
	if !ok {
		t.Fatal("credential for stripe not found")
	}
	if cred.ID != "cred-stripe" {
		t.Fatalf("unexpected credential ID: %s", cred.ID)
	}
	if cred.Service != "stripe" {
		t.Fatalf("unexpected credential service: %s", cred.Service)
	}
	if cred.HeaderName != "Authorization" {
		t.Fatalf("unexpected header name: %s", cred.HeaderName)
	}
	if cred.HeaderValue != "Bearer {value}" {
		t.Fatalf("unexpected header value: %s", cred.HeaderValue)
	}
	// Value should be the decrypted secret (NoopVault is default)
	if cred.Value != "sk_test_secretkey123" {
		t.Fatalf("unexpected credential value: %s", cred.Value)
	}
}

func TestHandleSecretWithoutPromote(t *testing.T) {
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	secretBody := []byte(`{"secret_id":"c","service":"s","sender_kid":"x"}`)
	err := gw.handleSecret(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageSecret), Body: secretBody},
	})
	if err == nil {
		t.Fatal("expected error for secret without promote")
	}
}

func TestHandleSecretWithVault(t *testing.T) {
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	// Set up an EnvVault
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	vault, _ := NewEnvVault(key)
	gw.Vault = vault

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	senderKID := KIDFromPublicKey(senderPub)

	promotePayload := PromotePayload{
		ConvID:     "test-org",
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Add sender as participant
	state := gw.GetConversationState(convID)
	state.Participants[senderKID] = senderPub

	payload, _ := BuildSecretPayload(
		senderPriv, senderPub,
		ed25519.PublicKey(gwIdentity.PublicKey),
		"cred-1", "github",
		"Authorization", "token {value}",
		"ghp_secrettoken",
	)
	secretBody, _ := json.Marshal(payload)

	err := gw.handleSecret(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageSecret), Body: secretBody},
	})
	if err != nil {
		t.Fatalf("handleSecret with vault: %v", err)
	}

	state = gw.GetConversationState(convID)
	cred := state.Credentials["github"]
	if cred == nil {
		t.Fatal("credential not stored")
	}

	// Value should be vault-encrypted (not plaintext)
	if cred.Value == "ghp_secrettoken" {
		t.Fatal("credential value should be encrypted at rest, but got plaintext")
	}
	if len(cred.Value) < len(vaultPrefix) || cred.Value[:len(vaultPrefix)] != vaultPrefix {
		t.Fatalf("credential value should have vault prefix, got: %s", cred.Value[:20])
	}

	// Verify decryption works
	decrypted, err := vault.Decrypt(cred.Value)
	if err != nil {
		t.Fatalf("vault decrypt: %v", err)
	}
	if decrypted != "ghp_secrettoken" {
		t.Fatalf("decrypted value mismatch: %s", decrypted)
	}
}
