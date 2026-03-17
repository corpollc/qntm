package gate

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/corpo/qntm/pkg/types"
)

// --- ConversationVault Delete tests ---

func TestConversationVault_Delete(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store two secrets
	_ = vault.Store("conv-1", "cred-stripe", "stripe", "Authorization", "Bearer {value}", "sk_test_123")
	_ = vault.Store("conv-1", "cred-github", "github", "Authorization", "token {value}", "ghp_test_456")

	// Delete stripe secret
	err = vault.Delete("conv-1", "stripe")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// stripe should be gone
	_, err = vault.Get("conv-1", "stripe")
	if err == nil {
		t.Fatal("expected error getting deleted secret")
	}

	// github should still exist
	secret, err := vault.Get("conv-1", "github")
	if err != nil {
		t.Fatalf("github should still exist: %v", err)
	}
	if secret.Value != "ghp_test_456" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
}

func TestConversationVault_DeleteNonexistent(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, _ := NewConversationVault(dir, key)

	// Delete nonexistent secret should be a no-op (not an error)
	err := vault.Delete("conv-1", "nonexistent")
	if err != nil {
		t.Fatalf("Delete nonexistent should not error: %v", err)
	}
}

func TestConversationVault_DeleteByService(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	vault, _ := NewConversationVault(dir, key)

	// Store secrets for multiple services
	_ = vault.Store("conv-1", "cred-1", "stripe", "Authorization", "Bearer {value}", "sk_1")
	_ = vault.Store("conv-1", "cred-2", "github", "Authorization", "token {value}", "ghp_1")
	_ = vault.Store("conv-1", "cred-3", "aws", "Authorization", "AWS4 {value}", "aws_1")

	// Delete by service "stripe"
	err := vault.DeleteByService("conv-1", "stripe")
	if err != nil {
		t.Fatalf("DeleteByService: %v", err)
	}

	// stripe should be gone
	_, err = vault.Get("conv-1", "stripe")
	if err == nil {
		t.Fatal("expected error getting deleted stripe secret")
	}

	// github and aws should still exist
	s, err := vault.Get("conv-1", "github")
	if err != nil {
		t.Fatalf("github should still exist: %v", err)
	}
	if s.Value != "ghp_1" {
		t.Fatalf("unexpected github value: %s", s.Value)
	}

	s, err = vault.Get("conv-1", "aws")
	if err != nil {
		t.Fatalf("aws should still exist: %v", err)
	}
	if s.Value != "aws_1" {
		t.Fatalf("unexpected aws value: %s", s.Value)
	}
}

func TestConversationVault_DeleteByServiceNonexistent(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, _ := NewConversationVault(dir, key)

	// Delete nonexistent service should be a no-op
	err := vault.DeleteByService("conv-1", "nonexistent")
	if err != nil {
		t.Fatalf("DeleteByService nonexistent should not error: %v", err)
	}
}

// --- Gateway handleRevoke tests ---

func setupGatewayWithSecret(t *testing.T) (*Gateway, *types.Conversation, types.ConversationID) {
	t.Helper()

	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

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

	// Add sender as participant
	state := gw.GetConversationState(convID)
	state.Participants[senderKID] = senderPub

	// Store secrets via handleSecret
	for _, s := range []struct {
		id, svc, val string
	}{
		{"cred-stripe", "stripe", "sk_test_123"},
		{"cred-github", "github", "ghp_test_456"},
		{"cred-aws", "aws", "AKIA_test_789"},
	} {
		payload, err := BuildSecretPayload(
			senderPriv, senderPub,
			ed25519.PublicKey(gwIdentity.PublicKey),
			s.id, s.svc,
			"Authorization", "Bearer {value}",
			s.val,
		)
		if err != nil {
			t.Fatalf("BuildSecretPayload %s: %v", s.svc, err)
		}
		secretBody, _ := json.Marshal(payload)
		err = gw.handleSecret(conv, &types.Message{
			Inner: &types.InnerPayload{BodyType: string(GateMessageSecret), Body: secretBody},
		})
		if err != nil {
			t.Fatalf("handleSecret %s: %v", s.svc, err)
		}
	}

	return gw, conv, convID
}

func TestHandleRevoke_BySecretID(t *testing.T) {
	gw, conv, convID := setupGatewayWithSecret(t)

	// Revoke by secret_id (which maps to a service key)
	revokePayload := RevokePayload{
		Service: "stripe",
	}
	body, _ := json.Marshal(revokePayload)
	msg := &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	}

	err := gw.handleRevoke(conv, msg)
	if err != nil {
		t.Fatalf("handleRevoke: %v", err)
	}

	// Verify stripe credential is gone
	state := gw.GetConversationState(convID)
	if _, ok := state.Credentials["stripe"]; ok {
		t.Fatal("stripe credential should have been revoked")
	}

	// Other credentials should remain
	if _, ok := state.Credentials["github"]; !ok {
		t.Fatal("github credential should still exist")
	}
	if _, ok := state.Credentials["aws"]; !ok {
		t.Fatal("aws credential should still exist")
	}
}

func TestHandleRevoke_ByService(t *testing.T) {
	gw, conv, convID := setupGatewayWithSecret(t)

	revokePayload := RevokePayload{
		Service: "github",
	}
	body, _ := json.Marshal(revokePayload)
	msg := &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	}

	err := gw.handleRevoke(conv, msg)
	if err != nil {
		t.Fatalf("handleRevoke by service: %v", err)
	}

	state := gw.GetConversationState(convID)
	if _, ok := state.Credentials["github"]; ok {
		t.Fatal("github credential should have been revoked")
	}

	// Other credentials should remain
	if _, ok := state.Credentials["stripe"]; !ok {
		t.Fatal("stripe credential should still exist")
	}
	if _, ok := state.Credentials["aws"]; !ok {
		t.Fatal("aws credential should still exist")
	}
}

func TestHandleRevoke_Nonexistent(t *testing.T) {
	gw, conv, convID := setupGatewayWithSecret(t)

	// Revoke nonexistent service should be a no-op
	revokePayload := RevokePayload{
		Service: "nonexistent",
	}
	body, _ := json.Marshal(revokePayload)
	msg := &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	}

	err := gw.handleRevoke(conv, msg)
	if err != nil {
		t.Fatalf("handleRevoke nonexistent should not error: %v", err)
	}

	// All credentials should still exist
	state := gw.GetConversationState(convID)
	if len(state.Credentials) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(state.Credentials))
	}
}

func TestHandleRevoke_WithoutPromote(t *testing.T) {
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	revokePayload := RevokePayload{Service: "stripe"}
	body, _ := json.Marshal(revokePayload)
	msg := &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	}

	err := gw.handleRevoke(conv, msg)
	if err == nil {
		t.Fatal("expected error for revoke without promote")
	}
}

func TestProcessMessage_RoutesRevoke(t *testing.T) {
	gw, conv, convID := setupGatewayWithSecret(t)

	// Send revoke via processMessage
	revokePayload := RevokePayload{
		Service: "stripe",
	}
	body, _ := json.Marshal(revokePayload)
	msg := &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	}

	err := gw.processMessage(conv, msg, nil)
	if err != nil {
		t.Fatalf("processMessage revoke: %v", err)
	}

	state := gw.GetConversationState(convID)
	if _, ok := state.Credentials["stripe"]; ok {
		t.Fatal("stripe credential should have been revoked via processMessage routing")
	}
}

func TestHandleRevoke_RevokedSecretCannotBeRetrieved(t *testing.T) {
	gw, conv, convID := setupGatewayWithSecret(t)

	// Verify we can access the credential before revocation
	state := gw.GetConversationState(convID)
	if _, ok := state.Credentials["stripe"]; !ok {
		t.Fatal("stripe credential should exist before revocation")
	}

	// Revoke
	revokePayload := RevokePayload{Service: "stripe"}
	body, _ := json.Marshal(revokePayload)
	err := gw.handleRevoke(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageRevoke), Body: body},
	})
	if err != nil {
		t.Fatalf("handleRevoke: %v", err)
	}

	// Verify revoked secret cannot be retrieved
	state = gw.GetConversationState(convID)
	if _, ok := state.Credentials["stripe"]; ok {
		t.Fatal("revoked credential should not be retrievable")
	}

	// Build org from state and verify credential is also gone there
	org := gw.buildOrg(state)
	if _, ok := org.Credentials["stripe"]; ok {
		t.Fatal("revoked credential should not appear in built org")
	}
}
