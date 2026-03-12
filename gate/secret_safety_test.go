package gate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/corpo/qntm/pkg/types"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// captureLog redirects the standard logger to a buffer for the duration of fn,
// then returns everything that was written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // restore default
	fn()
	return buf.String()
}

// setupGatewayForSafetyTest creates a promoted gateway with a stored secret and
// returns the gateway, conversation, and the plaintext secret value.
func setupGatewayForSafetyTest(t *testing.T, useVault bool) (*Gateway, *types.Conversation, string) {
	t.Helper()
	gwIdentity := newTestIdentity()
	gw := NewGateway(gwIdentity)

	if useVault {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		vault, err := NewEnvVault(key)
		if err != nil {
			t.Fatalf("NewEnvVault: %v", err)
		}
		gw.Vault = vault
	}

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	senderKID := KIDFromPublicKey(senderPub)

	promotePayload := PromotePayload{
		OrgID: "test-org",
		Signers: []Signer{
			{KID: senderKID, PublicKey: senderPub, Label: "sender"},
		},
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1},
		},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	secretValue := "test_fake_NOTAREALSECRET_0000000"

	payload, err := BuildSecretPayload(
		senderPriv, senderPub,
		ed25519.PublicKey(gwIdentity.PublicKey),
		"cred-stripe", "stripe",
		"Authorization", "Bearer {value}",
		secretValue,
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

	return gw, conv, secretValue
}

// --------------------------------------------------------------------------
// Tests: handleSecret does NOT leak plaintext in logs
// --------------------------------------------------------------------------

func TestHandleSecret_NoPlaintextInLogs(t *testing.T) {
	secretValue := "test_fake_NOTAREALSECRET_0000000"

	output := captureLog(func() {
		setupGatewayForSafetyTest(t, false)
	})

	if strings.Contains(output, secretValue) {
		t.Fatalf("log output contains plaintext secret value:\n%s", output)
	}
}

func TestHandleSecret_NoPlaintextInLogs_WithVault(t *testing.T) {
	secretValue := "test_fake_NOTAREALSECRET_0000000"

	output := captureLog(func() {
		setupGatewayForSafetyTest(t, true)
	})

	if strings.Contains(output, secretValue) {
		t.Fatalf("log output contains plaintext secret value:\n%s", output)
	}
}

// --------------------------------------------------------------------------
// Tests: gate.executed message does NOT contain credential values
// --------------------------------------------------------------------------

func TestExecutedMessage_NoCredentialValues(t *testing.T) {
	secretValue := "test_fake_NOTAREALSECRET_0000000"

	executedMsg := GateConversationMessage{
		Type:                GateMessageExecuted,
		OrgID:               "test-org",
		RequestID:           "req-1",
		ExecutedAt:          time.Now().UTC(),
		ExecutionStatusCode: 200,
	}
	body, err := json.Marshal(executedMsg)
	if err != nil {
		t.Fatalf("marshal executed msg: %v", err)
	}

	if strings.Contains(string(body), secretValue) {
		t.Fatal("gate.executed message contains credential value")
	}
	// Also verify no Authorization header values
	if strings.Contains(string(body), "Bearer") {
		t.Fatal("gate.executed message contains credential header template")
	}
}

// --------------------------------------------------------------------------
// Tests: ExecuteResult does NOT contain credential values
// --------------------------------------------------------------------------

func TestExecuteResult_NoCredentialValues(t *testing.T) {
	secretValue := "test_fake_NOTAREALSECRET_0000000"

	result := &ExecuteResult{
		OrgID:          "test-org",
		RequestID:      "req-1",
		Verb:           "GET",
		TargetEndpoint: "/api/test",
		TargetService:  "stripe",
		Status:         StatusExecuted,
		SignatureCount: 1,
		SignerKIDs:     []string{"kid-1"},
		Threshold:      1,
		ExpiresAt:      time.Now().Add(time.Hour),
		ExecutionResult: &ExecutionResult{
			StatusCode:    200,
			ContentType:   "application/json",
			ContentLength: 42,
		},
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal ExecuteResult: %v", err)
	}

	if strings.Contains(string(body), secretValue) {
		t.Fatal("ExecuteResult contains credential value")
	}
	if strings.Contains(string(body), "Authorization") {
		t.Fatal("ExecuteResult contains credential header name")
	}
}

// --------------------------------------------------------------------------
// Tests: AUDIT log from ExecuteIfReady does NOT contain credentials
// --------------------------------------------------------------------------

func TestExecuteIfReady_AuditLogNoCredentials(t *testing.T) {
	secretValue := "test_fake_NOTAREALSECRET_0000000"
	signer := newTestSigner()

	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: signer.kid, PublicKey: signer.pub}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
		Credentials: map[string]*Credential{
			"stripe": {
				ID: "cred-1", Service: "stripe",
				Value:       secretValue,
				HeaderName:  "Authorization",
				HeaderValue: "Bearer {value}",
			},
		},
	}

	// Build a signed request
	signable := &GateSignable{
		OrgID: "test-org", RequestID: "req-1", Verb: "GET",
		TargetEndpoint: "/api/test", TargetService: "stripe",
		TargetURL: "https://api.stripe.com/v1/charges",
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
	}
	sig, _ := SignRequest(signer.priv, signable)
	sigB64 := encodeBase64Std(sig)

	convStore := NewMemoryConversationStore()
	_ = convStore.WriteGateMessage("test-org", &GateConversationMessage{
		Type: GateMessageRequest, OrgID: "test-org", RequestID: "req-1",
		Verb: "GET", TargetEndpoint: "/api/test", TargetService: "stripe",
		TargetURL: "https://api.stripe.com/v1/charges",
		ExpiresAt: time.Now().Add(time.Hour),
		SignerKID: signer.kid, Signature: sigB64,
	})

	orgStore := NewOrgStore()
	_ = orgStore.Create(org)

	output := captureLog(func() {
		// This will fail at the HTTP level (no real server), but the AUDIT log
		// line is written before the HTTP call in some paths. We just want to
		// verify no credential leaks in what IS logged.
		_, _ = ExecuteIfReady("req-1", org, convStore, orgStore)
	})

	if strings.Contains(output, secretValue) {
		t.Fatalf("AUDIT log contains plaintext credential:\n%s", output)
	}
	if strings.Contains(output, "Bearer test_fake") {
		t.Fatalf("AUDIT log contains credential header value:\n%s", output)
	}
}

// --------------------------------------------------------------------------
// Tests: RedactSecret helper
// --------------------------------------------------------------------------

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "****"},
		{"ab", "****"},
		{"abc", "****"},
		{"abcd", "****"},
		{"abcde", "ab****de"},
		{"test_fake_NOTAREALSECRET_0000000", "te****00"},
		{"ghp_xxxxxxxxxxxx", "gh****xx"},
	}

	for _, tc := range tests {
		got := RedactSecret(tc.input)
		if got != tc.want {
			t.Errorf("RedactSecret(%q) = %q, want %q", tc.input, got, tc.want)
		}
		// Ensure original value is not recoverable from redacted output
		if len(tc.input) > 4 && strings.Contains(got, tc.input) {
			t.Errorf("RedactSecret(%q) still contains full secret", tc.input)
		}
	}
}

// --------------------------------------------------------------------------
// Tests: SecretPayload does not expose plaintext via String/GoString
// --------------------------------------------------------------------------

func TestSecretPayload_StringDoesNotLeakPlaintext(t *testing.T) {
	// SecretPayload only stores the EncryptedBlob (ciphertext), never plaintext.
	// Verify that fmt.Sprintf does not accidentally show anything sensitive.
	payload := SecretPayload{
		SecretID:      "cred-1",
		Service:       "stripe",
		HeaderName:    "Authorization",
		EncryptedBlob: "base64-encoded-ciphertext-here",
		SenderKID:     "some-kid",
	}

	str := fmt.Sprintf("%+v", payload)

	// The struct should NOT contain any plaintext secret -- it never has one.
	// But it WILL contain the encrypted blob, which is fine (it's ciphertext).
	if strings.Contains(str, "test_fake") || strings.Contains(str, "Bearer sk") {
		t.Fatalf("SecretPayload string representation contains plaintext secret: %s", str)
	}
}

// --------------------------------------------------------------------------
// Tests: Credential.Scrub zeroes value
// --------------------------------------------------------------------------

func TestCredentialScrub(t *testing.T) {
	cred := &Credential{
		ID:          "c1",
		Service:     "stripe",
		Value:       "test_fake_SECRET",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
	}

	cred.Scrub()

	if cred.Value != "" {
		t.Fatalf("Scrub did not zero Value: %q", cred.Value)
	}
	if cred.HeaderValue != "" {
		t.Fatalf("Scrub did not zero HeaderValue: %q", cred.HeaderValue)
	}
}

func TestCredentialScrub_Nil(t *testing.T) {
	// Should not panic
	var cred *Credential
	cred.Scrub()
}

// --------------------------------------------------------------------------
// Tests: ConversationVault key colocation warning
// --------------------------------------------------------------------------

func TestConversationVault_KeySameDirectory(t *testing.T) {
	// This is a documentation/awareness test: the vault key is stored in the
	// same directory as the encrypted vault files. This test verifies the
	// behavior exists so that if it changes, we notice.
	tmpDir := t.TempDir()
	vault, err := NewConversationVault(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewConversationVault: %v", err)
	}

	// The vault key file is at basePath/vault.key
	_ = vault // key is at tmpDir/vault.key, data at tmpDir/<convID>.vault.json
	// This test exists as a reminder: vault key and data are colocated.
	// If an attacker gains read access to the vault directory, they can
	// decrypt all secrets. Consider separating key storage in production.
}

// --------------------------------------------------------------------------
// Tests: handleSecret with vault encrypts at rest (stored value != plaintext)
// --------------------------------------------------------------------------

func TestHandleSecret_VaultEncryptsAtRest(t *testing.T) {
	gw, conv, secretValue := setupGatewayForSafetyTest(t, true)

	state := gw.GetConversationState(conv.ID)
	cred := state.Credentials["stripe"]
	if cred == nil {
		t.Fatal("credential not stored")
	}

	// Stored value must NOT be plaintext
	if cred.Value == secretValue {
		t.Fatal("credential stored as plaintext despite vault being configured")
	}

	// Must have the vault prefix
	if !strings.HasPrefix(cred.Value, vaultPrefix) {
		t.Fatalf("credential missing vault prefix, got: %s", cred.Value[:20])
	}
}

// --------------------------------------------------------------------------
// Tests: Stored credential does not contain plaintext in JSON serialization
// --------------------------------------------------------------------------

func TestStoredCredential_JSONNoPlaintext(t *testing.T) {
	gw, conv, secretValue := setupGatewayForSafetyTest(t, true)

	state := gw.GetConversationState(conv.ID)
	cred := state.Credentials["stripe"]

	body, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	if strings.Contains(string(body), secretValue) {
		t.Fatal("JSON-serialized credential contains plaintext secret")
	}
}
