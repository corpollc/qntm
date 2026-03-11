package gate

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestSealOpenSecret_Roundtrip(t *testing.T) {
	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	gatewayPub, gatewayPriv, _ := ed25519.GenerateKey(nil)

	secrets := []string{
		"sk-test-abc123",
		"Bearer eyJhbGciOiJSUzI1NiJ9.long-jwt-token",
		"simple-api-key",
		"",
	}

	for _, secret := range secrets {
		sealed, err := SealSecret(senderPriv, gatewayPub, []byte(secret))
		if err != nil {
			t.Fatalf("SealSecret(%q): %v", secret, err)
		}

		// Sealed must differ from plaintext
		if secret != "" && string(sealed) == secret {
			t.Fatalf("sealed should differ from plaintext for %q", secret)
		}

		opened, err := OpenSecret(gatewayPriv, senderPub, sealed)
		if err != nil {
			t.Fatalf("OpenSecret(%q): %v", secret, err)
		}

		if string(opened) != secret {
			t.Fatalf("round-trip failed: got %q, want %q", string(opened), secret)
		}
	}
}

func TestSealSecret_DifferentCiphertexts(t *testing.T) {
	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	_ = senderPub
	gatewayPub, _, _ := ed25519.GenerateKey(nil)

	sealed1, _ := SealSecret(senderPriv, gatewayPub, []byte("same-secret"))
	sealed2, _ := SealSecret(senderPriv, gatewayPub, []byte("same-secret"))

	if string(sealed1) == string(sealed2) {
		t.Fatal("encrypting same value should produce different ciphertexts (random nonce)")
	}
}

func TestOpenSecret_WrongKeyFails(t *testing.T) {
	_, senderPriv, _ := ed25519.GenerateKey(nil)
	gatewayPub, _, _ := ed25519.GenerateKey(nil)
	wrongPub, wrongPriv, _ := ed25519.GenerateKey(nil)

	sealed, err := SealSecret(senderPriv, gatewayPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Try to open with wrong gateway key
	_, err = OpenSecret(wrongPriv, wrongPub, sealed)
	if err == nil {
		t.Fatal("decrypting with wrong key should fail")
	}
}

func TestOpenSecret_ShortCiphertext(t *testing.T) {
	_, gatewayPriv, _ := ed25519.GenerateKey(nil)
	senderPub, _, _ := ed25519.GenerateKey(nil)

	_, err := OpenSecret(gatewayPriv, senderPub, []byte("tooshort"))
	if err == nil {
		t.Fatal("should reject short ciphertext")
	}
}

func TestBuildSecretPayload(t *testing.T) {
	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	gatewayPub, gatewayPriv, _ := ed25519.GenerateKey(nil)

	payload, err := BuildSecretPayload(
		senderPriv, senderPub, gatewayPub,
		"cred-1", "stripe",
		"Authorization", "Bearer {value}",
		"sk_test_secretkey123",
	)
	if err != nil {
		t.Fatal(err)
	}

	if payload.SecretID != "cred-1" {
		t.Fatalf("unexpected secret_id: %s", payload.SecretID)
	}
	if payload.Service != "stripe" {
		t.Fatalf("unexpected service: %s", payload.Service)
	}
	if payload.HeaderName != "Authorization" {
		t.Fatalf("unexpected header_name: %s", payload.HeaderName)
	}
	if payload.HeaderTemplate != "Bearer {value}" {
		t.Fatalf("unexpected header_template: %s", payload.HeaderTemplate)
	}
	if payload.SenderKID == "" {
		t.Fatal("sender_kid should not be empty")
	}

	// Verify we can parse and decrypt it
	body, _ := json.Marshal(payload)
	parsed, decrypted, err := ParseSecretPayload(gatewayPriv, senderPub, body)
	if err != nil {
		t.Fatalf("ParseSecretPayload: %v", err)
	}
	if parsed.SecretID != "cred-1" {
		t.Fatalf("parsed secret_id mismatch: %s", parsed.SecretID)
	}
	if decrypted != "sk_test_secretkey123" {
		t.Fatalf("decrypted value mismatch: %s", decrypted)
	}
}

func TestParseSecretPayload_WrongKey(t *testing.T) {
	senderPub, senderPriv, _ := ed25519.GenerateKey(nil)
	gatewayPub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)

	payload, _ := BuildSecretPayload(
		senderPriv, senderPub, gatewayPub,
		"cred-1", "stripe",
		"Authorization", "Bearer {value}",
		"sk_test_secretkey123",
	)
	body, _ := json.Marshal(payload)

	_, _, err := ParseSecretPayload(wrongPriv, senderPub, body)
	if err == nil {
		t.Fatal("should fail with wrong gateway key")
	}
}
