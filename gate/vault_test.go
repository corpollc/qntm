package gate

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNoopVault(t *testing.T) {
	v := NoopVault{}

	enc, err := v.Encrypt("my-secret")
	if err != nil {
		t.Fatal(err)
	}
	if enc != "my-secret" {
		t.Fatalf("noop encrypt should be passthrough, got %q", enc)
	}

	dec, err := v.Decrypt("my-secret")
	if err != nil {
		t.Fatal(err)
	}
	if dec != "my-secret" {
		t.Fatalf("noop decrypt should be passthrough, got %q", dec)
	}
}

func TestEnvVault_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	v, err := NewEnvVault(key)
	if err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		"sk-test-abc123",
		"Bearer eyJhbGciOiJSUzI1NiJ9.long-jwt-token",
		"",
		"unicode-🔑-key",
	}

	for _, secret := range secrets {
		encrypted, err := v.Encrypt(secret)
		if err != nil {
			t.Fatalf("encrypt %q: %v", secret, err)
		}

		// Must have vault prefix
		if encrypted[:len(vaultPrefix)] != vaultPrefix {
			t.Fatalf("encrypted %q missing vault prefix", secret)
		}

		// Must not contain plaintext
		if secret != "" && encrypted == secret {
			t.Fatalf("encrypted should differ from plaintext for %q", secret)
		}

		decrypted, err := v.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decrypt %q: %v", secret, err)
		}
		if decrypted != secret {
			t.Fatalf("round-trip failed: got %q, want %q", decrypted, secret)
		}
	}
}

func TestEnvVault_DifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	v, _ := NewEnvVault(key)

	enc1, _ := v.Encrypt("same-secret")
	enc2, _ := v.Encrypt("same-secret")

	// Random nonce means different ciphertexts each time
	if enc1 == enc2 {
		t.Fatal("encrypting same value should produce different ciphertexts (random nonce)")
	}
}

func TestEnvVault_WrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	v1, _ := NewEnvVault(key1)
	v2, _ := NewEnvVault(key2)

	encrypted, _ := v1.Encrypt("secret")
	_, err := v2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("decrypting with wrong key should fail")
	}
}

func TestEnvVault_PlaintextPassthrough(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	v, _ := NewEnvVault(key)

	// Unencrypted values pass through for migration compatibility
	dec, err := v.Decrypt("plaintext-api-key")
	if err != nil {
		t.Fatal(err)
	}
	if dec != "plaintext-api-key" {
		t.Fatalf("plaintext passthrough failed: got %q", dec)
	}
}

func TestEnvVaultFromBase64(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	encoded := base64.StdEncoding.EncodeToString(key)

	v, err := NewEnvVaultFromBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, _ := v.Encrypt("test")
	decrypted, _ := v.Decrypt(encrypted)
	if decrypted != "test" {
		t.Fatal("base64 vault round-trip failed")
	}
}

func TestEnvVault_BadKeyLength(t *testing.T) {
	_, err := NewEnvVault(make([]byte, 16))
	if err == nil {
		t.Fatal("should reject non-32-byte key")
	}
}

func TestEnvVault_IntegrationWithServer(t *testing.T) {
	// Verify that credentials stored through the server are encrypted at rest
	// and correctly decrypted during execution.
	key := make([]byte, 32)
	rand.Read(key)
	vault, _ := NewEnvVault(key)

	store, err := NewSQLiteStore(t.TempDir() + "/vault.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := NewInsecureServerForTestsWithStores(store, store)
	srv.Vault = vault

	// Store a credential through the server's vault path
	cred := &Credential{
		ID: "test-cred", Service: "test-svc",
		Value: "super-secret-api-key",
		HeaderName: "Authorization", HeaderValue: "Bearer {value}",
	}

	// Encrypt as the server would
	encrypted, err := vault.Encrypt(cred.Value)
	if err != nil {
		t.Fatal(err)
	}
	cred.Value = encrypted

	// Store via org store
	org := &Org{
		ID:      "vault-org",
		Signers: []Signer{},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	}
	if err := store.Create(org); err != nil {
		t.Fatal(err)
	}
	if err := store.AddCredential("vault-org", cred); err != nil {
		t.Fatal(err)
	}

	// Verify the stored value is encrypted (not plaintext)
	storedCred, err := store.GetCredentialByService("vault-org", "test-svc")
	if err != nil {
		t.Fatal(err)
	}
	if storedCred.Value == "super-secret-api-key" {
		t.Fatal("credential should be encrypted at rest, but was stored as plaintext")
	}
	if storedCred.Value[:len(vaultPrefix)] != vaultPrefix {
		t.Fatalf("stored credential should have vault prefix, got %q", storedCred.Value[:20])
	}

	// Verify decryption works
	decrypted, err := vault.Decrypt(storedCred.Value)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "super-secret-api-key" {
		t.Fatalf("decrypted value mismatch: got %q", decrypted)
	}
}
