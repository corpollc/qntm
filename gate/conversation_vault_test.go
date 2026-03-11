package gate

import (
	"os"
	"testing"
)

func TestConversationVault_StoreGet(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	err = vault.Store("conv-abc123", "cred-1", "stripe",
		"Authorization", "Bearer {value}", "sk_test_secretkey123")
	if err != nil {
		t.Fatal(err)
	}

	secret, err := vault.Get("conv-abc123", "stripe")
	if err != nil {
		t.Fatal(err)
	}

	if secret.SecretID != "cred-1" {
		t.Fatalf("unexpected secret_id: %s", secret.SecretID)
	}
	if secret.Service != "stripe" {
		t.Fatalf("unexpected service: %s", secret.Service)
	}
	if secret.HeaderName != "Authorization" {
		t.Fatalf("unexpected header_name: %s", secret.HeaderName)
	}
	if secret.HeaderTemplate != "Bearer {value}" {
		t.Fatalf("unexpected header_template: %s", secret.HeaderTemplate)
	}
	if secret.Value != "sk_test_secretkey123" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
}

func TestConversationVault_GetMissing(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, _ := NewConversationVault(dir, key)

	_, err := vault.Get("conv-none", "stripe")
	if err == nil {
		t.Fatal("should fail for missing service")
	}
}

func TestConversationVault_OverwriteService(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, _ := NewConversationVault(dir, key)

	_ = vault.Store("conv-1", "old", "stripe", "Auth", "Bearer {value}", "old-key")
	_ = vault.Store("conv-1", "new", "stripe", "Auth", "Token {value}", "new-key")

	secret, err := vault.Get("conv-1", "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if secret.SecretID != "new" {
		t.Fatalf("expected overwritten secret, got %s", secret.SecretID)
	}
	if secret.Value != "new-key" {
		t.Fatalf("expected overwritten value, got %s", secret.Value)
	}
	if secret.HeaderTemplate != "Token {value}" {
		t.Fatalf("expected overwritten template, got %s", secret.HeaderTemplate)
	}
}

func TestConversationVault_MultipleServices(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, _ := NewConversationVault(dir, key)

	_ = vault.Store("conv-1", "cred-1", "stripe", "Authorization", "Bearer {value}", "stripe-key")
	_ = vault.Store("conv-1", "cred-2", "github", "Authorization", "token {value}", "github-token")

	s1, _ := vault.Get("conv-1", "stripe")
	s2, _ := vault.Get("conv-1", "github")

	if s1.Value != "stripe-key" {
		t.Fatalf("stripe value wrong: %s", s1.Value)
	}
	if s2.Value != "github-token" {
		t.Fatalf("github value wrong: %s", s2.Value)
	}
}

func TestConversationVault_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	vault1, _ := NewConversationVault(dir, key1)
	_ = vault1.Store("conv-1", "cred-1", "stripe", "Auth", "Bearer {value}", "secret")

	vault2, _ := NewConversationVault(dir, key2)
	_, err := vault2.Get("conv-1", "stripe")
	if err == nil {
		t.Fatal("should fail with wrong vault key")
	}
}

func TestConversationVault_AutoGenerateKey(t *testing.T) {
	dir := t.TempDir()

	vault1, err := NewConversationVault(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	_ = vault1.Store("conv-1", "c", "svc", "H", "T", "val")

	// Same dir should re-use the key
	vault2, err := NewConversationVault(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := vault2.Get("conv-1", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "val" {
		t.Fatalf("expected val, got %s", secret.Value)
	}
}

func TestConversationVault_EnvKey(t *testing.T) {
	dir := t.TempDir()

	os.Setenv("GATE_VAULT_KEY", "test-vault-key-for-unit-test")
	defer os.Unsetenv("GATE_VAULT_KEY")

	vault, err := NewConversationVault(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	_ = vault.Store("conv-1", "c", "svc", "H", "T", "val")

	// Re-create with same env key
	vault2, err := NewConversationVault(dir+"/sub", nil)
	if err != nil {
		t.Fatal(err)
	}

	_ = vault2.Store("conv-1", "c", "svc", "H", "T", "val2")
	secret, err := vault2.Get("conv-1", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "val2" {
		t.Fatalf("expected val2, got %s", secret.Value)
	}
}
