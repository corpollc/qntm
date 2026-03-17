package gate

import (
	"os"
	"testing"
	"time"
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

func TestConversationVault_TTL_RetrievableBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store with 15-minute TTL
	err = vault.StoreWithTTL("conv-ttl-1", "cred-1", "stripe",
		"Authorization", "Bearer {value}", "sk_live_xxx", 15*60)
	if err != nil {
		t.Fatal(err)
	}

	// Should be retrievable immediately (well before expiry)
	secret, err := vault.Get("conv-ttl-1", "stripe")
	if err != nil {
		t.Fatalf("expected secret to be retrievable before expiry, got: %v", err)
	}
	if secret.Value != "sk_live_xxx" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
	if secret.SecretID != "cred-1" {
		t.Fatalf("unexpected secret_id: %s", secret.SecretID)
	}
}

func TestConversationVault_TTL_ExpiredSecretReturnsError(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store with 1-second TTL
	err = vault.StoreWithTTL("conv-ttl-2", "cred-1", "github",
		"Authorization", "token {value}", "ghp_xxx", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Should return error for expired secret
	_, err = vault.Get("conv-ttl-2", "github")
	if err == nil {
		t.Fatal("expected error for expired secret, got nil")
	}
}

func TestConversationVault_TTL_ZeroMeansNoExpiry(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store with TTL=0 (no expiry) via StoreWithTTL
	err = vault.StoreWithTTL("conv-ttl-3", "cred-1", "aws",
		"Authorization", "AWS {value}", "AKIAIOSFODNN7EXAMPLE", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Should always be retrievable
	secret, err := vault.Get("conv-ttl-3", "aws")
	if err != nil {
		t.Fatalf("expected secret with TTL=0 to never expire, got: %v", err)
	}
	if secret.Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
}

func TestConversationVault_TTL_StoreWithoutTTLNeverExpires(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store via original Store method (no TTL)
	err = vault.Store("conv-ttl-4", "cred-1", "stripe",
		"Authorization", "Bearer {value}", "sk_test_xxx")
	if err != nil {
		t.Fatal(err)
	}

	// Should always be retrievable
	secret, err := vault.Get("conv-ttl-4", "stripe")
	if err != nil {
		t.Fatalf("expected secret without TTL to never expire, got: %v", err)
	}
	if secret.Value != "sk_test_xxx" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
}

func TestConversationVault_PurgeExpired(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	// Store one secret with 1s TTL and one without TTL
	err = vault.StoreWithTTL("conv-purge", "cred-exp", "expiring-svc",
		"Auth", "Bearer {value}", "will-expire", 1)
	if err != nil {
		t.Fatal(err)
	}
	err = vault.Store("conv-purge", "cred-keep", "keep-svc",
		"Auth", "Token {value}", "will-keep")
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the short-TTL secret to expire
	time.Sleep(2 * time.Second)

	// Purge expired
	purged := vault.PurgeExpired("conv-purge")
	if purged != 1 {
		t.Fatalf("expected 1 purged secret, got %d", purged)
	}

	// Expired secret should be gone
	_, err = vault.Get("conv-purge", "expiring-svc")
	if err == nil {
		t.Fatal("expected error for purged secret")
	}

	// Non-expiring secret should still be there
	secret, err := vault.Get("conv-purge", "keep-svc")
	if err != nil {
		t.Fatalf("expected non-expiring secret to survive purge: %v", err)
	}
	if secret.Value != "will-keep" {
		t.Fatalf("unexpected value: %s", secret.Value)
	}
}

func TestConversationVault_TTL_CommonDurations(t *testing.T) {
	// Test that TTL values of 15min, 60min, and 4hr store correctly
	dir := t.TempDir()
	key := make([]byte, 32)
	vault, err := NewConversationVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	ttls := map[string]int{
		"svc-15m": 15 * 60,      // 15 minutes
		"svc-60m": 60 * 60,      // 60 minutes
		"svc-4hr": 4 * 60 * 60,  // 4 hours
	}

	for svc, ttl := range ttls {
		err = vault.StoreWithTTL("conv-durations", "cred-"+svc, svc,
			"Auth", "Bearer {value}", "secret-"+svc, ttl)
		if err != nil {
			t.Fatalf("store %s: %v", svc, err)
		}
	}

	// All should be retrievable immediately
	for svc := range ttls {
		secret, err := vault.Get("conv-durations", svc)
		if err != nil {
			t.Fatalf("get %s: %v", svc, err)
		}
		if secret.Value != "secret-"+svc {
			t.Fatalf("unexpected value for %s: %s", svc, secret.Value)
		}
	}
}
