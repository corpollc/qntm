package gate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitGateway(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "gw-config")

	result, err := InitGateway(configDir)
	if err != nil {
		t.Fatalf("InitGateway: %v", err)
	}

	// Check identity was created
	if result.Identity == nil {
		t.Fatal("identity is nil")
	}
	if result.KeyID == "" {
		t.Fatal("key ID is empty")
	}
	if result.PublicKey == "" {
		t.Fatal("public key is empty")
	}

	// Check identity file exists
	if _, err := os.Stat(result.IdentityPath); err != nil {
		t.Fatalf("identity file not found: %v", err)
	}

	// Check vault directory exists
	info, err := os.Stat(result.VaultDir)
	if err != nil {
		t.Fatalf("vault directory not found: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("vault path is not a directory")
	}

	// Check conversations file exists
	convsPath := filepath.Join(configDir, "conversations.json")
	data, err := os.ReadFile(convsPath)
	if err != nil {
		t.Fatalf("conversations file not found: %v", err)
	}
	if string(data) != "[]" {
		t.Fatalf("unexpected conversations content: %s", string(data))
	}

	// Check permissions on identity file (owner read/write only)
	info, _ = os.Stat(result.IdentityPath)
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		t.Fatalf("identity file has permissive permissions: %o", perm)
	}
}

func TestInitGatewayAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "gw-config")

	// First init should succeed
	_, err := InitGateway(configDir)
	if err != nil {
		t.Fatalf("first InitGateway: %v", err)
	}

	// Second init should fail
	_, err = InitGateway(configDir)
	if err == nil {
		t.Fatal("expected error on duplicate init")
	}
}

func TestInitGatewayForce(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "gw-config")

	// First init
	result1, err := InitGateway(configDir)
	if err != nil {
		t.Fatalf("first InitGateway: %v", err)
	}

	// Force init should succeed and produce a different key
	result2, err := InitGatewayForce(configDir)
	if err != nil {
		t.Fatalf("InitGatewayForce: %v", err)
	}

	if result1.KeyID == result2.KeyID {
		t.Fatal("force init produced the same key ID (extremely unlikely)")
	}
}

func TestInitGatewayDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "deep", "nested", "gw")

	result, err := InitGateway(configDir)
	if err != nil {
		t.Fatalf("InitGateway with nested dir: %v", err)
	}

	// Verify all expected paths exist
	paths := []string{
		result.IdentityPath,
		result.VaultDir,
		filepath.Join(configDir, "conversations.json"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected path %s does not exist: %v", p, err)
		}
	}
}
