package handle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/corpo/qntm/registry"
)

func TestVerifyReveal(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	salt := make([]byte, 32)
	rand.Read(salt)

	commitment, err := registry.ComputeCommitment("alice", pub, salt)
	if err != nil {
		t.Fatal(err)
	}
	commitmentHex := hex.EncodeToString(commitment)

	// Should pass
	if err := VerifyReveal("alice", pub, salt, commitmentHex); err != nil {
		t.Errorf("valid reveal failed: %v", err)
	}

	// Wrong handle
	if err := VerifyReveal("bob", pub, salt, commitmentHex); err == nil {
		t.Error("wrong handle should fail")
	}

	// Wrong salt
	badSalt := make([]byte, 32)
	rand.Read(badSalt)
	if err := VerifyReveal("alice", pub, badSalt, commitmentHex); err == nil {
		t.Error("wrong salt should fail")
	}
}

func TestStoreReveal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.StoreReveal("conv1234", "kid5678", "alice")
	if got := s.GetRevealedHandle("conv1234", "kid5678"); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
	if got := s.GetRevealedHandle("conv1234", "other"); got != "" {
		t.Errorf("expected empty for unknown kid")
	}
}

func TestStoreMyHandle(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetMyHandle("alice", "aabbccdd")
	h, salt := s.GetMyHandle()
	if h != "alice" || salt != "aabbccdd" {
		t.Errorf("got %q %q", h, salt)
	}

	// Reload
	s2, _ := NewStore(dir)
	h2, salt2 := s2.GetMyHandle()
	if h2 != "alice" || salt2 != "aabbccdd" {
		t.Errorf("after reload: %q %q", h2, salt2)
	}
}

func TestStoreCommitment(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hash := sha256.Sum256(pub)
	kid := hex.EncodeToString(hash[:16])

	s.SetCommitment(kid, "deadbeef")
	if got := s.GetCommitment(kid); got != "deadbeef" {
		t.Errorf("got %q", got)
	}
}
