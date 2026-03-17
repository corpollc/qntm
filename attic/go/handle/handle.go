// Package handle implements handle reveal and verification per QSP v1.1 §2.4.
package handle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/corpo/qntm/registry"
)

// RevealPayload is the body of a handle_reveal message (CBOR-encoded).
type RevealPayload struct {
	Handle    string `cbor:"handle"`
	HandleSalt []byte `cbor:"handle_salt"`
}

// RevealedHandle is a stored revealed handle for a conversation.
type RevealedHandle struct {
	KID    string `json:"kid"`    // hex
	Handle string `json:"handle"`
}

// Store manages revealed handles per conversation and local handle credentials.
type Store struct {
	mu   sync.RWMutex
	dir  string
	data *storeData
}

type storeData struct {
	// My handle credentials (for revealing)
	MyHandle string `json:"my_handle,omitempty"`
	MySalt   string `json:"my_salt,omitempty"` // hex
	// Commitments I know about: kid hex -> commitment hex
	Commitments map[string]string `json:"commitments"`
	// Revealed handles per conversation: conv_id hex -> []RevealedHandle
	Revealed map[string][]RevealedHandle `json:"revealed"`
}

// NewStore creates or loads a handle store.
func NewStore(dir string) (*Store, error) {
	path := filepath.Join(dir, "handles.json")
	s := &Store{
		dir: dir,
		data: &storeData{
			Commitments: make(map[string]string),
			Revealed:    make(map[string][]RevealedHandle),
		},
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, s.data); err != nil {
			return nil, fmt.Errorf("corrupt handles.json: %w", err)
		}
	}
	return s, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "handles.json"), data, 0600)
}

// SetMyHandle stores local handle credentials.
func (s *Store) SetMyHandle(handle, saltHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.MyHandle = handle
	s.data.MySalt = saltHex
	return s.save()
}

// GetMyHandle returns my handle and salt (hex).
func (s *Store) GetMyHandle() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.MyHandle, s.data.MySalt
}

// SetCommitment stores a known commitment for a kid.
func (s *Store) SetCommitment(kidHex, commitmentHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Commitments[kidHex] = commitmentHex
	return s.save()
}

// GetCommitment returns the commitment for a kid.
func (s *Store) GetCommitment(kidHex string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Commitments[kidHex]
}

// VerifyReveal verifies a handle reveal against a known commitment.
func VerifyReveal(handle string, ikPK ed25519.PublicKey, salt []byte, expectedCommitmentHex string) error {
	commitment, err := registry.ComputeCommitment(handle, ikPK, salt)
	if err != nil {
		return fmt.Errorf("failed to compute commitment: %w", err)
	}
	expected, err := hex.DecodeString(expectedCommitmentHex)
	if err != nil {
		return fmt.Errorf("invalid commitment hex: %w", err)
	}
	if !bytes.Equal(commitment, expected) {
		return fmt.Errorf("commitment mismatch: reveal verification failed")
	}
	return nil
}

// StoreReveal stores a verified reveal for a conversation.
func (s *Store) StoreReveal(convIDHex, kidHex, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Check if already revealed
	for _, r := range s.data.Revealed[convIDHex] {
		if r.KID == kidHex {
			// Update
			r.Handle = handle
			return s.save()
		}
	}
	s.data.Revealed[convIDHex] = append(s.data.Revealed[convIDHex], RevealedHandle{
		KID:    kidHex,
		Handle: handle,
	})
	return s.save()
}

// GetRevealedHandle returns the revealed handle for a kid in a conversation.
func (s *Store) GetRevealedHandle(convIDHex, kidHex string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.data.Revealed[convIDHex] {
		if r.KID == kidHex {
			return r.Handle
		}
	}
	return ""
}
