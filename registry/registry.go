// Package registry implements the QSP v1.1 handle registry server.
// Per spec §2.2: stores public commitments and enforces handle uniqueness.
package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// CommitmentInput is the CBOR structure hashed for the commitment.
// Field order in CBOR canonical encoding is determined by key sort order.
type CommitmentInput struct {
	Handle string `cbor:"handle"`
	IKPK   []byte `cbor:"ik_pk"`
	Salt   []byte `cbor:"salt"`
}

// ComputeCommitment computes H(CBOR({handle, ik_pk, salt})) per spec §2.3.
func ComputeCommitment(handle string, ikPK ed25519.PublicKey, salt []byte) ([]byte, error) {
	input := CommitmentInput{
		Handle: handle,
		IKPK:   []byte(ikPK),
		Salt:   salt,
	}
	data, err := cbor.MarshalCanonical(input)
	if err != nil {
		return nil, fmt.Errorf("CBOR marshal failed: %w", err)
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// Table1Entry is the public commitment table entry.
type Table1Entry struct {
	KID              string `json:"kid"`
	HandleCommitment string `json:"handle_commitment"` // hex
}

// Table2Entry is the internal uniqueness table entry.
type Table2Entry struct {
	Handle string `json:"handle"`
	KID    string `json:"kid"`
}

// Store is the registry's persistent storage.
type Store struct {
	mu          sync.RWMutex
	dir         string
	Commitments map[string]*Table1Entry `json:"commitments"` // kid hex -> entry
	Handles     map[string]*Table2Entry `json:"handles"`     // handle -> entry
}

// NewStore creates or loads a registry store.
func NewStore(dir string) (*Store, error) {
	s := &Store{
		dir:         dir,
		Commitments: make(map[string]*Table1Entry),
		Handles:     make(map[string]*Table2Entry),
	}
	path := filepath.Join(dir, "registry.json")
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, s); err != nil {
			return nil, fmt.Errorf("corrupt registry.json: %w", err)
		}
	}
	return s, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "registry.json"), data, 0600)
}

// RegisterRequest is the JSON body for POST /register.
type RegisterRequest struct {
	KID       string `json:"kid"`        // hex-encoded key ID
	IKPK      string `json:"ik_pk"`      // hex-encoded public key
	Handle    string `json:"handle"`
	Signature string `json:"signature"`  // hex-encoded Ed25519 signature
}

// RegisterResponse is returned on successful registration.
type RegisterResponse struct {
	Salt string `json:"salt"` // hex-encoded 32-byte salt
}

// ChangeRequest is the JSON body for POST /change.
type ChangeRequest struct {
	KID       string `json:"kid"`
	IKPK      string `json:"ik_pk"`
	NewHandle string `json:"new_handle"`
	Signature string `json:"signature"`
}

// DeleteRequest is the JSON body for DELETE /handle.
type DeleteRequest struct {
	KID       string `json:"kid"`
	IKPK      string `json:"ik_pk"`
	Signature string `json:"signature"`
}

// verifySignature verifies an Ed25519 signature over the given message.
func verifySignature(ikPKHex, signatureHex string, message []byte) (ed25519.PublicKey, error) {
	ikPK, err := hex.DecodeString(ikPKHex)
	if err != nil || len(ikPK) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key")
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(ikPK), message, sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	return ed25519.PublicKey(ikPK), nil
}

// verifyKID checks that the kid matches the public key.
func verifyKID(kidHex string, ikPK ed25519.PublicKey) error {
	hash := sha256.Sum256(ikPK)
	var expected types.KeyID
	copy(expected[:], hash[:16])
	expectedHex := hex.EncodeToString(expected[:])
	if kidHex != expectedHex {
		return fmt.Errorf("kid does not match public key")
	}
	return nil
}

// Server is the HTTP handle registry server.
type Server struct {
	store *Store
}

// NewServer creates a new registry server.
func NewServer(store *Store) *Server {
	return &Server{store: store}
}

// Handler returns the HTTP handler for the registry.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /commitment/", s.handleGetCommitment)
	mux.HandleFunc("POST /change", s.handleChange)
	mux.HandleFunc("DELETE /handle", s.handleDelete)
	return mux
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Handle == "" || len(req.Handle) > 64 {
		jsonError(w, "handle must be 1-64 bytes", http.StatusBadRequest)
		return
	}

	// Verify signature over "register:<kid>:<handle>"
	msg := []byte("register:" + req.KID + ":" + req.Handle)
	ikPK, err := verifySignature(req.IKPK, req.Signature, msg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := verifyKID(req.KID, ikPK); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	// Check uniqueness
	if existing, ok := s.store.Handles[req.Handle]; ok && existing.KID != req.KID {
		jsonError(w, "handle already taken", http.StatusConflict)
		return
	}

	// Check if kid already has a handle
	if _, ok := s.store.Commitments[req.KID]; ok {
		jsonError(w, "kid already registered (use /change)", http.StatusConflict)
		return
	}

	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Compute commitment
	commitment, err := ComputeCommitment(req.Handle, ikPK, salt)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.store.Commitments[req.KID] = &Table1Entry{
		KID:              req.KID,
		HandleCommitment: hex.EncodeToString(commitment),
	}
	s.store.Handles[req.Handle] = &Table2Entry{
		Handle: req.Handle,
		KID:    req.KID,
	}

	if err := s.store.save(); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RegisterResponse{Salt: hex.EncodeToString(salt)})
}

func (s *Server) handleGetCommitment(w http.ResponseWriter, r *http.Request) {
	// Extract kid from path: /commitment/<kid>
	kid := strings.TrimPrefix(r.URL.Path, "/commitment/")
	if kid == "" {
		jsonError(w, "kid required", http.StatusBadRequest)
		return
	}

	s.store.mu.RLock()
	entry, ok := s.store.Commitments[kid]
	s.store.mu.RUnlock()

	if !ok {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (s *Server) handleChange(w http.ResponseWriter, r *http.Request) {
	var req ChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.NewHandle == "" || len(req.NewHandle) > 64 {
		jsonError(w, "handle must be 1-64 bytes", http.StatusBadRequest)
		return
	}

	msg := []byte("change:" + req.KID + ":" + req.NewHandle)
	ikPK, err := verifySignature(req.IKPK, req.Signature, msg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := verifyKID(req.KID, ikPK); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	// Must have existing registration
	if _, ok := s.store.Commitments[req.KID]; !ok {
		jsonError(w, "kid not registered", http.StatusNotFound)
		return
	}

	// Check new handle uniqueness
	if existing, ok := s.store.Handles[req.NewHandle]; ok && existing.KID != req.KID {
		jsonError(w, "handle already taken", http.StatusConflict)
		return
	}

	// Remove old handle from Table 2
	for h, entry := range s.store.Handles {
		if entry.KID == req.KID {
			delete(s.store.Handles, h)
			break
		}
	}

	// Generate new salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	commitment, err := ComputeCommitment(req.NewHandle, ikPK, salt)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.store.Commitments[req.KID] = &Table1Entry{
		KID:              req.KID,
		HandleCommitment: hex.EncodeToString(commitment),
	}
	s.store.Handles[req.NewHandle] = &Table2Entry{
		Handle: req.NewHandle,
		KID:    req.KID,
	}

	if err := s.store.save(); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RegisterResponse{Salt: hex.EncodeToString(salt)})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req DeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	msg := []byte("delete:" + req.KID)
	_, err := verifySignature(req.IKPK, req.Signature, msg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	ikPK, _ := hex.DecodeString(req.IKPK)
	if err := verifyKID(req.KID, ed25519.PublicKey(ikPK)); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.store.Commitments[req.KID]; !ok {
		jsonError(w, "kid not registered", http.StatusNotFound)
		return
	}

	// Remove from both tables
	for h, entry := range s.store.Handles {
		if entry.KID == req.KID {
			delete(s.store.Handles, h)
			break
		}
	}
	delete(s.store.Commitments, req.KID)

	if err := s.store.save(); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
