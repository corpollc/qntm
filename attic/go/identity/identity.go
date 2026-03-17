package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// Manager handles identity creation, storage, and retrieval
type Manager struct {
	suite *crypto.QSP1Suite
}

// NewManager creates a new identity manager
func NewManager() *Manager {
	return &Manager{
		suite: crypto.NewQSP1Suite(),
	}
}

// GenerateIdentity creates a new agent identity
func (m *Manager) GenerateIdentity() (*types.Identity, error) {
	pub, priv, err := m.suite.GenerateIdentityKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}
	
	keyID := m.suite.ComputeKeyID(pub)
	
	identity := &types.Identity{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      keyID,
	}
	
	return identity, nil
}

// KeyIDFromPublicKey computes the key identifier for a public key
func (m *Manager) KeyIDFromPublicKey(pubkey ed25519.PublicKey) types.KeyID {
	return m.suite.ComputeKeyID(pubkey)
}

// VerifyKeyID verifies that a key ID matches the given public key
func (m *Manager) VerifyKeyID(pubkey ed25519.PublicKey, keyID types.KeyID) bool {
	computed := m.suite.ComputeKeyID(pubkey)
	return computed == keyID
}

// SerializeIdentity serializes an identity to canonical CBOR
func (m *Manager) SerializeIdentity(identity *types.Identity) ([]byte, error) {
	// Create a serializable structure
	data := struct {
		PrivateKey []byte        `cbor:"private_key"`
		PublicKey  []byte        `cbor:"public_key"`
		KeyID      types.KeyID   `cbor:"key_id"`
	}{
		PrivateKey: identity.PrivateKey,
		PublicKey:  identity.PublicKey,
		KeyID:      identity.KeyID,
	}
	
	return cbor.MarshalCanonical(data)
}

// DeserializeIdentity deserializes an identity from canonical CBOR
func (m *Manager) DeserializeIdentity(data []byte) (*types.Identity, error) {
	var serialized struct {
		PrivateKey []byte        `cbor:"private_key"`
		PublicKey  []byte        `cbor:"public_key"`
		KeyID      types.KeyID   `cbor:"key_id"`
	}
	
	if err := cbor.UnmarshalCanonical(data, &serialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity: %w", err)
	}
	
	// Validate key lengths
	if len(serialized.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(serialized.PrivateKey))
	}
	if len(serialized.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(serialized.PublicKey))
	}
	
	identity := &types.Identity{
		PrivateKey: ed25519.PrivateKey(serialized.PrivateKey),
		PublicKey:  ed25519.PublicKey(serialized.PublicKey),
		KeyID:      serialized.KeyID,
	}
	
	// Verify that the key ID is correct
	if !m.VerifyKeyID(identity.PublicKey, identity.KeyID) {
		return nil, fmt.Errorf("key ID does not match public key")
	}
	
	return identity, nil
}

// PublicKeyToString converts a public key to a base64url string
func (m *Manager) PublicKeyToString(pubkey ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pubkey)
}

// PublicKeyFromString parses a public key from a base64url string
func (m *Manager) PublicKeyFromString(s string) (ed25519.PublicKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url encoding: %w", err)
	}
	
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(data))
	}
	
	return ed25519.PublicKey(data), nil
}

// KeyIDToString converts a key ID to a base64url string
func (m *Manager) KeyIDToString(keyID types.KeyID) string {
	return base64.RawURLEncoding.EncodeToString(keyID[:])
}

// KeyIDFromString parses a key ID from a base64url string
func (m *Manager) KeyIDFromString(s string) (types.KeyID, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return types.KeyID{}, fmt.Errorf("invalid base64url encoding: %w", err)
	}
	
	if len(data) != 16 {
		return types.KeyID{}, fmt.Errorf("invalid key ID length: %d", len(data))
	}
	
	var keyID types.KeyID
	copy(keyID[:], data)
	return keyID, nil
}

// GenerateRandomBytes generates cryptographically random bytes
func (m *Manager) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateConversationID generates a random 16-byte conversation ID
func (m *Manager) GenerateConversationID() (types.ConversationID, error) {
	bytes, err := m.GenerateRandomBytes(16)
	if err != nil {
		return types.ConversationID{}, err
	}
	
	var convID types.ConversationID
	copy(convID[:], bytes)
	return convID, nil
}

// GenerateMessageID generates a random 16-byte message ID
func (m *Manager) GenerateMessageID() (types.MessageID, error) {
	bytes, err := m.GenerateRandomBytes(16)
	if err != nil {
		return types.MessageID{}, err
	}
	
	var msgID types.MessageID
	copy(msgID[:], bytes)
	return msgID, nil
}

// ValidateIdentity performs validation checks on an identity
func (m *Manager) ValidateIdentity(identity *types.Identity) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}
	
	// Check key lengths
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key length: %d", len(identity.PrivateKey))
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: %d", len(identity.PublicKey))
	}
	
	// Verify key ID matches public key
	if !m.VerifyKeyID(identity.PublicKey, identity.KeyID) {
		return fmt.Errorf("key ID does not match public key")
	}
	
	// Test that the key pair works for signing
	testMessage := []byte("validation test")
	signature, err := m.suite.Sign(identity.PrivateKey, testMessage)
	if err != nil {
		return fmt.Errorf("private key cannot sign: %w", err)
	}
	
	err = m.suite.Verify(identity.PublicKey, testMessage, signature)
	if err != nil {
		return fmt.Errorf("public key cannot verify signature from private key: %w", err)
	}
	
	return nil
}