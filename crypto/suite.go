package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Suite QSP-1 constants
const (
	SuiteQSP1      = "QSP-1"
	ProtoPrefix    = "qntm/qsp/v1"
	
	// Key derivation info strings
	InfoRoot  = "qntm/qsp/v1/root"
	InfoAEAD  = "qntm/qsp/v1/aead"
	InfoNonce = "qntm/qsp/v1/nonce"
)

var (
	ErrInvalidSuite     = errors.New("unsupported cryptographic suite")
	ErrInvalidKeyLength = errors.New("invalid key length")
	ErrDecryptionFailed = errors.New("AEAD decryption failed")
	ErrInvalidSignature = errors.New("signature verification failed")
)

// QSP1Suite implements the QSP-1 cryptographic suite
type QSP1Suite struct{}

// NewQSP1Suite creates a new QSP-1 suite implementation
func NewQSP1Suite() *QSP1Suite {
	return &QSP1Suite{}
}

// Name returns the suite identifier
func (s *QSP1Suite) Name() string {
	return SuiteQSP1
}

// GenerateIdentityKey generates a new Ed25519 identity key pair
func (s *QSP1Suite) GenerateIdentityKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// ComputeKeyID computes the 16-byte key identifier from a public key
func (s *QSP1Suite) ComputeKeyID(pubkey ed25519.PublicKey) [16]byte {
	hash := sha256.Sum256(pubkey)
	var keyID [16]byte
	copy(keyID[:], hash[:16])
	return keyID
}

// DeriveRootKey derives the root key from invite secret and salt
func (s *QSP1Suite) DeriveRootKey(inviteSecret, inviteSalt, convID []byte) ([]byte, error) {
	if len(inviteSecret) != 32 {
		return nil, fmt.Errorf("invite secret must be 32 bytes, got %d", len(inviteSecret))
	}
	
	// PRK = HKDF-Extract(salt=invite_salt, IKM=invite_secret)
	prk := hkdf.Extract(sha256.New, inviteSecret, inviteSalt)
	
	// root = HKDF-Expand(PRK, info="qntm/qsp/v1/root" || conv_id, L=32)
	info := append([]byte(InfoRoot), convID...)
	root := make([]byte, 32)
	
	reader := hkdf.Expand(sha256.New, prk, info)
	if _, err := reader.Read(root); err != nil {
		return nil, fmt.Errorf("failed to derive root key: %w", err)
	}
	
	return root, nil
}

// DeriveConversationKeys derives AEAD and nonce keys from root key
func (s *QSP1Suite) DeriveConversationKeys(rootKey, convID []byte) (aeadKey, nonceKey []byte, err error) {
	if len(rootKey) != 32 {
		return nil, nil, fmt.Errorf("root key must be 32 bytes, got %d", len(rootKey))
	}
	
	// k_aead = HKDF-Expand(root, info="qntm/qsp/v1/aead" || conv_id, L=32)
	aeadInfo := append([]byte(InfoAEAD), convID...)
	aeadKey = make([]byte, 32)
	aeadReader := hkdf.Expand(sha256.New, rootKey, aeadInfo)
	if _, err := aeadReader.Read(aeadKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive AEAD key: %w", err)
	}
	
	// k_nonce = HKDF-Expand(root, info="qntm/qsp/v1/nonce" || conv_id, L=32)
	nonceInfo := append([]byte(InfoNonce), convID...)
	nonceKey = make([]byte, 32)
	nonceReader := hkdf.Expand(sha256.New, rootKey, nonceInfo)
	if _, err := nonceReader.Read(nonceKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive nonce key: %w", err)
	}
	
	return aeadKey, nonceKey, nil
}

// DeriveNonce derives a deterministic nonce from message ID
func (s *QSP1Suite) DeriveNonce(nonceKey, msgID []byte) ([24]byte, error) {
	if len(nonceKey) != 32 {
		return [24]byte{}, fmt.Errorf("nonce key must be 32 bytes, got %d", len(nonceKey))
	}
	if len(msgID) != 16 {
		return [24]byte{}, fmt.Errorf("message ID must be 16 bytes, got %d", len(msgID))
	}
	
	// nonce = Trunc24(HMAC-SHA-256(k_nonce, msg_id))
	h := sha256.New()
	h.Write(nonceKey)
	h.Write(msgID)
	hash := h.Sum(nil)
	
	var nonce [24]byte
	copy(nonce[:], hash[:24])
	return nonce, nil
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305
func (s *QSP1Suite) Encrypt(aeadKey []byte, nonce [24]byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}
	
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305
func (s *QSP1Suite) Decrypt(aeadKey []byte, nonce [24]byte, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}
	
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	
	return plaintext, nil
}

// Sign creates an Ed25519 signature
func (s *QSP1Suite) Sign(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}
	
	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

// Verify verifies an Ed25519 signature
func (s *QSP1Suite) Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: %d", len(publicKey))
	}
	
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	
	return nil
}

// Hash computes SHA-256 hash
func (s *QSP1Suite) Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}