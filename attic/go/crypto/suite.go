package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
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
	
	// Key derivation info strings (v1.0)
	InfoRoot  = "qntm/qsp/v1/root"
	InfoAEAD  = "qntm/qsp/v1/aead"
	InfoNonce = "qntm/qsp/v1/nonce"
	
	// Key derivation info strings (v1.1 epoch-based)
	InfoAEADv11  = "qntm/qsp/v1.1/aead"
	InfoNoncev11 = "qntm/qsp/v1.1/nonce"
	InfoWrapv11  = "qntm/qsp/v1.1/wrap"
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
	mac := hmac.New(sha256.New, nonceKey)
	mac.Write(msgID)
	hash := mac.Sum(nil)
	
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

// DeriveEpochKeys derives AEAD and nonce keys for a given epoch.
// Epoch 0 uses v1.0 info strings for backward compatibility.
// Epoch 1+ uses v1.1 info strings with conv_id and epoch appended.
func (s *QSP1Suite) DeriveEpochKeys(groupKey, convID []byte, epoch uint) (aeadKey, nonceKey []byte, err error) {
	if len(groupKey) != 32 {
		return nil, nil, fmt.Errorf("group key must be 32 bytes, got %d", len(groupKey))
	}

	if epoch == 0 {
		// v1.0 compatibility: use original info strings
		return s.DeriveConversationKeys(groupKey, convID)
	}

	// v1.1: info = "qntm/qsp/v1.1/aead" || conv_id || epoch(big-endian 4 bytes)
	epochBytes := make([]byte, 4)
	epochBytes[0] = byte(epoch >> 24)
	epochBytes[1] = byte(epoch >> 16)
	epochBytes[2] = byte(epoch >> 8)
	epochBytes[3] = byte(epoch)

	aeadInfo := append([]byte(InfoAEADv11), convID...)
	aeadInfo = append(aeadInfo, epochBytes...)
	aeadKey = make([]byte, 32)
	aeadReader := hkdf.Expand(sha256.New, groupKey, aeadInfo)
	if _, err := aeadReader.Read(aeadKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive epoch AEAD key: %w", err)
	}

	nonceInfo := append([]byte(InfoNoncev11), convID...)
	nonceInfo = append(nonceInfo, epochBytes...)
	nonceKey = make([]byte, 32)
	nonceReader := hkdf.Expand(sha256.New, groupKey, nonceInfo)
	if _, err := nonceReader.Read(nonceKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive epoch nonce key: %w", err)
	}

	return aeadKey, nonceKey, nil
}

// WrapKeyForRecipient wraps a new group key for a recipient using their Ed25519 public key.
// Returns CBOR({ek_pk: bytes(32), nonce: bytes(24), ct: bytes(48)}).
func (s *QSP1Suite) WrapKeyForRecipient(newGroupKey []byte, recipientEd25519PK ed25519.PublicKey, recipientKID [16]byte, convID []byte) ([]byte, error) {
	if len(newGroupKey) != 32 {
		return nil, fmt.Errorf("group key must be 32 bytes")
	}

	// 1. Convert recipient Ed25519 public key to X25519
	recipientX25519, err := Ed25519PublicKeyToX25519(recipientEd25519PK)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient key: %w", err)
	}

	// 2. Generate ephemeral X25519 keypair
	ekSK, ekPK, err := GenerateX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// 3. Compute shared secret
	ss, err := X25519SharedSecret(ekSK, recipientX25519)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// 4. Derive wrap key
	prkWrap := hkdf.Extract(sha256.New, ss, convID)
	wrapInfo := append([]byte(InfoWrapv11), recipientKID[:]...)
	wk := make([]byte, 32)
	wkReader := hkdf.Expand(sha256.New, prkWrap, wrapInfo)
	if _, err := wkReader.Read(wk); err != nil {
		return nil, fmt.Errorf("failed to derive wrap key: %w", err)
	}

	// 5. Encrypt with XChaCha20-Poly1305
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aead, err := chacha20poly1305.NewX(wk)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	ct := aead.Seal(nil, nonce, newGroupKey, nil)

	// 6. CBOR encode the wrapped blob
	type wrappedBlob struct {
		EKPK  []byte `cbor:"ek_pk"`
		Nonce []byte `cbor:"nonce"`
		CT    []byte `cbor:"ct"`
	}
	blob := wrappedBlob{EKPK: ekPK, Nonce: nonce, CT: ct}

	// Use fxamacker/cbor directly for canonical encoding
	return cborMarshal(blob)
}

// UnwrapKeyForRecipient unwraps a group key from a wrapped blob using the recipient's Ed25519 private key.
func (s *QSP1Suite) UnwrapKeyForRecipient(wrappedData []byte, recipientEd25519SK ed25519.PrivateKey, recipientKID [16]byte, convID []byte) ([]byte, error) {
	// Decode CBOR blob
	type wrappedBlob struct {
		EKPK  []byte `cbor:"ek_pk"`
		Nonce []byte `cbor:"nonce"`
		CT    []byte `cbor:"ct"`
	}
	var blob wrappedBlob
	if err := cborUnmarshal(wrappedData, &blob); err != nil {
		return nil, fmt.Errorf("failed to decode wrapped blob: %w", err)
	}

	if len(blob.EKPK) != 32 || len(blob.Nonce) != 24 {
		return nil, fmt.Errorf("invalid wrapped blob dimensions")
	}

	// 1. Convert recipient Ed25519 private key to X25519
	recipientX25519SK, err := Ed25519PrivateKeyToX25519(recipientEd25519SK)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient private key: %w", err)
	}

	// 2. Compute shared secret with ephemeral public key
	ss, err := X25519SharedSecret(recipientX25519SK, blob.EKPK)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// 3. Derive wrap key
	prkWrap := hkdf.Extract(sha256.New, ss, convID)
	wrapInfo := append([]byte(InfoWrapv11), recipientKID[:]...)
	wk := make([]byte, 32)
	wkReader := hkdf.Expand(sha256.New, prkWrap, wrapInfo)
	if _, err := wkReader.Read(wk); err != nil {
		return nil, fmt.Errorf("failed to derive wrap key: %w", err)
	}

	// 4. Decrypt
	aead, err := chacha20poly1305.NewX(wk)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	plaintext, err := aead.Open(nil, blob.Nonce, blob.CT, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return plaintext, nil
}

// GenerateGroupKey generates a random 32-byte group key for a new epoch.
func (s *QSP1Suite) GenerateGroupKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate group key: %w", err)
	}
	return key, nil
}