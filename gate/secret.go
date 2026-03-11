package gate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	qcrypto "github.com/corpo/qntm/crypto"
	"golang.org/x/crypto/nacl/box"
)

// SecretPayload is the body of a gate.secret message.
type SecretPayload struct {
	SecretID       string `json:"secret_id"`
	Service        string `json:"service"`
	HeaderName     string `json:"header_name"`
	HeaderTemplate string `json:"header_template"` // e.g. "Bearer {value}"
	EncryptedBlob  string `json:"encrypted_blob"`  // base64-encoded NaCl box ciphertext
	SenderKID      string `json:"sender_kid"`
}

// SealSecret encrypts a secret value to the gateway's public key using NaCl box
// (X25519-XSalsa20-Poly1305). Ed25519 keys are converted to X25519 for DH.
func SealSecret(senderPrivKey ed25519.PrivateKey, gatewayPubKey ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	// Convert Ed25519 keys to X25519
	senderX25519, err := qcrypto.Ed25519PrivateKeyToX25519(senderPrivKey)
	if err != nil {
		return nil, fmt.Errorf("convert sender private key to X25519: %w", err)
	}

	gatewayX25519, err := qcrypto.Ed25519PublicKeyToX25519(gatewayPubKey)
	if err != nil {
		return nil, fmt.Errorf("convert gateway public key to X25519: %w", err)
	}

	// Generate random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Convert to fixed-size arrays for nacl/box
	var recipientPub [32]byte
	var senderPriv [32]byte
	copy(recipientPub[:], gatewayX25519)
	copy(senderPriv[:], senderX25519)

	// Seal: nonce || box.Seal(plaintext)
	sealed := box.Seal(nonce[:], plaintext, &nonce, &recipientPub, &senderPriv)
	return sealed, nil
}

// OpenSecret decrypts a secret sealed by SealSecret using the gateway's private
// key and the sender's public key.
func OpenSecret(gatewayPrivKey ed25519.PrivateKey, senderPubKey ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24+box.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Convert Ed25519 keys to X25519
	gatewayX25519, err := qcrypto.Ed25519PrivateKeyToX25519(gatewayPrivKey)
	if err != nil {
		return nil, fmt.Errorf("convert gateway private key to X25519: %w", err)
	}

	senderX25519, err := qcrypto.Ed25519PublicKeyToX25519(senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("convert sender public key to X25519: %w", err)
	}

	// Extract nonce (first 24 bytes)
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	var senderPub [32]byte
	var recipientPriv [32]byte
	copy(senderPub[:], senderX25519)
	copy(recipientPriv[:], gatewayX25519)

	// Open
	plaintext, ok := box.Open(nil, ciphertext[24:], &nonce, &senderPub, &recipientPriv)
	if !ok {
		return nil, fmt.Errorf("decryption failed (authentication error)")
	}
	return plaintext, nil
}

// BuildSecretPayload constructs a SecretPayload with the secret value encrypted
// to the gateway's public key.
func BuildSecretPayload(
	senderPrivKey ed25519.PrivateKey,
	senderPubKey ed25519.PublicKey,
	gatewayPubKey ed25519.PublicKey,
	secretID, service, headerName, headerTemplate, secretValue string,
) (*SecretPayload, error) {
	sealed, err := SealSecret(senderPrivKey, gatewayPubKey, []byte(secretValue))
	if err != nil {
		return nil, fmt.Errorf("seal secret: %w", err)
	}

	return &SecretPayload{
		SecretID:       secretID,
		Service:        service,
		HeaderName:     headerName,
		HeaderTemplate: headerTemplate,
		EncryptedBlob:  base64.RawURLEncoding.EncodeToString(sealed),
		SenderKID:      KIDFromPublicKey(senderPubKey),
	}, nil
}

// ParseSecretPayload parses and decrypts a gate.secret message body.
func ParseSecretPayload(
	gatewayPrivKey ed25519.PrivateKey,
	senderPubKey ed25519.PublicKey,
	body json.RawMessage,
) (*SecretPayload, string, error) {
	var payload SecretPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", fmt.Errorf("unmarshal secret payload: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(payload.EncryptedBlob)
	if err != nil {
		// Try standard base64
		ciphertext, err = base64.StdEncoding.DecodeString(payload.EncryptedBlob)
		if err != nil {
			return nil, "", fmt.Errorf("decode encrypted blob: %w", err)
		}
	}

	plaintext, err := OpenSecret(gatewayPrivKey, senderPubKey, ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt secret: %w", err)
	}

	return &payload, string(plaintext), nil
}
