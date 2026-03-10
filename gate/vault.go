package gate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// VaultProvider abstracts credential encryption at rest.
// Implementations can range from a simple AES-GCM envelope (EnvVault)
// to full HashiCorp Vault or cloud KMS integration.
type VaultProvider interface {
	// Encrypt encrypts a plaintext credential value for storage.
	Encrypt(plaintext string) (string, error)

	// Decrypt decrypts a stored credential value.
	Decrypt(ciphertext string) (string, error)
}

// NoopVault stores credentials as plaintext. Used for testing and dev.
type NoopVault struct{}

func (NoopVault) Encrypt(plaintext string) (string, error) { return plaintext, nil }
func (NoopVault) Decrypt(ciphertext string) (string, error) { return ciphertext, nil }

// EnvVault encrypts credentials using AES-256-GCM with a master key from
// the environment. The master key must be exactly 32 bytes (passed as raw bytes
// or base64-encoded via GATE_VAULT_KEY).
//
// Stored format: "vault:v1:" + base64(nonce + ciphertext)
type EnvVault struct {
	gcm cipher.AEAD
}

const vaultPrefix = "vault:v1:"

// NewEnvVault creates a vault from a 32-byte master key.
func NewEnvVault(masterKey []byte) (*EnvVault, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("vault master key must be 32 bytes, got %d", len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &EnvVault{gcm: gcm}, nil
}

// NewEnvVaultFromBase64 creates a vault from a base64-encoded master key.
func NewEnvVaultFromBase64(encoded string) (*EnvVault, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode vault key: %w", err)
	}
	return NewEnvVault(key)
}

func (v *EnvVault) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := v.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return vaultPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (v *EnvVault) Decrypt(stored string) (string, error) {
	if !strings.HasPrefix(stored, vaultPrefix) {
		// Not encrypted — return as-is for migration compatibility.
		return stored, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, vaultPrefix))
	if err != nil {
		return "", fmt.Errorf("decode vault ciphertext: %w", err)
	}
	nonceSize := v.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("vault ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := v.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt vault ciphertext: %w", err)
	}
	return string(plaintext), nil
}
