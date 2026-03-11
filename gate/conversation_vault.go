package gate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// ConversationVault stores per-conversation credentials on disk, encrypted with
// AES-256-GCM. The vault key is derived from GATE_VAULT_KEY or auto-generated.
type ConversationVault struct {
	BasePath string
	gcm      cipher.AEAD
	mu       sync.RWMutex
}

// StoredSecret is a decrypted credential from the vault.
type StoredSecret struct {
	SecretID       string `json:"secret_id"`
	Service        string `json:"service"`
	HeaderName     string `json:"header_name"`
	HeaderTemplate string `json:"header_template"`
	Value          string `json:"value"`
}

// conversationVaultFile is the on-disk format for a conversation's secrets.
type conversationVaultFile struct {
	Secrets map[string]*storedSecretEncrypted `json:"secrets"` // keyed by service
}

type storedSecretEncrypted struct {
	SecretID       string `json:"secret_id"`
	Service        string `json:"service"`
	HeaderName     string `json:"header_name"`
	HeaderTemplate string `json:"header_template"`
	EncryptedValue string `json:"encrypted_value"` // base64 nonce+ciphertext via EnvVault format
}

// NewConversationVault creates a vault at the given base path. If vaultKeyBytes
// is nil, the vault attempts to load a key from GATE_VAULT_KEY env var. If that
// is also unset, it generates and persists a key at basePath/vault.key.
func NewConversationVault(basePath string, vaultKeyBytes []byte) (*ConversationVault, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	key, err := resolveVaultKey(basePath, vaultKeyBytes)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	return &ConversationVault{
		BasePath: basePath,
		gcm:      gcm,
	}, nil
}

func resolveVaultKey(basePath string, explicit []byte) ([]byte, error) {
	if len(explicit) == 32 {
		return explicit, nil
	}

	// Try env var
	if envKey := os.Getenv("GATE_VAULT_KEY"); envKey != "" {
		h := sha256.Sum256([]byte(envKey))
		return h[:], nil
	}

	// Auto-generate and persist
	keyPath := filepath.Join(basePath, "vault.key")
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate vault key: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("persist vault key: %w", err)
	}
	return key, nil
}

// Store encrypts and persists a credential for a conversation+service.
func (v *ConversationVault) Store(convID, secretID, service, headerName, headerTemplate, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	vaultFile := v.loadFile(convID)

	// Encrypt the value
	encValue, err := v.encrypt(value)
	if err != nil {
		return fmt.Errorf("encrypt secret value: %w", err)
	}

	vaultFile.Secrets[service] = &storedSecretEncrypted{
		SecretID:       secretID,
		Service:        service,
		HeaderName:     headerName,
		HeaderTemplate: headerTemplate,
		EncryptedValue: encValue,
	}

	return v.saveFile(convID, vaultFile)
}

// Get retrieves and decrypts a credential for a conversation+service.
func (v *ConversationVault) Get(convID, service string) (*StoredSecret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	vaultFile := v.loadFile(convID)

	enc, ok := vaultFile.Secrets[service]
	if !ok {
		return nil, fmt.Errorf("no secret for service %q in conversation %s", service, convID)
	}

	decrypted, err := v.decrypt(enc.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	return &StoredSecret{
		SecretID:       enc.SecretID,
		Service:        enc.Service,
		HeaderName:     enc.HeaderName,
		HeaderTemplate: enc.HeaderTemplate,
		Value:          decrypted,
	}, nil
}

func (v *ConversationVault) convFilePath(convID string) string {
	return filepath.Join(v.BasePath, convID+".vault.json")
}

func (v *ConversationVault) loadFile(convID string) *conversationVaultFile {
	p := v.convFilePath(convID)
	data, err := os.ReadFile(p)
	if err != nil {
		return &conversationVaultFile{Secrets: make(map[string]*storedSecretEncrypted)}
	}
	var vf conversationVaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return &conversationVaultFile{Secrets: make(map[string]*storedSecretEncrypted)}
	}
	if vf.Secrets == nil {
		vf.Secrets = make(map[string]*storedSecretEncrypted)
	}
	return &vf
}

func (v *ConversationVault) saveFile(convID string, vf *conversationVaultFile) error {
	data, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vault file: %w", err)
	}
	return os.WriteFile(v.convFilePath(convID), data, 0600)
}

func (v *ConversationVault) encrypt(plaintext string) (string, error) {
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := v.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return vaultPrefix + encodeBase64Std(ciphertext), nil
}

func (v *ConversationVault) decrypt(stored string) (string, error) {
	if len(stored) <= len(vaultPrefix) {
		return stored, nil
	}
	raw := stored[len(vaultPrefix):]
	data, err := decodeBase64Std(raw)
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

func encodeBase64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64Std(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
