package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/corpo/qntm/pkg/types"
)

type chatArchiveEntry struct {
	MessageID    string `json:"msg_id"`
	Direction    string `json:"direction"`
	SenderKIDHex string `json:"sender_kid_hex,omitempty"`
	BodyType     string `json:"body_type"`
	Body         string `json:"body"`
	BodyEncoding string `json:"body_encoding"`
	CreatedTS    int64  `json:"created_ts"`
}

type encryptedChatArchive struct {
	NonceB64      string `json:"nonce"`
	CiphertextB64 string `json:"ciphertext"`
}

func chatArchiveDir() string {
	return filepath.Join(configDir, "chats")
}

func chatArchivePath(convID types.ConversationID) string {
	convIDHex := hex.EncodeToString(convID[:])
	return filepath.Join(chatArchiveDir(), convIDHex+".json.enc")
}

func deriveChatArchiveKey(conversation *types.Conversation) [32]byte {
	const context = "qntm-chat-archive-v1"
	buf := make([]byte, 0, len(context)+len(conversation.Keys.Root))
	buf = append(buf, []byte(context)...)
	buf = append(buf, conversation.Keys.Root...)
	return sha256.Sum256(buf)
}

func encodeChatBody(body []byte) (string, string) {
	if utf8.Valid(body) {
		return string(body), "utf8"
	}
	return base64.RawStdEncoding.EncodeToString(body), "base64"
}

func decodeChatBody(entry chatArchiveEntry) string {
	if entry.BodyEncoding == "base64" {
		return fmt.Sprintf("<base64:%s>", entry.Body)
	}
	return entry.Body
}

func loadChatArchive(conversation *types.Conversation) ([]chatArchiveEntry, error) {
	path := chatArchivePath(conversation.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []chatArchiveEntry{}, nil
		}
		return nil, err
	}

	var blob encryptedChatArchive
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("failed to decode chat archive envelope: %w", err)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(blob.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chat archive nonce: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.CiphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chat archive ciphertext: %w", err)
	}

	key := deriveChatArchiveKey(conversation)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to init chat archive cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init chat archive AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, conversation.ID[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt chat archive: %w", err)
	}

	var entries []chatArchiveEntry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("failed to decode chat archive payload: %w", err)
	}

	return entries, nil
}

func saveChatArchive(conversation *types.Conversation, entries []chatArchiveEntry) error {
	if err := os.MkdirAll(chatArchiveDir(), 0700); err != nil {
		return fmt.Errorf("failed to create chat archive dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedTS != entries[j].CreatedTS {
			return entries[i].CreatedTS < entries[j].CreatedTS
		}
		return entries[i].MessageID < entries[j].MessageID
	})

	plaintext, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("failed to encode chat archive payload: %w", err)
	}

	key := deriveChatArchiveKey(conversation)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to init chat archive cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to init chat archive AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate chat archive nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, conversation.ID[:])

	blob := encryptedChatArchive{
		NonceB64:      base64.RawStdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.RawStdEncoding.EncodeToString(ciphertext),
	}

	encoded, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("failed to encode chat archive envelope: %w", err)
	}

	return os.WriteFile(chatArchivePath(conversation.ID), encoded, 0600)
}

func appendChatArchiveEntry(conversation *types.Conversation, entry chatArchiveEntry) error {
	entries, err := loadChatArchive(conversation)
	if err != nil {
		return err
	}

	for _, existing := range entries {
		if existing.MessageID == entry.MessageID && existing.Direction == entry.Direction {
			return nil
		}
	}

	entries = append(entries, entry)
	return saveChatArchive(conversation, entries)
}
