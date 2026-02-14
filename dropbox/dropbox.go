package dropbox

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

// StorageProvider defines the interface for drop box storage backends
type StorageProvider interface {
	// Store stores an envelope at the given key
	Store(key string, data []byte) error
	
	// Retrieve retrieves data from the given key
	Retrieve(key string) ([]byte, error)
	
	// List lists all keys with the given prefix, optionally sorted by creation time
	List(prefix string) ([]string, error)
	
	// Delete removes the object at the given key
	Delete(key string) error
	
	// Exists checks if a key exists
	Exists(key string) (bool, error)
}

// Manager handles drop box operations
type Manager struct {
	storage    StorageProvider
	messageMgr *message.Manager
}

// NewManager creates a new drop box manager
func NewManager(storage StorageProvider) *Manager {
	return &Manager{
		storage:    storage,
		messageMgr: message.NewManager(),
	}
}

// SendMessage stores a message envelope in the drop box
func (m *Manager) SendMessage(envelope *types.OuterEnvelope) error {
	if err := m.messageMgr.ValidateEnvelope(envelope); err != nil {
		return fmt.Errorf("invalid envelope: %w", err)
	}
	
	// Serialize the envelope
	data, err := m.messageMgr.SerializeEnvelope(envelope)
	if err != nil {
		return fmt.Errorf("failed to serialize envelope: %w", err)
	}
	
	// Generate storage key
	key := m.GenerateStorageKey(envelope)
	
	// Store in drop box
	if err := m.storage.Store(key, data); err != nil {
		return fmt.Errorf("failed to store envelope: %w", err)
	}
	
	return nil
}

// ReceiveMessages retrieves and decrypts messages from the drop box
func (m *Manager) ReceiveMessages(
	conversation *types.Conversation,
	seenMessageIDs map[types.MessageID]bool,
) ([]*types.Message, error) {
	// List messages for this conversation
	prefix := m.GenerateConversationPrefix(conversation.ID)
	keys, err := m.storage.List(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}
	
	var messages []*types.Message
	var messagesToDelete []string
	
	for _, key := range keys {
		// Skip if we've already seen this message
		msgID, err := m.ExtractMessageIDFromKey(key)
		if err != nil {
			// Skip malformed keys
			continue
		}
		
		if seenMessageIDs[msgID] {
			continue
		}
		
		// Retrieve the envelope
		data, err := m.storage.Retrieve(key)
		if err != nil {
			// Skip messages we can't retrieve
			continue
		}
		
		// Deserialize envelope
		envelope, err := m.messageMgr.DeserializeEnvelope(data)
		if err != nil {
			// Skip malformed envelopes
			continue
		}
		
		// Check if message has expired
		if m.messageMgr.CheckExpiry(envelope) {
			// Mark for deletion
			messagesToDelete = append(messagesToDelete, key)
			continue
		}
		
		// Try to decrypt the message
		msg, err := m.messageMgr.DecryptMessage(envelope, conversation)
		if err != nil {
			// Skip messages we can't decrypt (wrong conversation, invalid signature, etc.)
			continue
		}
		
		// Mark as seen
		seenMessageIDs[msgID] = true
		messages = append(messages, msg)
		
		// Mark for deletion (ephemeral storage)
		messagesToDelete = append(messagesToDelete, key)
	}
	
	// Delete processed/expired messages
	for _, key := range messagesToDelete {
		_ = m.storage.Delete(key) // Best effort deletion
	}
	
	// Sort messages by creation timestamp
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Envelope.CreatedTS < messages[j].Envelope.CreatedTS
	})
	
	return messages, nil
}

// SendACK sends an acknowledgment message for a received message
func (m *Manager) SendACK(
	senderIdentity *types.Identity,
	conversation *types.Conversation,
	ackedMsgID types.MessageID,
	status string,
) error {
	// TODO: Implement proper ACK serialization
	// For now, just create a simple ACK message
	ackText := fmt.Sprintf("ack:%s:%s", hex.EncodeToString(ackedMsgID[:]), status)
	
	// Create ACK message
	envelope, err := m.messageMgr.CreateMessage(
		senderIdentity,
		conversation,
		"ack",
		[]byte(ackText),
		nil,
		300, // 5 minute TTL for ACKs
	)
	if err != nil {
		return fmt.Errorf("failed to create ACK message: %w", err)
	}
	
	// Send the ACK
	return m.SendMessage(envelope)
}

// GenerateStorageKey generates a storage key for a message envelope
func (m *Manager) GenerateStorageKey(envelope *types.OuterEnvelope) string {
	// Format: /{conv_id_hex}/msg/{created_ts}/{msg_id_hex}.cbor
	convIDHex := hex.EncodeToString(envelope.ConvID[:])
	msgIDHex := hex.EncodeToString(envelope.MsgID[:])
	
	return fmt.Sprintf("/%s/msg/%d/%s.cbor", convIDHex, envelope.CreatedTS, msgIDHex)
}

// GenerateConversationPrefix generates a prefix for listing conversation messages
func (m *Manager) GenerateConversationPrefix(convID types.ConversationID) string {
	convIDHex := hex.EncodeToString(convID[:])
	return fmt.Sprintf("/%s/msg/", convIDHex)
}

// ExtractMessageIDFromKey extracts the message ID from a storage key
func (m *Manager) ExtractMessageIDFromKey(key string) (types.MessageID, error) {
	// Expected format: /{conv_id_hex}/msg/{created_ts}/{msg_id_hex}.cbor
	parts := strings.Split(key, "/")
	if len(parts) < 4 {
		return types.MessageID{}, fmt.Errorf("invalid key format")
	}
	
	// Last part should be {msg_id_hex}.cbor
	filename := parts[len(parts)-1]
	if !strings.HasSuffix(filename, ".cbor") {
		return types.MessageID{}, fmt.Errorf("invalid file extension")
	}
	
	// Extract hex part
	msgIDHex := strings.TrimSuffix(filename, ".cbor")
	msgIDBytes, err := hex.DecodeString(msgIDHex)
	if err != nil {
		return types.MessageID{}, fmt.Errorf("invalid message ID hex: %w", err)
	}
	
	if len(msgIDBytes) != 16 {
		return types.MessageID{}, fmt.Errorf("invalid message ID length: %d", len(msgIDBytes))
	}
	
	var msgID types.MessageID
	copy(msgID[:], msgIDBytes)
	return msgID, nil
}

// CleanupExpiredMessages removes expired messages from the drop box
func (m *Manager) CleanupExpiredMessages(convID types.ConversationID) error {
	prefix := m.GenerateConversationPrefix(convID)
	keys, err := m.storage.List(prefix)
	if err != nil {
		return fmt.Errorf("failed to list messages for cleanup: %w", err)
	}
	
	now := time.Now().Unix()
	var expiredKeys []string
	
	for _, key := range keys {
		// Try to retrieve and check expiry
		data, err := m.storage.Retrieve(key)
		if err != nil {
			continue
		}
		
		envelope, err := m.messageMgr.DeserializeEnvelope(data)
		if err != nil {
			// Delete malformed envelopes too
			expiredKeys = append(expiredKeys, key)
			continue
		}
		
		if envelope.ExpiryTS < now {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	// Delete expired messages
	for _, key := range expiredKeys {
		_ = m.storage.Delete(key) // Best effort
	}
	
	return nil
}

// GetStorageStats returns statistics about storage usage for a conversation
func (m *Manager) GetStorageStats(convID types.ConversationID) (*StorageStats, error) {
	prefix := m.GenerateConversationPrefix(convID)
	keys, err := m.storage.List(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}
	
	stats := &StorageStats{
		ConversationID: convID,
		MessageCount:   len(keys),
	}
	
	now := time.Now().Unix()
	
	for _, key := range keys {
		data, err := m.storage.Retrieve(key)
		if err != nil {
			continue
		}
		
		stats.TotalSize += len(data)
		
		envelope, err := m.messageMgr.DeserializeEnvelope(data)
		if err != nil {
			continue
		}
		
		if envelope.ExpiryTS < now {
			stats.ExpiredCount++
		}
		
		if envelope.CreatedTS < stats.OldestTimestamp || stats.OldestTimestamp == 0 {
			stats.OldestTimestamp = envelope.CreatedTS
		}
		
		if envelope.CreatedTS > stats.NewestTimestamp {
			stats.NewestTimestamp = envelope.CreatedTS
		}
	}
	
	return stats, nil
}

// StorageStats represents statistics about drop box storage
type StorageStats struct {
	ConversationID   types.ConversationID `json:"conversation_id"`
	MessageCount     int                  `json:"message_count"`
	ExpiredCount     int                  `json:"expired_count"`
	TotalSize        int                  `json:"total_size"`
	OldestTimestamp  int64                `json:"oldest_timestamp"`
	NewestTimestamp  int64                `json:"newest_timestamp"`
}

// MemoryStorageProvider provides an in-memory implementation for testing
type MemoryStorageProvider struct {
	data map[string][]byte
}

// NewMemoryStorageProvider creates a new in-memory storage provider
func NewMemoryStorageProvider() *MemoryStorageProvider {
	return &MemoryStorageProvider{
		data: make(map[string][]byte),
	}
}

// Store implements StorageProvider
func (m *MemoryStorageProvider) Store(key string, data []byte) error {
	m.data[key] = make([]byte, len(data))
	copy(m.data[key], data)
	return nil
}

// Retrieve implements StorageProvider
func (m *MemoryStorageProvider) Retrieve(key string) ([]byte, error) {
	data, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// List implements StorageProvider
func (m *MemoryStorageProvider) List(prefix string) ([]string, error) {
	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	
	// Sort keys for consistent ordering
	sort.Strings(keys)
	return keys, nil
}

// Delete implements StorageProvider
func (m *MemoryStorageProvider) Delete(key string) error {
	delete(m.data, key)
	return nil
}

// Exists implements StorageProvider
func (m *MemoryStorageProvider) Exists(key string) (bool, error) {
	_, exists := m.data[key]
	return exists, nil
}

// Clear removes all data (for testing)
func (m *MemoryStorageProvider) Clear() {
	m.data = make(map[string][]byte)
}