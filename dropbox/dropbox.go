package dropbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
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
	idMgr      *identity.Manager
}

// NewManager creates a new drop box manager
func NewManager(storage StorageProvider) *Manager {
	return &Manager{
		storage:    storage,
		messageMgr: message.NewManager(),
		idMgr:      identity.NewManager(),
	}
}

const ackProto = "qntm-ack-v1"

type messageACK struct {
	Proto    string               `cbor:"proto"`
	ConvID   types.ConversationID `cbor:"conv_id"`
	MsgID    types.MessageID      `cbor:"msg_id"`
	AckerKID types.KeyID          `cbor:"acker_kid"`
	AckerPK  []byte               `cbor:"acker_ik_pk"`
	AckTS    int64                `cbor:"ack_ts"`
	Sig      []byte               `cbor:"sig"`
}

type ackSignable struct {
	Proto    string               `cbor:"proto"`
	ConvID   types.ConversationID `cbor:"conv_id"`
	MsgID    types.MessageID      `cbor:"msg_id"`
	AckerKID types.KeyID          `cbor:"acker_kid"`
	AckTS    int64                `cbor:"ack_ts"`
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
	receiverIdentity *types.Identity,
	conversation *types.Conversation,
	seenMessageIDs map[types.MessageID]bool,
) ([]*types.Message, error) {
	if receiverIdentity == nil {
		return nil, fmt.Errorf("receiver identity is required")
	}

	// List messages for this conversation
	prefix := m.GenerateConversationPrefix(conversation.ID)
	keys, err := m.storage.List(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	var messages []*types.Message

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

		// Relay-managed receipt recording (HTTP provider); ignore failures so
		// message delivery is not blocked by transient receipt issues.
		if recorder, ok := m.storage.(interface {
			RecordReadReceipt(*types.Identity, *types.Conversation, types.MessageID) error
		}); ok {
			_ = recorder.RecordReadReceipt(receiverIdentity, conversation, msgID)
		}
	}

	// Sort messages by creation timestamp
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Envelope.CreatedTS < messages[j].Envelope.CreatedTS
	})

	return messages, nil
}

func (m *Manager) ensureACK(identity *types.Identity, convID types.ConversationID, msgID types.MessageID) error {
	ackKey := m.GenerateACKKey(convID, msgID, identity.KeyID)
	exists, err := m.storage.Exists(ackKey)
	if err == nil && exists {
		return nil
	}

	ackTS := time.Now().Unix()
	signable := ackSignable{
		Proto:    ackProto,
		ConvID:   convID,
		MsgID:    msgID,
		AckerKID: identity.KeyID,
		AckTS:    ackTS,
	}

	signableBytes, err := cbor.MarshalCanonical(signable)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(signableBytes)
	signature := ed25519.Sign(identity.PrivateKey, digest[:])

	ack := messageACK{
		Proto:    ackProto,
		ConvID:   convID,
		MsgID:    msgID,
		AckerKID: identity.KeyID,
		AckerPK:  []byte(identity.PublicKey),
		AckTS:    ackTS,
		Sig:      signature,
	}

	ackBytes, err := cbor.MarshalCanonical(ack)
	if err != nil {
		return err
	}

	return m.storage.Store(ackKey, ackBytes)
}

func (m *Manager) cleanupIfACKed(conversation *types.Conversation, messageKey string, msgID types.MessageID) error {
	hasAll, err := m.hasAllValidACKs(conversation, msgID)
	if err != nil {
		return err
	}

	if !hasAll {
		return nil
	}

	return m.deleteMessageWithACKs(messageKey, conversation.ID, msgID)
}

func (m *Manager) hasAllValidACKs(conversation *types.Conversation, msgID types.MessageID) (bool, error) {
	required := make(map[types.KeyID]bool, len(conversation.Participants))
	for _, participant := range conversation.Participants {
		required[participant] = true
	}

	// Conversation participant sets can be temporarily incomplete (for example,
	// when the inviter self-accepts before peers join). Never auto-delete a
	// message in that state, or a local self-ACK can wipe undelivered messages.
	if len(required) < 2 {
		return false, nil
	}

	ackPrefix := m.GenerateACKPrefix(conversation.ID, msgID)
	ackKeys, err := m.storage.List(ackPrefix)
	if err != nil {
		return false, err
	}

	validACKers := make(map[types.KeyID]bool, len(required))
	for _, ackKey := range ackKeys {
		data, err := m.storage.Retrieve(ackKey)
		if err != nil {
			continue
		}

		var ack messageACK
		if err := cbor.UnmarshalCanonical(data, &ack); err != nil {
			continue
		}

		if ack.Proto != ackProto {
			continue
		}
		if ack.ConvID != conversation.ID || ack.MsgID != msgID {
			continue
		}
		if !required[ack.AckerKID] {
			continue
		}
		if !m.idMgr.VerifyKeyID(ed25519.PublicKey(ack.AckerPK), ack.AckerKID) {
			continue
		}

		signable := ackSignable{
			Proto:    ack.Proto,
			ConvID:   ack.ConvID,
			MsgID:    ack.MsgID,
			AckerKID: ack.AckerKID,
			AckTS:    ack.AckTS,
		}
		signableBytes, err := cbor.MarshalCanonical(signable)
		if err != nil {
			continue
		}
		digest := sha256.Sum256(signableBytes)
		if !ed25519.Verify(ed25519.PublicKey(ack.AckerPK), digest[:], ack.Sig) {
			continue
		}

		validACKers[ack.AckerKID] = true
	}

	return len(validACKers) >= len(required), nil
}

func (m *Manager) deleteMessageWithACKs(messageKey string, convID types.ConversationID, msgID types.MessageID) error {
	_ = m.storage.Delete(messageKey)

	ackPrefix := m.GenerateACKPrefix(convID, msgID)
	ackKeys, err := m.storage.List(ackPrefix)
	if err != nil {
		return nil
	}

	for _, ackKey := range ackKeys {
		_ = m.storage.Delete(ackKey)
	}

	return nil
}

// SendACK sends an acknowledgment message for a received message
func (m *Manager) SendACK(
	senderIdentity *types.Identity,
	conversation *types.Conversation,
	ackedMsgID types.MessageID,
	status string,
) error {
	_ = senderIdentity
	_ = conversation
	_ = ackedMsgID
	_ = status
	return fmt.Errorf("client ACK messages are disabled; use relay-managed read receipts")
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

// GenerateACKPrefix generates a prefix for message ACKs.
func (m *Manager) GenerateACKPrefix(convID types.ConversationID, msgID types.MessageID) string {
	convIDHex := hex.EncodeToString(convID[:])
	msgIDHex := hex.EncodeToString(msgID[:])
	return fmt.Sprintf("/%s/ack/%s/", convIDHex, msgIDHex)
}

// GenerateACKKey generates a unique key for an ACK record.
func (m *Manager) GenerateACKKey(convID types.ConversationID, msgID types.MessageID, ackerKID types.KeyID) string {
	ackPrefix := m.GenerateACKPrefix(convID, msgID)
	ackerKIDHex := hex.EncodeToString(ackerKID[:])
	return ackPrefix + ackerKIDHex + ".cbor"
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
	type expiredMessage struct {
		key   string
		msgID types.MessageID
	}
	var expired []expiredMessage

	for _, key := range keys {
		msgID, msgIDErr := m.ExtractMessageIDFromKey(key)

		// Try to retrieve and check expiry
		data, err := m.storage.Retrieve(key)
		if err != nil {
			continue
		}

		envelope, err := m.messageMgr.DeserializeEnvelope(data)
		if err != nil {
			// Delete malformed envelopes too
			if msgIDErr == nil {
				expired = append(expired, expiredMessage{key: key, msgID: msgID})
			} else {
				_ = m.storage.Delete(key)
			}
			continue
		}

		if envelope.ExpiryTS < now {
			if msgIDErr == nil {
				expired = append(expired, expiredMessage{key: key, msgID: msgID})
			} else {
				_ = m.storage.Delete(key)
			}
		}
	}

	// Delete expired messages
	for _, item := range expired {
		_ = m.deleteMessageWithACKs(item.key, convID, item.msgID) // Best effort
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

// CountUnreadMessages returns the number of currently stored unread messages
// for a conversation, based on the caller's seen-message map.
func (m *Manager) CountUnreadMessages(
	convID types.ConversationID,
	seenMessageIDs map[types.MessageID]bool,
) (int, error) {
	if seenMessageIDs == nil {
		seenMessageIDs = map[types.MessageID]bool{}
	}

	prefix := m.GenerateConversationPrefix(convID)
	keys, err := m.storage.List(prefix)
	if err != nil {
		return 0, fmt.Errorf("failed to list messages: %w", err)
	}

	unread := 0
	for _, key := range keys {
		msgID, err := m.ExtractMessageIDFromKey(key)
		if err != nil {
			continue
		}

		data, err := m.storage.Retrieve(key)
		if err != nil {
			continue
		}

		envelope, err := m.messageMgr.DeserializeEnvelope(data)
		if err != nil {
			continue
		}

		if m.messageMgr.CheckExpiry(envelope) {
			continue
		}

		if !seenMessageIDs[msgID] {
			unread++
		}
	}

	return unread, nil
}

// StorageStats represents statistics about drop box storage
type StorageStats struct {
	ConversationID  types.ConversationID `json:"conversation_id"`
	MessageCount    int                  `json:"message_count"`
	ExpiredCount    int                  `json:"expired_count"`
	TotalSize       int                  `json:"total_size"`
	OldestTimestamp int64                `json:"oldest_timestamp"`
	NewestTimestamp int64                `json:"newest_timestamp"`
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
