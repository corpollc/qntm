package dropbox

import (
	"strings"
	"testing"
	"time"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

func TestManager_SendReceiveMessage(t *testing.T) {
	// Create test setup
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	messageMgr := message.NewManager()

	// Create sender and receiver identities
	senderIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate sender identity: %v", err)
	}

	receiverIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate receiver identity: %v", err)
	}

	// Create conversation
	invite, err := inviteMgr.CreateInvite(senderIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}

	keys, err := inviteMgr.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	conversation, err := inviteMgr.CreateConversation(invite, keys)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Add receiver to conversation
	inviteMgr.AddParticipant(conversation, receiverIdentity.PublicKey)

	// Create and send a message
	envelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("Hello, World!"), nil, messageMgr.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	err = manager.SendMessage(envelope)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Verify message was stored
	key := manager.GenerateStorageKey(envelope)
	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if !exists {
		t.Error("Message was not stored")
	}

	// Receive messages
	seenMessages := make(map[types.MessageID]bool)
	messages, err := manager.ReceiveMessages(receiverIdentity, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	// Verify we received the message
	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}

	receivedMsg := messages[0]
	if string(receivedMsg.Inner.Body) != "Hello, World!" {
		t.Errorf("Message body mismatch: got %s, want Hello, World!", string(receivedMsg.Inner.Body))
	}

	if !receivedMsg.Verified {
		t.Error("Message signature verification failed")
	}

	// Verify message was marked as seen
	if !seenMessages[envelope.MsgID] {
		t.Error("Message was not marked as seen")
	}

	// Client receive should not delete relay-stored messages.
	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Failed to check existence after receive: %v", err)
	}
	if !exists {
		t.Error("Message should remain after receive")
	}

	// Sender receives once too.
	senderSeen := make(map[types.MessageID]bool)
	_, err = manager.ReceiveMessages(senderIdentity, conversation, senderSeen)
	if err != nil {
		t.Fatalf("Sender failed to receive: %v", err)
	}

	// Message should still exist; deletion is relay-managed.
	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Failed to check existence after second receive: %v", err)
	}
	if !exists {
		t.Error("Message should remain; client must not delete relay data")
	}
}

func TestManager_MultipleMessages(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create test setup
	senderIdentity, conversation := createDropBoxTestSetup(t)
	messageMgr := message.NewManager()

	// Send multiple messages
	messageTexts := []string{"First", "Second", "Third"}
	var sentEnvelopes []*types.OuterEnvelope

	for _, text := range messageTexts {
		envelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte(text), nil, messageMgr.DefaultTTL())
		if err != nil {
			t.Fatalf("Failed to create message %s: %v", text, err)
		}

		err = manager.SendMessage(envelope)
		if err != nil {
			t.Fatalf("Failed to send message %s: %v", text, err)
		}

		sentEnvelopes = append(sentEnvelopes, envelope)
	}

	// Receive all messages
	seenMessages := make(map[types.MessageID]bool)
	messages, err := manager.ReceiveMessages(senderIdentity, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	// Verify we received all messages
	if len(messages) != len(messageTexts) {
		t.Fatalf("Expected %d messages, got %d", len(messageTexts), len(messages))
	}

	// Verify all message texts are present (order may vary due to timestamp resolution)
	receivedTexts := make(map[string]bool)
	for _, msg := range messages {
		receivedTexts[string(msg.Inner.Body)] = true
	}

	for _, expectedText := range messageTexts {
		if !receivedTexts[expectedText] {
			t.Errorf("Message with body %s was not received", expectedText)
		}
	}
}

func TestManager_ReplayProtection(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create test setup
	senderIdentity, conversation := createDropBoxTestSetup(t)
	messageMgr := message.NewManager()

	// Send a message
	envelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("Test"), nil, messageMgr.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	err = manager.SendMessage(envelope)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// First receive should work
	seenMessages := make(map[types.MessageID]bool)
	messages, err := manager.ReceiveMessages(senderIdentity, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}

	// Send the same message again (simulate replay attack)
	err = manager.SendMessage(envelope)
	if err != nil {
		t.Fatalf("Failed to send replayed message: %v", err)
	}

	// Second receive should not return the replayed message
	messages2, err := manager.ReceiveMessages(senderIdentity, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages second time: %v", err)
	}

	if len(messages2) != 0 {
		t.Errorf("Expected 0 messages on replay, got %d", len(messages2))
	}
}

func TestManager_ExpiredMessages(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create test setup
	senderIdentity, conversation := createDropBoxTestSetup(t)
	messageMgr := message.NewManager()

	// Send a message with very short TTL (already expired)
	envelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("Expired"), nil, 1)
	// Manually adjust timestamps to make it expired
	envelope.CreatedTS = time.Now().Unix() - 3600 // 1 hour ago
	envelope.ExpiryTS = time.Now().Unix() - 1800  // 30 minutes ago
	if err != nil {
		t.Fatalf("Failed to create expired message: %v", err)
	}

	err = manager.SendMessage(envelope)
	if err != nil {
		t.Fatalf("Failed to send expired message: %v", err)
	}

	// Verify message was stored
	key := manager.GenerateStorageKey(envelope)
	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if !exists {
		t.Error("Expired message was not stored")
	}

	// Try to receive - should not return the expired message
	seenMessages := make(map[types.MessageID]bool)
	messages, err := manager.ReceiveMessages(senderIdentity, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	if len(messages) != 0 {
		t.Errorf("Expected 0 messages (expired), got %d", len(messages))
	}

	// Expired message remains for relay-side cleanup.
	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Failed to check existence after cleanup: %v", err)
	}
	if !exists {
		t.Error("Expired message should remain until relay cleanup")
	}
}

func TestManager_WrongConversation(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create two different conversations
	senderIdentity1, conversation1 := createDropBoxTestSetup(t)
	senderIdentity2, conversation2 := createDropBoxTestSetup(t)

	messageMgr := message.NewManager()

	// Send message to conversation1
	envelope, err := messageMgr.CreateMessage(senderIdentity1, conversation1, "text", []byte("Secret"), nil, messageMgr.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	err = manager.SendMessage(envelope)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Try to receive with conversation2 (should not work)
	seenMessages := make(map[types.MessageID]bool)
	messages, err := manager.ReceiveMessages(senderIdentity2, conversation2, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	// Should not receive any messages (different conversation)
	if len(messages) != 0 {
		t.Errorf("Expected 0 messages (wrong conversation), got %d", len(messages))
	}

	// But receiving with conversation1 should work
	messages, err = manager.ReceiveMessages(senderIdentity1, conversation1, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages with correct conversation: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message with correct conversation, got %d", len(messages))
	}
}

func TestManager_StorageKeyGeneration(t *testing.T) {
	manager := NewManager(NewMemoryStorageProvider())

	// Create test envelope
	envelope := &types.OuterEnvelope{
		ConvID:    types.ConversationID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		MsgID:     types.MessageID{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xa0},
		CreatedTS: 1234567890,
	}

	// Generate key
	key := manager.GenerateStorageKey(envelope)

	// Verify key format
	expectedPrefix := "/0102030405060708090a0b0c0d0e0f10/msg/"
	if !strings.HasPrefix(key, expectedPrefix) {
		t.Errorf("Key should start with %s, got %s", expectedPrefix, key)
	}

	if !strings.HasSuffix(key, ".cbor") {
		t.Errorf("Key should end with .cbor, got %s", key)
	}

	if !strings.Contains(key, "1234567890") {
		t.Errorf("Key should contain timestamp, got %s", key)
	}

	// Test message ID extraction
	extractedMsgID, err := manager.ExtractMessageIDFromKey(key)
	if err != nil {
		t.Fatalf("Failed to extract message ID: %v", err)
	}

	if extractedMsgID != envelope.MsgID {
		t.Error("Extracted message ID does not match original")
	}
}

func TestManager_StorageStats(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create test setup
	senderIdentity, conversation := createDropBoxTestSetup(t)
	messageMgr := message.NewManager()

	// Initially should have no messages
	stats, err := manager.GetStorageStats(conversation.ID)
	if err != nil {
		t.Fatalf("Failed to get initial stats: %v", err)
	}

	if stats.MessageCount != 0 {
		t.Errorf("Expected 0 initial messages, got %d", stats.MessageCount)
	}

	// Send some messages with explicit timestamps
	baseTime := time.Now().Unix()
	for i := 0; i < 3; i++ {
		envelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("test"), nil, messageMgr.DefaultTTL())
		if err != nil {
			t.Fatalf("Failed to create message %d: %v", i, err)
		}

		// Override timestamps to ensure they're different
		envelope.CreatedTS = baseTime + int64(i*10)
		envelope.ExpiryTS = baseTime + int64(i*10) + messageMgr.DefaultTTL()

		err = manager.SendMessage(envelope)
		if err != nil {
			t.Fatalf("Failed to send message %d: %v", i, err)
		}
	}

	// Check stats
	stats, err = manager.GetStorageStats(conversation.ID)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if stats.MessageCount != 3 {
		t.Errorf("Expected 3 messages, got %d", stats.MessageCount)
	}

	if stats.TotalSize == 0 {
		t.Error("Total size should be greater than 0")
	}

	if stats.NewestTimestamp <= stats.OldestTimestamp {
		t.Error("Newest timestamp should be greater than oldest")
	}
}

func TestManager_CleanupExpiredMessages(t *testing.T) {
	storage := NewMemoryStorageProvider()
	manager := NewManager(storage)

	// Create test setup
	senderIdentity, conversation := createDropBoxTestSetup(t)
	messageMgr := message.NewManager()

	// Send an expired message
	expiredEnvelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("expired"), nil, 1)
	// Manually adjust timestamps to make it expired
	expiredEnvelope.CreatedTS = time.Now().Unix() - 3600 // 1 hour ago
	expiredEnvelope.ExpiryTS = time.Now().Unix() - 1800  // 30 minutes ago
	if err != nil {
		t.Fatalf("Failed to create expired message: %v", err)
	}

	err = manager.SendMessage(expiredEnvelope)
	if err != nil {
		t.Fatalf("Failed to send expired message: %v", err)
	}

	// Send a valid message
	validEnvelope, err := messageMgr.CreateMessage(senderIdentity, conversation, "text", []byte("valid"), nil, messageMgr.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create valid message: %v", err)
	}

	err = manager.SendMessage(validEnvelope)
	if err != nil {
		t.Fatalf("Failed to send valid message: %v", err)
	}

	// Verify both messages are stored
	expiredKey := manager.GenerateStorageKey(expiredEnvelope)
	validKey := manager.GenerateStorageKey(validEnvelope)

	exists, _ := storage.Exists(expiredKey)
	if !exists {
		t.Error("Expired message should be stored initially")
	}

	exists, _ = storage.Exists(validKey)
	if !exists {
		t.Error("Valid message should be stored")
	}

	// Run cleanup
	err = manager.CleanupExpiredMessages(conversation.ID)
	if err != nil {
		t.Fatalf("Failed to cleanup expired messages: %v", err)
	}

	// Verify expired message was deleted
	exists, _ = storage.Exists(expiredKey)
	if exists {
		t.Error("Expired message should have been deleted")
	}

	// Verify valid message still exists
	exists, _ = storage.Exists(validKey)
	if !exists {
		t.Error("Valid message should still exist after cleanup")
	}
}

// Helper function to create test setup
func createDropBoxTestSetup(t *testing.T) (*types.Identity, *types.Conversation) {
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create sender identity
	senderIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate sender identity: %v", err)
	}

	// Create invite and derive conversation
	invite, err := inviteMgr.CreateInvite(senderIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}

	keys, err := inviteMgr.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	conversation, err := inviteMgr.CreateConversation(invite, keys)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	return senderIdentity, conversation
}
