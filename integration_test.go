package qntm

import (
	"crypto/ed25519"
	"testing"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/group"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
	"github.com/corpo/qntm/security"
)

// TestEndToEndWorkflow tests the complete qntm messaging workflow
func TestEndToEndWorkflow(t *testing.T) {
	// Create managers
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	messageMgr := message.NewManager()
	securityEnforcer := security.NewPolicyEnforcer(nil)
	storage := dropbox.NewMemoryStorageProvider()
	dropboxMgr := dropbox.NewManager(storage)

	// Create two users: Alice and Bob
	alice, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice's identity: %v", err)
	}

	bob, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob's identity: %v", err)
	}

	// Step 1: Alice creates a direct conversation invite
	directInvite, err := inviteMgr.CreateInvite(alice, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Alice failed to create direct invite: %v", err)
	}

	// Step 2: Alice shares invite with Bob (out-of-band)
	inviteURL, err := inviteMgr.InviteToURL(directInvite, "https://example.com/qntm")
	if err != nil {
		t.Fatalf("Failed to create invite URL: %v", err)
	}

	// Step 3: Bob accepts the invite
	bobReceivedInvite, err := inviteMgr.InviteFromURL(inviteURL)
	if err != nil {
		t.Fatalf("Bob failed to parse invite: %v", err)
	}

	// Step 4: Both derive the same conversation keys
	aliceKeys, err := inviteMgr.DeriveConversationKeys(directInvite)
	if err != nil {
		t.Fatalf("Alice failed to derive keys: %v", err)
	}

	bobKeys, err := inviteMgr.DeriveConversationKeys(bobReceivedInvite)
	if err != nil {
		t.Fatalf("Bob failed to derive keys: %v", err)
	}

	// Verify keys match
	if string(aliceKeys.AEADKey) != string(bobKeys.AEADKey) {
		t.Error("AEAD keys don't match between Alice and Bob")
	}

	// Step 5: Create conversations
	aliceConversation, err := inviteMgr.CreateConversation(directInvite, aliceKeys)
	if err != nil {
		t.Fatalf("Alice failed to create conversation: %v", err)
	}

	bobConversation, err := inviteMgr.CreateConversation(bobReceivedInvite, bobKeys)
	if err != nil {
		t.Fatalf("Bob failed to create conversation: %v", err)
	}

	// Add participants
	inviteMgr.AddParticipant(aliceConversation, bob.PublicKey)
	inviteMgr.AddParticipant(bobConversation, alice.PublicKey)

	// Step 6: Alice sends a message to Bob
	aliceMessage := "Hello Bob! This is a secure message."
	envelope, err := messageMgr.CreateMessage(
		alice,
		aliceConversation,
		"text",
		[]byte(aliceMessage),
		nil,
		3600, // 1 hour TTL
	)
	if err != nil {
		t.Fatalf("Alice failed to create message: %v", err)
	}

	// Step 7: Store message in drop box
	if err := dropboxMgr.SendMessage(envelope); err != nil {
		t.Fatalf("Failed to send Alice's message: %v", err)
	}

	// Step 8: Bob receives and decrypts the message
	seenMessages := make(map[types.MessageID]bool)
	messages, err := dropboxMgr.ReceiveMessages(bob, bobConversation, seenMessages)
	if err != nil {
		t.Fatalf("Bob failed to receive messages: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}

	receivedMessage := messages[0]

	// Step 9: Verify message content and signature
	if string(receivedMessage.Inner.Body) != aliceMessage {
		t.Errorf("Message content mismatch: got %s, want %s",
			string(receivedMessage.Inner.Body), aliceMessage)
	}

	if !receivedMessage.Verified {
		t.Error("Message signature verification failed")
	}

	if receivedMessage.Inner.SenderKID != alice.KeyID {
		t.Error("Sender key ID doesn't match Alice")
	}

	// Step 10: Security policy enforcement
	err = securityEnforcer.CheckMessageSecurity(envelope, receivedMessage.Inner, bobConversation)
	if err != nil {
		t.Fatalf("Security check failed: %v", err)
	}

	// Step 11: Bob sends a reply
	bobReply := "Hello Alice! Message received and verified!"
	bobEnvelope, err := messageMgr.CreateMessage(
		bob,
		bobConversation,
		"text",
		[]byte(bobReply),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Bob failed to create reply: %v", err)
	}

	if err := dropboxMgr.SendMessage(bobEnvelope); err != nil {
		t.Fatalf("Failed to send Bob's reply: %v", err)
	}

	// Step 12: Alice receives Bob's reply
	aliceSeenMessages := make(map[types.MessageID]bool)
	aliceMessages, err := dropboxMgr.ReceiveMessages(alice, aliceConversation, aliceSeenMessages)
	if err != nil {
		t.Fatalf("Alice failed to receive Bob's reply: %v", err)
	}

	if len(aliceMessages) == 0 {
		t.Fatalf("Expected at least 1 reply message, got %d", len(aliceMessages))
	}

	var reply *types.Message
	for _, msg := range aliceMessages {
		if msg.Inner.SenderKID == bob.KeyID && string(msg.Inner.Body) == bobReply {
			reply = msg
			break
		}
	}
	if reply == nil {
		t.Fatalf("Expected to find Bob's reply in %d messages", len(aliceMessages))
	}

	if reply.Inner.SenderKID != bob.KeyID {
		t.Error("Reply sender key ID doesn't match Bob")
	}

	t.Logf("✓ End-to-end test passed: Alice and Bob successfully exchanged encrypted messages")
}

// TestGroupWorkflow tests the complete group messaging workflow
func TestGroupWorkflow(t *testing.T) {
	// Create managers
	identityMgr := identity.NewManager()
	groupMgr := group.NewManager()
	messageMgr := message.NewManager()
	storage := dropbox.NewMemoryStorageProvider()
	dropboxMgr := dropbox.NewManager(storage)

	// Create three users: Alice (admin), Bob, and Charlie
	alice, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice's identity: %v", err)
	}

	bob, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob's identity: %v", err)
	}

	charlie, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Charlie's identity: %v", err)
	}

	// Step 1: Alice creates a group
	conversation, groupState, err := groupMgr.CreateGroup(
		alice,
		"Test Group",
		"A test group for integration testing",
		[]ed25519.PublicKey{bob.PublicKey}, // Bob is founding member
		storage,
	)
	if err != nil {
		t.Fatalf("Alice failed to create group: %v", err)
	}

	// Verify initial group state
	if groupMgr.GetMemberCount(groupState) != 2 {
		t.Errorf("Expected 2 initial members, got %d", groupMgr.GetMemberCount(groupState))
	}

	if !groupMgr.IsAdmin(groupState, alice.KeyID) {
		t.Error("Alice should be admin")
	}

	if !groupMgr.IsMember(groupState, bob.KeyID) {
		t.Error("Bob should be a member")
	}

	// Step 2: Alice adds Charlie to the group
	err = groupMgr.AddMembers(
		alice,
		conversation,
		groupState,
		[]ed25519.PublicKey{charlie.PublicKey},
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to add Charlie to group: %v", err)
	}

	if groupMgr.GetMemberCount(groupState) != 3 {
		t.Errorf("Expected 3 members after adding Charlie, got %d", groupMgr.GetMemberCount(groupState))
	}

	// Step 3: Alice sends a group message
	groupMessage := "Hello everyone! Welcome to the test group."
	envelope, err := messageMgr.CreateMessage(
		alice,
		conversation,
		"text",
		[]byte(groupMessage),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Alice failed to create group message: %v", err)
	}

	if err := dropboxMgr.SendMessage(envelope); err != nil {
		t.Fatalf("Failed to send group message: %v", err)
	}

	// Step 4: Bob receives the group message
	bobSeenMessages := make(map[types.MessageID]bool)
	bobMessages, err := dropboxMgr.ReceiveMessages(bob, conversation, bobSeenMessages)
	if err != nil {
		t.Fatalf("Bob failed to receive group messages: %v", err)
	}

	// Bob should receive both the genesis message and Alice's message
	if len(bobMessages) < 2 {
		t.Fatalf("Expected at least 2 messages (genesis + Alice's message), got %d", len(bobMessages))
	}

	// Find Alice's text message
	var aliceTextMessage *types.Message
	for _, msg := range bobMessages {
		if msg.Inner.BodyType == "text" && msg.Inner.SenderKID == alice.KeyID {
			aliceTextMessage = msg
			break
		}
	}

	if aliceTextMessage == nil {
		t.Fatal("Bob didn't receive Alice's text message")
	}

	if string(aliceTextMessage.Inner.Body) != groupMessage {
		t.Errorf("Group message content mismatch: got %s, want %s",
			string(aliceTextMessage.Inner.Body), groupMessage)
	}

	// Step 5: Process group management messages
	freshGroupState := &group.GroupState{
		Members: make(map[types.KeyID]*group.GroupMemberInfo),
		Admins:  make(map[types.KeyID]bool),
	}

	// Process messages in chronological order
	// First process genesis and admin setup, then other messages
	for _, msg := range bobMessages {
		if msg.Inner.BodyType == "group_genesis" {
			err = groupMgr.ProcessGroupMessage(msg, freshGroupState)
			if err != nil {
				t.Fatalf("Failed to process genesis message: %v", err)
			}
		}
	}

	// Then process other group messages
	for _, msg := range bobMessages {
		if msg.Inner.BodyType != "group_genesis" {
			err = groupMgr.ProcessGroupMessage(msg, freshGroupState)
			if err != nil && msg.Inner.BodyType != "text" {
				// Only fail on group management messages, not regular text messages
				t.Fatalf("Failed to process group message %s: %v", msg.Inner.BodyType, err)
			}
		}
	}

	// Verify group state was reconstructed correctly
	if freshGroupState.GroupName != "Test Group" {
		t.Errorf("Expected group name 'Test Group', got %s", freshGroupState.GroupName)
	}

	if len(freshGroupState.Members) != 3 {
		t.Errorf("Expected 3 members in reconstructed state, got %d", len(freshGroupState.Members))
	}

	t.Logf("✓ Group workflow test passed: Group created, members added, messages exchanged and processed")
}

// TestSecurityFeatures tests security enforcement
func TestSecurityFeatures(t *testing.T) {
	// Create setup
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	messageMgr := message.NewManager()
	securityEnforcer := security.NewPolicyEnforcer(nil)
	storage := dropbox.NewMemoryStorageProvider()
	_ = storage // For potential future use

	alice, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice's identity: %v", err)
	}

	bob, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob's identity: %v", err)
	}

	// Create conversation
	invite, err := inviteMgr.CreateInvite(alice, types.ConversationTypeDirect)
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

	inviteMgr.AddParticipant(conversation, bob.PublicKey)

	// Test 1: Valid message passes all security checks
	envelope, err := messageMgr.CreateMessage(
		alice,
		conversation,
		"text",
		[]byte("Valid message"),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Failed to create valid message: %v", err)
	}

	msg, err := messageMgr.DecryptMessage(envelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt valid message: %v", err)
	}

	err = securityEnforcer.CheckMessageSecurity(envelope, msg.Inner, conversation)
	if err != nil {
		t.Fatalf("Valid message should pass security checks: %v", err)
	}

	// Test 2: Replay attack is detected
	err = securityEnforcer.CheckMessageSecurity(envelope, msg.Inner, conversation)
	if err == nil {
		t.Error("Replay attack should be detected")
	}

	// Test 3: Membership policy enforcement
	// Create a message from Bob and verify it passes
	bobEnvelope, err := messageMgr.CreateMessage(
		bob,
		conversation,
		"text",
		[]byte("Bob's message"),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Failed to create Bob's message: %v", err)
	}

	bobMsg, err := messageMgr.DecryptMessage(bobEnvelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt Bob's message: %v", err)
	}

	err = securityEnforcer.CheckMessageSecurity(bobEnvelope, bobMsg.Inner, conversation)
	if err != nil {
		t.Fatalf("Bob's message should pass security checks: %v", err)
	}

	// Test 4: Unauthorized sender is rejected
	unauthorized, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate unauthorized identity: %v", err)
	}

	// Set a restrictive membership policy
	policy := &security.MembershipPolicy{
		AllowedMembers: map[types.KeyID]bool{
			alice.KeyID: true,
			bob.KeyID:   true,
		},
		Admins: map[types.KeyID]bool{
			alice.KeyID: true,
		},
	}

	securityEnforcer.SetMembershipPolicy(conversation.ID, policy)

	// Try to create message from unauthorized user
	unauthorizedEnvelope, err := messageMgr.CreateMessage(
		unauthorized,
		conversation,
		"text",
		[]byte("Unauthorized message"),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Failed to create unauthorized message: %v", err)
	}

	unauthorizedMsg, err := messageMgr.DecryptMessage(unauthorizedEnvelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt unauthorized message: %v", err)
	}

	err = securityEnforcer.CheckMessageSecurity(unauthorizedEnvelope, unauthorizedMsg.Inner, conversation)
	if err == nil {
		t.Error("Unauthorized message should be rejected by membership policy")
	}

	t.Logf("✓ Security features test passed: Replay protection, membership policies working correctly")
}

// TestCompleteIntegration runs all integration tests
func TestCompleteIntegration(t *testing.T) {
	t.Run("EndToEndWorkflow", TestEndToEndWorkflow)
	t.Run("GroupWorkflow", TestGroupWorkflow)
	t.Run("SecurityFeatures", TestSecurityFeatures)
}
