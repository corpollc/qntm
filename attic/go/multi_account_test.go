package qntm

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
	"github.com/corpo/qntm/security"
)

// TestMultiAccountMessaging demonstrates full Alice-Bob scenario with separate keystores
func TestMultiAccountMessaging(t *testing.T) {
	// Create separate temporary directories for Alice and Bob
	tempDir := t.TempDir()
	aliceDir := filepath.Join(tempDir, "alice")
	bobDir := filepath.Join(tempDir, "bob")

	if err := os.MkdirAll(aliceDir, 0700); err != nil {
		t.Fatalf("Failed to create Alice directory: %v", err)
	}
	if err := os.MkdirAll(bobDir, 0700); err != nil {
		t.Fatalf("Failed to create Bob directory: %v", err)
	}

	t.Logf("🔑 Alice keystore: %s", aliceDir)
	t.Logf("🔑 Bob keystore: %s", bobDir)

	// Create managers
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	messageMgr := message.NewManager()
	securityEnforcer := security.NewPolicyEnforcer(nil)

	// Shared drop box storage (simulates Cloudflare Worker)
	storage := dropbox.NewMemoryStorageProvider()
	dropboxMgr := dropbox.NewManager(storage)

	// === Step 1: Alice generates her identity ===
	t.Log("👩 Alice generates her identity...")
	aliceIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice's identity: %v", err)
	}

	// Save Alice's identity to her keystore
	aliceIdentityFile := filepath.Join(aliceDir, "identity.cbor")
	aliceIdentityData, err := identityMgr.SerializeIdentity(aliceIdentity)
	if err != nil {
		t.Fatalf("Failed to serialize Alice's identity: %v", err)
	}
	if err := os.WriteFile(aliceIdentityFile, aliceIdentityData, 0600); err != nil {
		t.Fatalf("Failed to save Alice's identity: %v", err)
	}

	t.Logf("   Alice Key ID: %s", identityMgr.KeyIDToString(aliceIdentity.KeyID))
	t.Logf("   Alice Public Key: %s", identityMgr.PublicKeyToString(aliceIdentity.PublicKey))
	t.Logf("   Saved to: %s", aliceIdentityFile)

	// === Step 2: Bob generates his identity ===
	t.Log("🧑 Bob generates his identity...")
	bobIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob's identity: %v", err)
	}

	// Save Bob's identity to his keystore
	bobIdentityFile := filepath.Join(bobDir, "identity.cbor")
	bobIdentityData, err := identityMgr.SerializeIdentity(bobIdentity)
	if err != nil {
		t.Fatalf("Failed to serialize Bob's identity: %v", err)
	}
	if err := os.WriteFile(bobIdentityFile, bobIdentityData, 0600); err != nil {
		t.Fatalf("Failed to save Bob's identity: %v", err)
	}

	t.Logf("   Bob Key ID: %s", identityMgr.KeyIDToString(bobIdentity.KeyID))
	t.Logf("   Bob Public Key: %s", identityMgr.PublicKeyToString(bobIdentity.PublicKey))
	t.Logf("   Saved to: %s", bobIdentityFile)

	// === Step 3: Alice creates a direct conversation invite ===
	t.Log("📧 Alice creates an invite for Bob...")
	directInvite, err := inviteMgr.CreateInvite(aliceIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Alice failed to create invite: %v", err)
	}

	// Generate invite URL
	inviteURL, err := inviteMgr.InviteToURL(directInvite, "https://test.local/join")
	if err != nil {
		t.Fatalf("Failed to generate invite URL: %v", err)
	}

	t.Logf("   Conversation ID: %s", hex.EncodeToString(directInvite.ConvID[:]))
	t.Logf("   Invite URL: %s", inviteURL)

	// === Step 4: Alice derives her conversation keys ===
	t.Log("🔐 Alice derives conversation keys...")
	aliceKeys, err := inviteMgr.DeriveConversationKeys(directInvite)
	if err != nil {
		t.Fatalf("Alice failed to derive keys: %v", err)
	}

	aliceConversation, err := inviteMgr.CreateConversation(directInvite, aliceKeys)
	if err != nil {
		t.Fatalf("Alice failed to create conversation: %v", err)
	}

	// Save Alice's conversation to her keystore
	aliceConvFile := filepath.Join(aliceDir, "conversations.json")
	aliceConversations := []*types.Conversation{aliceConversation}
	aliceConvData, err := json.MarshalIndent(aliceConversations, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal Alice's conversations: %v", err)
	}
	if err := os.WriteFile(aliceConvFile, aliceConvData, 0600); err != nil {
		t.Fatalf("Failed to save Alice's conversations: %v", err)
	}

	t.Logf("   Alice's conversation saved to: %s", aliceConvFile)

	// === Step 5: Bob accepts the invite (out-of-band) ===
	t.Log("📨 Bob accepts Alice's invite...")
	bobReceivedInvite, err := inviteMgr.InviteFromURL(inviteURL)
	if err != nil {
		t.Fatalf("Bob failed to parse invite: %v", err)
	}

	// Bob derives the same conversation keys
	bobKeys, err := inviteMgr.DeriveConversationKeys(bobReceivedInvite)
	if err != nil {
		t.Fatalf("Bob failed to derive keys: %v", err)
	}

	bobConversation, err := inviteMgr.CreateConversation(bobReceivedInvite, bobKeys)
	if err != nil {
		t.Fatalf("Bob failed to create conversation: %v", err)
	}

	// Save Bob's conversation to his keystore
	bobConvFile := filepath.Join(bobDir, "conversations.json")
	bobConversations := []*types.Conversation{bobConversation}
	bobConvData, err := json.MarshalIndent(bobConversations, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal Bob's conversations: %v", err)
	}
	if err := os.WriteFile(bobConvFile, bobConvData, 0600); err != nil {
		t.Fatalf("Failed to save Bob's conversations: %v", err)
	}

	t.Logf("   Bob's conversation saved to: %s", bobConvFile)

	// Verify keys match (critical test!)
	if string(aliceKeys.AEADKey) != string(bobKeys.AEADKey) {
		t.Fatal("❌ CRITICAL: Alice and Bob derived different AEAD keys!")
	}
	if string(aliceKeys.NonceKey) != string(bobKeys.NonceKey) {
		t.Fatal("❌ CRITICAL: Alice and Bob derived different nonce keys!")
	}
	t.Log("✅ Key derivation successful - Alice and Bob have matching encryption keys")

	// Add participants to each other's conversations
	inviteMgr.AddParticipant(aliceConversation, bobIdentity.PublicKey)
	inviteMgr.AddParticipant(bobConversation, aliceIdentity.PublicKey)

	// === Step 6: Alice sends first message to Bob ===
	t.Log("💌 Alice sends first message...")
	aliceMessage1 := "Hello Bob! This is Alice. Can you receive this encrypted message?"
	aliceEnvelope1, err := messageMgr.CreateMessage(
		aliceIdentity,
		aliceConversation,
		"text",
		[]byte(aliceMessage1),
		nil,
		3600, // 1 hour TTL
	)
	if err != nil {
		t.Fatalf("Alice failed to create first message: %v", err)
	}

	// Store in shared drop box
	if err := dropboxMgr.SendMessage(aliceEnvelope1); err != nil {
		t.Fatalf("Failed to send Alice's first message: %v", err)
	}

	t.Logf("   Message: %s", aliceMessage1)
	t.Logf("   Message ID: %s", hex.EncodeToString(aliceEnvelope1.MsgID[:]))

	// === Step 7: Bob receives and decrypts Alice's message ===
	t.Log("📬 Bob receives Alice's message...")
	bobSeenMessages := make(map[types.MessageID]bool)
	bobMessages1, err := dropboxMgr.ReceiveMessages(bobIdentity, bobConversation, bobSeenMessages)
	if err != nil {
		t.Fatalf("Bob failed to receive messages: %v", err)
	}

	if len(bobMessages1) != 1 {
		t.Fatalf("Expected 1 message for Bob, got %d", len(bobMessages1))
	}

	bobMsg1 := bobMessages1[0]
	if string(bobMsg1.Inner.Body) != aliceMessage1 {
		t.Fatalf("❌ Message content mismatch!\n  Expected: %s\n  Got: %s", aliceMessage1, string(bobMsg1.Inner.Body))
	}

	if !bobMsg1.Verified {
		t.Fatal("❌ Alice's message signature verification failed")
	}

	if bobMsg1.Inner.SenderKID != aliceIdentity.KeyID {
		t.Fatal("❌ Sender key ID doesn't match Alice")
	}

	t.Log("✅ Bob successfully decrypted and verified Alice's message")
	t.Logf("   Received: %s", string(bobMsg1.Inner.Body))

	// === Step 8: Security policy check ===
	t.Log("🔐 Security policy enforcement check...")
	err = securityEnforcer.CheckMessageSecurity(aliceEnvelope1, bobMsg1.Inner, bobConversation)
	if err != nil {
		t.Fatalf("Security check failed for Alice's message: %v", err)
	}
	t.Log("✅ Security policy check passed")

	// === Step 9: Bob sends reply to Alice ===
	t.Log("💌 Bob sends reply to Alice...")
	bobMessage1 := "Hi Alice! Yes, I received your message loud and clear. The encryption is working perfectly!"
	bobEnvelope1, err := messageMgr.CreateMessage(
		bobIdentity,
		bobConversation,
		"text",
		[]byte(bobMessage1),
		nil,
		3600,
	)
	if err != nil {
		t.Fatalf("Bob failed to create reply: %v", err)
	}

	if err := dropboxMgr.SendMessage(bobEnvelope1); err != nil {
		t.Fatalf("Failed to send Bob's reply: %v", err)
	}

	t.Logf("   Message: %s", bobMessage1)
	t.Logf("   Message ID: %s", hex.EncodeToString(bobEnvelope1.MsgID[:]))

	// === Step 10: Alice receives Bob's reply ===
	t.Log("📬 Alice receives Bob's reply...")
	aliceSeenMessages := make(map[types.MessageID]bool)
	aliceMessages1, err := dropboxMgr.ReceiveMessages(aliceIdentity, aliceConversation, aliceSeenMessages)
	if err != nil {
		t.Fatalf("Alice failed to receive Bob's reply: %v", err)
	}

	if len(aliceMessages1) == 0 {
		t.Fatalf("Expected at least 1 reply message for Alice, got %d", len(aliceMessages1))
	}

	var aliceRecvMsg1 *types.Message
	for _, msg := range aliceMessages1 {
		if msg.Inner.SenderKID == bobIdentity.KeyID && string(msg.Inner.Body) == bobMessage1 {
			aliceRecvMsg1 = msg
			break
		}
	}
	if aliceRecvMsg1 == nil {
		t.Fatalf("❌ Bob's reply not found in %d received messages", len(aliceMessages1))
	}

	if !aliceRecvMsg1.Verified {
		t.Fatal("❌ Bob's message signature verification failed")
	}

	if aliceRecvMsg1.Inner.SenderKID != bobIdentity.KeyID {
		t.Fatal("❌ Reply sender key ID doesn't match Bob")
	}

	t.Log("✅ Alice successfully decrypted and verified Bob's reply")
	t.Logf("   Received: %s", string(aliceRecvMsg1.Inner.Body))

	// === Step 11: Multiple round-trip messages ===
	t.Log("🔄 Testing multiple round-trip messages...")

	messages := []struct {
		sender     *types.Identity
		senderName string
		text       string
	}{
		{aliceIdentity, "Alice", "Let's test multiple messages. This is message #2 from Alice."},
		{bobIdentity, "Bob", "Great idea! This is Bob's message #2. Crypto holding up well."},
		{aliceIdentity, "Alice", "Perfect! Message #3 from Alice. How about we test some emoji? 🚀🔒✨"},
		{bobIdentity, "Bob", "Emoji working! 👍 Bob's message #3. Let's try some special chars: @#$%^&*()"},
		{aliceIdentity, "Alice", "Final test from Alice. This proves bidirectional encryption with separate keystores! 🎉"},
	}

	for i, msg := range messages {
		t.Logf("   📨 %s sending message %d...", msg.senderName, i+3)

		var senderConv *types.Conversation
		var receiverConv *types.Conversation
		var receiverSeenMsgs *map[types.MessageID]bool
		var receiverIdentity *types.Identity

		if msg.sender == aliceIdentity {
			senderConv = aliceConversation
			receiverConv = bobConversation
			receiverSeenMsgs = &bobSeenMessages
			receiverIdentity = bobIdentity
		} else {
			senderConv = bobConversation
			receiverConv = aliceConversation
			receiverSeenMsgs = &aliceSeenMessages
			receiverIdentity = aliceIdentity
		}

		// Create and send message
		envelope, err := messageMgr.CreateMessage(
			msg.sender,
			senderConv,
			"text",
			[]byte(msg.text),
			nil,
			3600,
		)
		if err != nil {
			t.Fatalf("%s failed to create message %d: %v", msg.senderName, i+3, err)
		}

		if err := dropboxMgr.SendMessage(envelope); err != nil {
			t.Fatalf("Failed to send %s's message %d: %v", msg.senderName, i+3, err)
		}

		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)

		// Receiver gets message
		receivedMsgs, err := dropboxMgr.ReceiveMessages(receiverIdentity, receiverConv, *receiverSeenMsgs)
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i+3, err)
		}

		// Find the new message (last one chronologically)
		if len(receivedMsgs) == 0 {
			t.Fatalf("No messages received for round %d", i+3)
		}

		var newMsg *types.Message
		for _, candidate := range receivedMsgs {
			if candidate.Inner.SenderKID == msg.sender.KeyID && string(candidate.Inner.Body) == msg.text {
				newMsg = candidate
				break
			}
		}
		if newMsg == nil {
			t.Fatalf("❌ Message %d not found in %d received message(s)", i+3, len(receivedMsgs))
		}

		if !newMsg.Verified {
			t.Fatalf("❌ Message %d signature verification failed", i+3)
		}

		t.Logf("      ✅ Received and verified: %s", msg.text[:50]+"...")
	}

	// === Step 12: Verify separate keystore integrity ===
	t.Log("🔍 Verifying separate keystore integrity...")

	// Reload Alice's identity from her keystore
	aliceReloadedData, err := os.ReadFile(aliceIdentityFile)
	if err != nil {
		t.Fatalf("Failed to reload Alice's identity: %v", err)
	}
	aliceReloaded, err := identityMgr.DeserializeIdentity(aliceReloadedData)
	if err != nil {
		t.Fatalf("Failed to deserialize Alice's reloaded identity: %v", err)
	}

	// Reload Bob's identity from his keystore
	bobReloadedData, err := os.ReadFile(bobIdentityFile)
	if err != nil {
		t.Fatalf("Failed to reload Bob's identity: %v", err)
	}
	bobReloaded, err := identityMgr.DeserializeIdentity(bobReloadedData)
	if err != nil {
		t.Fatalf("Failed to deserialize Bob's reloaded identity: %v", err)
	}

	// Verify identities match
	if aliceReloaded.KeyID != aliceIdentity.KeyID {
		t.Fatal("❌ Alice's reloaded identity doesn't match original")
	}
	if bobReloaded.KeyID != bobIdentity.KeyID {
		t.Fatal("❌ Bob's reloaded identity doesn't match original")
	}

	t.Log("✅ Keystore integrity verified - separate identities maintained")

	// === Final Summary ===
	t.Log("")
	t.Log("🎉 MULTI-ACCOUNT TEST COMPLETE!")
	t.Log("✅ Separate keystores created and maintained")
	t.Log("✅ End-to-end encryption working across distinct identities")
	t.Log("✅ Key derivation produces matching encryption keys")
	t.Log("✅ Bidirectional messaging successful")
	t.Log("✅ Signature verification working for both parties")
	t.Log("✅ Security policy enforcement working")
	t.Log("✅ Multiple round-trip messages successful")
	t.Log("✅ Keystore integrity maintained through reload")

	t.Logf("📊 Stats:")
	t.Logf("   Alice keystore: %s", aliceDir)
	t.Logf("   Bob keystore: %s", bobDir)
	t.Logf("   Messages exchanged: %d", len(messages)+2)
	t.Logf("   Conversation ID: %s", hex.EncodeToString(directInvite.ConvID[:]))
}
