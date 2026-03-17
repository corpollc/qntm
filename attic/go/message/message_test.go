package message

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

func TestManager_CreateMessage(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Create a test message
	bodyType := "text"
	body := []byte("Hello, this is a test message!")
	refs := []interface{}{"ref1", "ref2"}
	ttl := manager.DefaultTTL()

	envelope, err := manager.CreateMessage(senderIdentity, conversation, bodyType, body, refs, ttl)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Validate envelope structure
	err = manager.ValidateEnvelope(envelope)
	if err != nil {
		t.Fatalf("Created envelope is invalid: %v", err)
	}

	// Check envelope fields
	if envelope.ConvID != conversation.ID {
		t.Error("Envelope conversation ID does not match")
	}

	if envelope.Suite != types.DefaultSuite {
		t.Error("Envelope suite does not match default")
	}

	if len(envelope.Ciphertext) == 0 {
		t.Error("Envelope ciphertext is empty")
	}

	if envelope.ExpiryTS <= envelope.CreatedTS {
		t.Error("Expiry timestamp should be after created timestamp")
	}
}

func TestManager_DecryptMessage(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Create a test message
	bodyType := "text"
	body := []byte("Hello, this is a test message!")
	refs := []interface{}{"ref1", "ref2"}
	ttl := manager.DefaultTTL()

	envelope, err := manager.CreateMessage(senderIdentity, conversation, bodyType, body, refs, ttl)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Decrypt the message
	message, err := manager.DecryptMessage(envelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify the decrypted content
	if message.Inner.BodyType != bodyType {
		t.Errorf("Body type mismatch: got %s, want %s", message.Inner.BodyType, bodyType)
	}

	if string(message.Inner.Body) != string(body) {
		t.Errorf("Body content mismatch: got %s, want %s", string(message.Inner.Body), string(body))
	}

	if len(message.Inner.Refs) != len(refs) {
		t.Errorf("Refs length mismatch: got %d, want %d", len(message.Inner.Refs), len(refs))
	}

	// Verify signature verification succeeded
	if !message.Verified {
		t.Error("Message signature verification failed")
	}

	// Verify sender information
	if !ed25519.PublicKey(message.Inner.SenderIKPK).Equal(senderIdentity.PublicKey) {
		t.Error("Sender public key mismatch")
	}

	if message.Inner.SenderKID != senderIdentity.KeyID {
		t.Error("Sender key ID mismatch")
	}
}

func TestManager_MessageRoundTrip(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Test different message types and content
	testCases := []struct {
		name     string
		bodyType string
		body     []byte
		refs     []interface{}
	}{
		{
			name:     "text message",
			bodyType: "text",
			body:     []byte("Hello, world!"),
			refs:     nil,
		},
		{
			name:     "json message",
			bodyType: "json",
			body:     []byte(`{"key": "value", "number": 42}`),
			refs:     []interface{}{"attachment1.jpg"},
		},
		{
			name:     "event message",
			bodyType: "event",
			body:     []byte("calendar-invite"),
			refs:     []interface{}{"cal1", "cal2"},
		},
		{
			name:     "empty body",
			bodyType: "ping",
			body:     []byte{},
			refs:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create message
			envelope, err := manager.CreateMessage(senderIdentity, conversation, tc.bodyType, tc.body, tc.refs, manager.DefaultTTL())
			if err != nil {
				t.Fatalf("Failed to create %s: %v", tc.name, err)
			}

			// Decrypt message
			message, err := manager.DecryptMessage(envelope, conversation)
			if err != nil {
				t.Fatalf("Failed to decrypt %s: %v", tc.name, err)
			}

			// Verify content matches
			if message.Inner.BodyType != tc.bodyType {
				t.Errorf("Body type mismatch: got %s, want %s", message.Inner.BodyType, tc.bodyType)
			}

			if string(message.Inner.Body) != string(tc.body) {
				t.Errorf("Body mismatch: got %s, want %s", string(message.Inner.Body), string(tc.body))
			}

			if len(message.Inner.Refs) != len(tc.refs) {
				t.Errorf("Refs length mismatch: got %d, want %d", len(message.Inner.Refs), len(tc.refs))
			}

			// Verify signature
			if !message.Verified {
				t.Errorf("%s signature verification failed", tc.name)
			}
		})
	}
}

func TestManager_SignatureVerification(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Create a message
	envelope, err := manager.CreateMessage(senderIdentity, conversation, "text", []byte("test"), nil, manager.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Decrypt to get inner payload
	message, err := manager.DecryptMessage(envelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Test valid signature verification
	verified, err := manager.VerifyMessageSignature(envelope, message.Inner)
	if err != nil {
		t.Fatalf("Signature verification error: %v", err)
	}
	if !verified {
		t.Error("Valid signature should verify successfully")
	}

	// Test with corrupted signature
	corruptedInner := *message.Inner
	corruptedInner.Signature[0] ^= 0xFF // flip bits

	verified, err = manager.VerifyMessageSignature(envelope, &corruptedInner)
	if err != nil {
		t.Fatalf("Signature verification error: %v", err)
	}
	if verified {
		t.Error("Corrupted signature should not verify")
	}

	// Test with wrong sender key ID
	wrongKIDInner := *message.Inner
	wrongKIDInner.SenderKID = types.KeyID{0xFF, 0xFF, 0xFF, 0xFF}

	verified, err = manager.VerifyMessageSignature(envelope, &wrongKIDInner)
	if err != nil {
		t.Fatalf("Signature verification error: %v", err)
	}
	if verified {
		t.Error("Wrong sender key ID should not verify")
	}
}

func TestManager_DecryptMessage_InvalidSignatureFails(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)
	envelope, err := manager.CreateMessage(senderIdentity, conversation, "text", []byte("tamper me"), nil, manager.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	aadStruct := types.AADStruct{
		Version:   envelope.Version,
		Suite:     envelope.Suite,
		ConvID:    envelope.ConvID,
		MsgID:     envelope.MsgID,
		CreatedTS: envelope.CreatedTS,
		ExpiryTS:  envelope.ExpiryTS,
		ConvEpoch: envelope.ConvEpoch,
	}
	aadBytes, err := cbor.MarshalCanonical(aadStruct)
	if err != nil {
		t.Fatalf("Failed to marshal AAD: %v", err)
	}

	nonce, err := manager.suite.DeriveNonce(conversation.Keys.NonceKey, envelope.MsgID[:])
	if err != nil {
		t.Fatalf("Failed to derive nonce: %v", err)
	}

	innerPayloadBytes, err := manager.suite.Decrypt(conversation.Keys.AEADKey, nonce, envelope.Ciphertext, aadBytes)
	if err != nil {
		t.Fatalf("Failed to decrypt inner payload: %v", err)
	}

	var inner types.InnerPayload
	if err := cbor.UnmarshalCanonical(innerPayloadBytes, &inner); err != nil {
		t.Fatalf("Failed to unmarshal inner payload: %v", err)
	}

	inner.Signature[0] ^= 0xFF

	tamperedInnerBytes, err := cbor.MarshalCanonical(inner)
	if err != nil {
		t.Fatalf("Failed to marshal tampered inner payload: %v", err)
	}

	tamperedCiphertext, err := manager.suite.Encrypt(conversation.Keys.AEADKey, nonce, tamperedInnerBytes, aadBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt tampered payload: %v", err)
	}

	tamperedEnvelope := *envelope
	tamperedEnvelope.Ciphertext = tamperedCiphertext
	tamperedEnvelope.AADHash = manager.suite.Hash(aadBytes)

	_, err = manager.DecryptMessage(&tamperedEnvelope, conversation)
	if err == nil {
		t.Fatal("expected invalid signature to fail decrypt")
	}
	if !strings.Contains(err.Error(), "invalid message signature") {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}
}

func TestManager_WrongConversationDecryption(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create two different conversations
	senderIdentity1, conversation1 := createTestSetup(t, identityMgr, inviteMgr)
	_, conversation2 := createTestSetup(t, identityMgr, inviteMgr)

	// Create message in conversation1
	envelope, err := manager.CreateMessage(senderIdentity1, conversation1, "text", []byte("secret"), nil, manager.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Try to decrypt with conversation2 keys (should fail)
	_, err = manager.DecryptMessage(envelope, conversation2)
	if err == nil {
		t.Error("Decryption should fail with wrong conversation keys")
	}
}

func TestManager_ExpiredMessage(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Create message with very short TTL
	shortTTL := int64(-1) // Already expired
	envelope, err := manager.CreateMessage(senderIdentity, conversation, "text", []byte("expired"), nil, shortTTL)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Check expiry
	if !manager.CheckExpiry(envelope) {
		t.Error("Message should be expired")
	}

	// Try to decrypt expired message (should fail)
	_, err = manager.DecryptMessage(envelope, conversation)
	if err == nil {
		t.Error("Decryption should fail for expired message")
	}
}

func TestManager_Serialization(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	// Create test setup
	senderIdentity, conversation := createTestSetup(t, identityMgr, inviteMgr)

	// Create a message
	originalEnvelope, err := manager.CreateMessage(senderIdentity, conversation, "text", []byte("test"), nil, manager.DefaultTTL())
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Serialize
	data, err := manager.SerializeEnvelope(originalEnvelope)
	if err != nil {
		t.Fatalf("Failed to serialize envelope: %v", err)
	}

	if len(data) == 0 {
		t.Error("Serialized data is empty")
	}

	// Deserialize
	deserializedEnvelope, err := manager.DeserializeEnvelope(data)
	if err != nil {
		t.Fatalf("Failed to deserialize envelope: %v", err)
	}

	// Compare
	if !envelopesEqual(originalEnvelope, deserializedEnvelope) {
		t.Error("Deserialized envelope does not match original")
	}

	// Verify the deserialized envelope can still be decrypted
	message, err := manager.DecryptMessage(deserializedEnvelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt deserialized envelope: %v", err)
	}

	if !message.Verified {
		t.Error("Deserialized message signature verification failed")
	}
}

func TestManager_ValidationErrors(t *testing.T) {
	manager := NewManager()

	// Test nil envelope validation
	err := manager.ValidateEnvelope(nil)
	if err == nil {
		t.Error("ValidateEnvelope should fail with nil envelope")
	}

	// Test invalid version
	invalidEnvelope := &types.OuterEnvelope{
		Version: 999,
		Suite:   types.DefaultSuite,
	}
	err = manager.ValidateEnvelope(invalidEnvelope)
	if err == nil {
		t.Error("ValidateEnvelope should fail with invalid version")
	}

	// Test invalid suite
	invalidEnvelope.Version = types.ProtocolVersion
	invalidEnvelope.Suite = "INVALID-SUITE"
	err = manager.ValidateEnvelope(invalidEnvelope)
	if err == nil {
		t.Error("ValidateEnvelope should fail with invalid suite")
	}

	// Test nil inner payload validation
	err = manager.ValidateInnerPayload(nil)
	if err == nil {
		t.Error("ValidateInnerPayload should fail with nil inner payload")
	}

	// Test invalid signature algorithm
	invalidInner := &types.InnerPayload{
		SenderIKPK: make([]byte, ed25519.PublicKeySize),
		SigAlg:     "INVALID-ALG",
		Signature:  make([]byte, ed25519.SignatureSize),
		BodyType:   "test",
	}
	err = manager.ValidateInnerPayload(invalidInner)
	if err == nil {
		t.Error("ValidateInnerPayload should fail with invalid signature algorithm")
	}
}

// Helper function to create test setup
func createTestSetup(t *testing.T, identityMgr *identity.Manager, inviteMgr *invite.Manager) (*types.Identity, *types.Conversation) {
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

// Helper function to compare envelopes
func envelopesEqual(a, b *types.OuterEnvelope) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return a.Version == b.Version &&
		a.Suite == b.Suite &&
		a.ConvID == b.ConvID &&
		a.MsgID == b.MsgID &&
		a.CreatedTS == b.CreatedTS &&
		a.ExpiryTS == b.ExpiryTS &&
		string(a.Ciphertext) == string(b.Ciphertext) &&
		string(a.AADHash) == string(b.AADHash)
}
