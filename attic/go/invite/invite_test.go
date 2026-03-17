package invite

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

func TestManager_CreateInvite(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identity
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	// Test direct conversation invite
	directInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create direct invite: %v", err)
	}
	
	err = manager.ValidateInvite(directInvite)
	if err != nil {
		t.Fatalf("Created direct invite is invalid: %v", err)
	}
	
	if directInvite.Type != string(types.ConversationTypeDirect) {
		t.Errorf("Expected direct conversation type, got %s", directInvite.Type)
	}
	
	// Test group conversation invite
	groupInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeGroup)
	if err != nil {
		t.Fatalf("Failed to create group invite: %v", err)
	}
	
	err = manager.ValidateInvite(groupInvite)
	if err != nil {
		t.Fatalf("Created group invite is invalid: %v", err)
	}
	
	if groupInvite.Type != string(types.ConversationTypeGroup) {
		t.Errorf("Expected group conversation type, got %s", groupInvite.Type)
	}
	
	// Verify invites have different conversation IDs
	if directInvite.ConvID == groupInvite.ConvID {
		t.Error("Two invites should have different conversation IDs")
	}
	
	// Verify invites have different secrets
	if string(directInvite.InviteSecret) == string(groupInvite.InviteSecret) {
		t.Error("Two invites should have different secrets")
	}
}

func TestManager_Serialization(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identity and invite
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	originalInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create test invite: %v", err)
	}
	
	// Serialize
	data, err := manager.SerializeInvite(originalInvite)
	if err != nil {
		t.Fatalf("Failed to serialize invite: %v", err)
	}
	
	if len(data) == 0 {
		t.Error("Serialized data is empty")
	}
	
	// Deserialize
	deserializedInvite, err := manager.DeserializeInvite(data)
	if err != nil {
		t.Fatalf("Failed to deserialize invite: %v", err)
	}
	
	// Compare
	if !invitesEqual(originalInvite, deserializedInvite) {
		t.Error("Deserialized invite does not match original")
	}
}

func TestManager_URLConversion(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identity and invite
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	originalInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create test invite: %v", err)
	}
	
	baseURL := "https://example.com/qntm"
	
	// Convert to URL
	inviteURL, err := manager.InviteToURL(originalInvite, baseURL)
	if err != nil {
		t.Fatalf("Failed to convert invite to URL: %v", err)
	}
	
	// URL should contain the base URL
	if !strings.HasPrefix(inviteURL, baseURL) {
		t.Errorf("Invite URL should start with base URL")
	}
	
	// URL should have a fragment
	if !strings.Contains(inviteURL, "#") {
		t.Error("Invite URL should contain a fragment")
	}
	
	// Convert back from URL
	deserializedInvite, err := manager.InviteFromURL(inviteURL)
	if err != nil {
		t.Fatalf("Failed to extract invite from URL: %v", err)
	}
	
	// Compare
	if !invitesEqual(originalInvite, deserializedInvite) {
		t.Error("Invite extracted from URL does not match original")
	}
}

func TestManager_KeyDerivation(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identity and invite
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	invite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create test invite: %v", err)
	}
	
	// Derive keys
	keys, err := manager.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive conversation keys: %v", err)
	}
	
	// Validate key lengths
	if len(keys.Root) != 32 {
		t.Errorf("Root key length is %d, want 32", len(keys.Root))
	}
	if len(keys.AEADKey) != 32 {
		t.Errorf("AEAD key length is %d, want 32", len(keys.AEADKey))
	}
	if len(keys.NonceKey) != 32 {
		t.Errorf("Nonce key length is %d, want 32", len(keys.NonceKey))
	}
	
	// Test deterministic derivation
	keys2, err := manager.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive conversation keys again: %v", err)
	}
	
	if !keysEqual(keys, keys2) {
		t.Error("Key derivation is not deterministic")
	}
	
	// Different invite should produce different keys
	differentInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create different invite: %v", err)
	}
	
	differentKeys, err := manager.DeriveConversationKeys(differentInvite)
	if err != nil {
		t.Fatalf("Failed to derive keys for different invite: %v", err)
	}
	
	if keysEqual(keys, differentKeys) {
		t.Error("Different invites should produce different keys")
	}
}

func TestManager_ConversationCreation(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identity and invite
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	invite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create test invite: %v", err)
	}
	
	keys, err := manager.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive conversation keys: %v", err)
	}
	
	// Create conversation
	conversation, err := manager.CreateConversation(invite, keys)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	
	// Validate conversation
	if conversation.ID != invite.ConvID {
		t.Error("Conversation ID does not match invite conversation ID")
	}
	
	if conversation.Type != types.ConversationType(invite.Type) {
		t.Error("Conversation type does not match invite type")
	}
	
	if !keysEqual(&conversation.Keys, keys) {
		t.Error("Conversation keys do not match derived keys")
	}
	
	// Verify inviter is a participant
	expectedKeyID := identityMgr.KeyIDFromPublicKey(testIdentity.PublicKey)
	found := false
	for _, participant := range conversation.Participants {
		if participant == expectedKeyID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Inviter should be a participant in the conversation")
	}
}

func TestManager_ParticipantManagement(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	
	// Create test identities
	identity1, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate identity 1: %v", err)
	}
	
	identity2, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate identity 2: %v", err)
	}
	
	// Create conversation
	invite, err := manager.CreateInvite(identity1, types.ConversationTypeGroup)
	if err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}
	
	keys, err := manager.DeriveConversationKeys(invite)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}
	
	conversation, err := manager.CreateConversation(invite, keys)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	
	// Initially, only inviter should be a participant
	if !manager.IsParticipant(conversation, identity1.PublicKey) {
		t.Error("Inviter should be a participant")
	}
	
	if manager.IsParticipant(conversation, identity2.PublicKey) {
		t.Error("Identity2 should not be a participant yet")
	}
	
	// Add second participant
	manager.AddParticipant(conversation, identity2.PublicKey)
	
	// Now both should be participants
	if !manager.IsParticipant(conversation, identity1.PublicKey) {
		t.Error("Identity1 should still be a participant")
	}
	
	if !manager.IsParticipant(conversation, identity2.PublicKey) {
		t.Error("Identity2 should now be a participant")
	}
	
	// Adding the same participant again should not duplicate
	originalCount := len(conversation.Participants)
	manager.AddParticipant(conversation, identity2.PublicKey)
	if len(conversation.Participants) != originalCount {
		t.Error("Adding duplicate participant should not increase count")
	}
}

func TestManager_ValidateInvite(t *testing.T) {
	manager := NewManager()
	
	// Test nil invite
	err := manager.ValidateInvite(nil)
	if err == nil {
		t.Error("ValidateInvite should fail with nil invite")
	}
	
	// Create valid invite for other tests
	identityMgr := identity.NewManager()
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	validInvite, err := manager.CreateInvite(testIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("Failed to create valid invite: %v", err)
	}
	
	// Test valid invite
	err = manager.ValidateInvite(validInvite)
	if err != nil {
		t.Fatalf("ValidateInvite failed for valid invite: %v", err)
	}
	
	// Test invalid version
	invalidVersionInvite := *validInvite
	invalidVersionInvite.Version = 999
	err = manager.ValidateInvite(&invalidVersionInvite)
	if err == nil {
		t.Error("ValidateInvite should fail with invalid version")
	}
	
	// Test invalid suite
	invalidSuiteInvite := *validInvite
	invalidSuiteInvite.Suite = "INVALID-SUITE"
	err = manager.ValidateInvite(&invalidSuiteInvite)
	if err == nil {
		t.Error("ValidateInvite should fail with invalid suite")
	}
	
	// Test invalid conversation type
	invalidTypeInvite := *validInvite
	invalidTypeInvite.Type = "invalid"
	err = manager.ValidateInvite(&invalidTypeInvite)
	if err == nil {
		t.Error("ValidateInvite should fail with invalid conversation type")
	}
	
	// Test invalid public key
	invalidPubkeyInvite := *validInvite
	invalidPubkeyInvite.InviterIKPK = make([]byte, 10) // wrong length
	err = manager.ValidateInvite(&invalidPubkeyInvite)
	if err == nil {
		t.Error("ValidateInvite should fail with invalid public key")
	}
	
	// Test invalid invite secret
	invalidSecretInvite := *validInvite
	invalidSecretInvite.InviteSecret = make([]byte, 10) // wrong length
	err = manager.ValidateInvite(&invalidSecretInvite)
	if err == nil {
		t.Error("ValidateInvite should fail with invalid invite secret")
	}
}

// Helper functions

func invitesEqual(a, b *types.InvitePayload) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	
	return a.Version == b.Version &&
		a.Suite == b.Suite &&
		a.Type == b.Type &&
		a.ConvID == b.ConvID &&
		ed25519.PublicKey(a.InviterIKPK).Equal(b.InviterIKPK) &&
		string(a.InviteSalt) == string(b.InviteSalt) &&
		string(a.InviteSecret) == string(b.InviteSecret)
}

func keysEqual(a, b *types.ConversationKeys) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	
	return string(a.Root) == string(b.Root) &&
		string(a.AEADKey) == string(b.AEADKey) &&
		string(a.NonceKey) == string(b.NonceKey)
}