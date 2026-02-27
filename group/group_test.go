package group

import (
	"crypto/ed25519"
	"testing"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

func TestManager_CreateGroup(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create creator identity
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	// Create some founding members
	member1, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member1 identity: %v", err)
	}

	member2, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member2 identity: %v", err)
	}

	foundingMembers := []ed25519.PublicKey{member1.PublicKey, member2.PublicKey}

	// Create group
	conversation, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"A test group for unit testing",
		foundingMembers,
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Verify conversation
	if conversation.Type != types.ConversationTypeGroup {
		t.Errorf("Expected group conversation type, got %v", conversation.Type)
	}

	// Verify group state
	if groupState.GroupName != "Test Group" {
		t.Errorf("Expected group name 'Test Group', got %s", groupState.GroupName)
	}

	if groupState.Description != "A test group for unit testing" {
		t.Errorf("Expected description 'A test group for unit testing', got %s", groupState.Description)
	}

	if groupState.Creator != creator.KeyID {
		t.Error("Creator key ID does not match")
	}

	// Verify membership (creator + 2 founding members = 3 total)
	expectedMemberCount := 3
	if manager.GetMemberCount(groupState) != expectedMemberCount {
		t.Errorf("Expected %d members, got %d", expectedMemberCount, manager.GetMemberCount(groupState))
	}

	// Verify creator is admin
	if !manager.IsAdmin(groupState, creator.KeyID) {
		t.Error("Creator should be an admin")
	}

	// Verify founding members are regular members
	if !manager.IsMember(groupState, member1.KeyID) {
		t.Error("Member1 should be a member")
	}

	if manager.IsAdmin(groupState, member1.KeyID) {
		t.Error("Member1 should not be an admin initially")
	}

	if !manager.IsMember(groupState, member2.KeyID) {
		t.Error("Member2 should be a member")
	}

	// Verify admin count (only creator initially)
	if manager.GetAdminCount(groupState) != 1 {
		t.Errorf("Expected 1 admin, got %d", manager.GetAdminCount(groupState))
	}
}

func TestManager_AddMembers(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group with creator only
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	conversation, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		nil, // No founding members
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Initial member count should be 1 (creator only)
	if manager.GetMemberCount(groupState) != 1 {
		t.Errorf("Expected 1 initial member, got %d", manager.GetMemberCount(groupState))
	}

	// Generate new members to add
	newMember1, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate newMember1 identity: %v", err)
	}

	newMember2, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate newMember2 identity: %v", err)
	}

	newMembers := []ed25519.PublicKey{newMember1.PublicKey, newMember2.PublicKey}

	// Add members
	err = manager.AddMembers(creator, conversation, groupState, newMembers, storage)
	if err != nil {
		t.Fatalf("Failed to add members: %v", err)
	}

	// Verify member count increased
	expectedMemberCount := 3
	if manager.GetMemberCount(groupState) != expectedMemberCount {
		t.Errorf("Expected %d members after adding, got %d", expectedMemberCount, manager.GetMemberCount(groupState))
	}

	// Verify new members are added
	if !manager.IsMember(groupState, newMember1.KeyID) {
		t.Error("NewMember1 should be a member after adding")
	}

	if !manager.IsMember(groupState, newMember2.KeyID) {
		t.Error("NewMember2 should be a member after adding")
	}

	// Verify new members are not admins
	if manager.IsAdmin(groupState, newMember1.KeyID) {
		t.Error("NewMember1 should not be an admin")
	}

	if manager.IsAdmin(groupState, newMember2.KeyID) {
		t.Error("NewMember2 should not be an admin")
	}
}

func TestManager_AddMembersNonAdmin(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	regularMember, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate regular member identity: %v", err)
	}

	conversation, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		[]ed25519.PublicKey{regularMember.PublicKey},
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Try to add members as non-admin (should fail)
	newMember, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate new member identity: %v", err)
	}

	err = manager.AddMembers(regularMember, conversation, groupState, []ed25519.PublicKey{newMember.PublicKey}, storage)
	if err == nil {
		t.Error("Non-admin should not be able to add members")
	}

	// Verify member count unchanged
	if manager.GetMemberCount(groupState) != 2 {
		t.Error("Member count should not have changed")
	}
}

func TestManager_RemoveMembers(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group with multiple members
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	member1, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member1 identity: %v", err)
	}

	member2, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member2 identity: %v", err)
	}

	foundingMembers := []ed25519.PublicKey{member1.PublicKey, member2.PublicKey}

	conversation, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		foundingMembers,
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Initial member count should be 3
	if manager.GetMemberCount(groupState) != 3 {
		t.Errorf("Expected 3 initial members, got %d", manager.GetMemberCount(groupState))
	}

	// Remove member1
	err = manager.RemoveMembers(creator, conversation, groupState, []types.KeyID{member1.KeyID}, "testing removal", storage)
	if err != nil {
		t.Fatalf("Failed to remove member: %v", err)
	}

	// Verify member count decreased
	expectedMemberCount := 2
	if manager.GetMemberCount(groupState) != expectedMemberCount {
		t.Errorf("Expected %d members after removal, got %d", expectedMemberCount, manager.GetMemberCount(groupState))
	}

	// Verify member1 is no longer a member
	if manager.IsMember(groupState, member1.KeyID) {
		t.Error("Member1 should not be a member after removal")
	}

	// Verify member2 is still a member
	if !manager.IsMember(groupState, member2.KeyID) {
		t.Error("Member2 should still be a member")
	}

	// Verify creator is still a member
	if !manager.IsMember(groupState, creator.KeyID) {
		t.Error("Creator should still be a member")
	}
}

func TestManager_CannotRemoveCreator(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	conversation, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		nil,
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Try to remove creator (should not actually remove them)
	err = manager.RemoveMembers(creator, conversation, groupState, []types.KeyID{creator.KeyID}, "self removal", storage)
	if err != nil {
		t.Fatalf("RemoveMembers should not error when trying to remove creator: %v", err)
	}

	// Verify creator is still a member and admin
	if !manager.IsMember(groupState, creator.KeyID) {
		t.Error("Creator should still be a member")
	}

	if !manager.IsAdmin(groupState, creator.KeyID) {
		t.Error("Creator should still be an admin")
	}
}

func TestManager_PromoteToAdmin(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	regularMember, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate regular member identity: %v", err)
	}

	_, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		[]ed25519.PublicKey{regularMember.PublicKey},
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Initially, regular member should not be an admin
	if manager.IsAdmin(groupState, regularMember.KeyID) {
		t.Error("Regular member should not be an admin initially")
	}

	// Admin count should be 1 (creator only)
	if manager.GetAdminCount(groupState) != 1 {
		t.Errorf("Expected 1 admin initially, got %d", manager.GetAdminCount(groupState))
	}

	// Promote regular member to admin
	err = manager.PromoteToAdmin(creator, groupState, regularMember.KeyID)
	if err != nil {
		t.Fatalf("Failed to promote member to admin: %v", err)
	}

	// Verify member is now an admin
	if !manager.IsAdmin(groupState, regularMember.KeyID) {
		t.Error("Regular member should be an admin after promotion")
	}

	// Admin count should be 2
	if manager.GetAdminCount(groupState) != 2 {
		t.Errorf("Expected 2 admins after promotion, got %d", manager.GetAdminCount(groupState))
	}
}

func TestManager_ListMembersAndAdmins(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()

	// Create group with multiple members
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	member1, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member1 identity: %v", err)
	}

	member2, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate member2 identity: %v", err)
	}

	foundingMembers := []ed25519.PublicKey{member1.PublicKey, member2.PublicKey}

	_, groupState, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		foundingMembers,
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// List members
	members := manager.ListMembers(groupState)
	if len(members) != 3 {
		t.Errorf("Expected 3 members in list, got %d", len(members))
	}

	// Verify all members are in the list
	memberMap := make(map[types.KeyID]bool)
	for _, keyID := range members {
		memberMap[keyID] = true
	}

	if !memberMap[creator.KeyID] {
		t.Error("Creator should be in members list")
	}

	if !memberMap[member1.KeyID] {
		t.Error("Member1 should be in members list")
	}

	if !memberMap[member2.KeyID] {
		t.Error("Member2 should be in members list")
	}

	// List admins (should only be creator initially)
	admins := manager.ListAdmins(groupState)
	if len(admins) != 1 {
		t.Errorf("Expected 1 admin in list, got %d", len(admins))
	}

	if admins[0] != creator.KeyID {
		t.Error("Creator should be the only admin initially")
	}

	// Promote member1 and check admin list again
	err = manager.PromoteToAdmin(creator, groupState, member1.KeyID)
	if err != nil {
		t.Fatalf("Failed to promote member1: %v", err)
	}

	admins = manager.ListAdmins(groupState)
	if len(admins) != 2 {
		t.Errorf("Expected 2 admins after promotion, got %d", len(admins))
	}
}

func TestManager_ProcessGroupMessages(t *testing.T) {
	manager := NewManager()
	identityMgr := identity.NewManager()
	storage := dropbox.NewMemoryStorageProvider()
	dropboxMgr := dropbox.NewManager(storage)

	// Create group
	creator, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate creator identity: %v", err)
	}

	conversation, _, err := manager.CreateGroup(
		creator,
		"Test Group",
		"Test group",
		nil,
		storage,
	)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	// Create a fresh group state to simulate receiving messages from scratch
	freshGroupState := &GroupState{
		Members: make(map[types.KeyID]*GroupMemberInfo),
		Admins:  make(map[types.KeyID]bool),
	}

	// Receive and process messages
	seenMessages := make(map[types.MessageID]bool)
	messages, err := dropboxMgr.ReceiveMessages(creator, conversation, seenMessages)
	if err != nil {
		t.Fatalf("Failed to receive messages: %v", err)
	}

	// Should have received the genesis message
	if len(messages) != 1 {
		t.Fatalf("Expected 1 message (genesis), got %d", len(messages))
	}

	// Process genesis message
	err = manager.ProcessGroupMessage(messages[0], freshGroupState)
	if err != nil {
		t.Fatalf("Failed to process genesis message: %v", err)
	}

	// Verify fresh group state was updated from genesis
	if freshGroupState.GroupName != "Test Group" {
		t.Errorf("Expected group name 'Test Group', got %s", freshGroupState.GroupName)
	}

	if freshGroupState.Creator != creator.KeyID {
		t.Error("Creator key ID should be set from genesis")
	}

	if !manager.IsMember(freshGroupState, creator.KeyID) {
		t.Error("Creator should be a member in fresh state")
	}

	if !manager.IsAdmin(freshGroupState, creator.KeyID) {
		t.Error("Creator should be an admin in fresh state")
	}
}
