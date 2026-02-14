package group

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// Manager handles group messaging operations
type Manager struct {
	inviteMgr   *invite.Manager
	messageMgr  *message.Manager
	identityMgr *identity.Manager
}

// NewManager creates a new group messaging manager
func NewManager() *Manager {
	return &Manager{
		inviteMgr:   invite.NewManager(),
		messageMgr:  message.NewManager(),
		identityMgr: identity.NewManager(),
	}
}

// GroupGenesisBody represents the body of a group genesis message
type GroupGenesisBody struct {
	GroupName       string                `cbor:"group_name"`
	Description     string                `cbor:"description,omitempty"`
	CreatedAt       int64                 `cbor:"created_at"`
	FoundingMembers []GroupMemberInfo     `cbor:"founding_members"`
	Metadata        map[string]interface{} `cbor:"metadata,omitempty"`
}

// GroupMemberInfo represents information about a group member
type GroupMemberInfo struct {
	KeyID     types.KeyID       `cbor:"key_id"`
	PublicKey ed25519.PublicKey `cbor:"public_key"`
	Role      string            `cbor:"role"`     // "admin", "member"
	AddedAt   int64             `cbor:"added_at"`
	AddedBy   types.KeyID       `cbor:"added_by"` // Key ID of who added this member
}

// GroupAddBody represents the body of a group add message
type GroupAddBody struct {
	NewMembers []GroupMemberInfo `cbor:"new_members"`
	AddedAt    int64             `cbor:"added_at"`
}

// GroupRemoveBody represents the body of a group remove message
type GroupRemoveBody struct {
	RemovedMembers []types.KeyID `cbor:"removed_members"`
	RemovedAt      int64         `cbor:"removed_at"`
	Reason         string        `cbor:"reason,omitempty"`
}

// GroupState represents the current state of a group
type GroupState struct {
	GroupName   string                   `json:"group_name"`
	Description string                   `json:"description"`
	CreatedAt   int64                    `json:"created_at"`
	Members     map[types.KeyID]*GroupMemberInfo `json:"members"`
	Admins      map[types.KeyID]bool     `json:"admins"`
	Creator     types.KeyID              `json:"creator"`
}

// CreateGroup creates a new group with genesis message
func (m *Manager) CreateGroup(
	creatorIdentity *types.Identity,
	groupName, description string,
	foundingMembers []ed25519.PublicKey,
	storage dropbox.StorageProvider,
) (*types.Conversation, *GroupState, error) {
	if err := m.identityMgr.ValidateIdentity(creatorIdentity); err != nil {
		return nil, nil, fmt.Errorf("invalid creator identity: %w", err)
	}
	
	// Create group invite
	groupInvite, err := m.inviteMgr.CreateInvite(creatorIdentity, types.ConversationTypeGroup)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create group invite: %w", err)
	}
	
	// Derive conversation keys
	keys, err := m.inviteMgr.DeriveConversationKeys(groupInvite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive conversation keys: %w", err)
	}
	
	// Create conversation
	conversation, err := m.inviteMgr.CreateConversation(groupInvite, keys)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create conversation: %w", err)
	}
	
	// Build founding members list
	now := time.Now().Unix()
	creatorKeyID := creatorIdentity.KeyID
	
	var memberInfos []GroupMemberInfo
	
	// Creator is always first and admin
	memberInfos = append(memberInfos, GroupMemberInfo{
		KeyID:     creatorKeyID,
		PublicKey: creatorIdentity.PublicKey,
		Role:      "admin",
		AddedAt:   now,
		AddedBy:   creatorKeyID, // Self-added
	})
	
	// Add founding members as regular members
	for _, pubkey := range foundingMembers {
		keyID := m.identityMgr.KeyIDFromPublicKey(pubkey)
		
		// Skip if already added (duplicate or creator)
		if keyID == creatorKeyID {
			continue
		}
		
		memberInfos = append(memberInfos, GroupMemberInfo{
			KeyID:     keyID,
			PublicKey: pubkey,
			Role:      "member",
			AddedAt:   now,
			AddedBy:   creatorKeyID,
		})
		
		// Add to conversation participants
		m.inviteMgr.AddParticipant(conversation, pubkey)
	}
	
	// Create genesis message body
	genesisBody := GroupGenesisBody{
		GroupName:       groupName,
		Description:     description,
		CreatedAt:       now,
		FoundingMembers: memberInfos,
	}
	
	genesisBodyBytes, err := cbor.MarshalCanonical(genesisBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal genesis body: %w", err)
	}
	
	// Create and send genesis message
	envelope, err := m.messageMgr.CreateMessage(
		creatorIdentity,
		conversation,
		"group_genesis",
		genesisBodyBytes,
		nil,
		m.messageMgr.DefaultTTL(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create genesis message: %w", err)
	}
	
	// Send genesis message
	dropboxMgr := dropbox.NewManager(storage)
	if err := dropboxMgr.SendMessage(envelope); err != nil {
		return nil, nil, fmt.Errorf("failed to send genesis message: %w", err)
	}
	
	// Create initial group state
	groupState := &GroupState{
		GroupName:   groupName,
		Description: description,
		CreatedAt:   now,
		Members:     make(map[types.KeyID]*GroupMemberInfo),
		Admins:      make(map[types.KeyID]bool),
		Creator:     creatorKeyID,
	}
	
	// Add members to state
	for _, member := range memberInfos {
		groupState.Members[member.KeyID] = &member
		if member.Role == "admin" {
			groupState.Admins[member.KeyID] = true
		}
	}
	
	return conversation, groupState, nil
}

// AddMembers adds new members to a group
func (m *Manager) AddMembers(
	adderIdentity *types.Identity,
	conversation *types.Conversation,
	groupState *GroupState,
	newMembers []ed25519.PublicKey,
	storage dropbox.StorageProvider,
) error {
	if err := m.identityMgr.ValidateIdentity(adderIdentity); err != nil {
		return fmt.Errorf("invalid adder identity: %w", err)
	}
	
	// Check if adder is an admin
	if !groupState.Admins[adderIdentity.KeyID] {
		return fmt.Errorf("only admins can add members")
	}
	
	// Build new member info
	now := time.Now().Unix()
	var newMemberInfos []GroupMemberInfo
	
	for _, pubkey := range newMembers {
		keyID := m.identityMgr.KeyIDFromPublicKey(pubkey)
		
		// Skip if already a member
		if _, exists := groupState.Members[keyID]; exists {
			continue
		}
		
		memberInfo := GroupMemberInfo{
			KeyID:     keyID,
			PublicKey: pubkey,
			Role:      "member",
			AddedAt:   now,
			AddedBy:   adderIdentity.KeyID,
		}
		
		newMemberInfos = append(newMemberInfos, memberInfo)
		
		// Add to conversation participants
		m.inviteMgr.AddParticipant(conversation, pubkey)
		
		// Add to group state
		groupState.Members[keyID] = &memberInfo
	}
	
	if len(newMemberInfos) == 0 {
		return nil // No new members to add
	}
	
	// Create group add message
	addBody := GroupAddBody{
		NewMembers: newMemberInfos,
		AddedAt:    now,
	}
	
	addBodyBytes, err := cbor.MarshalCanonical(addBody)
	if err != nil {
		return fmt.Errorf("failed to marshal add body: %w", err)
	}
	
	// Create and send add message
	envelope, err := m.messageMgr.CreateMessage(
		adderIdentity,
		conversation,
		"group_add",
		addBodyBytes,
		nil,
		m.messageMgr.DefaultTTL(),
	)
	if err != nil {
		return fmt.Errorf("failed to create add message: %w", err)
	}
	
	// Send add message
	dropboxMgr := dropbox.NewManager(storage)
	return dropboxMgr.SendMessage(envelope)
}

// RemoveMembers removes members from a group
func (m *Manager) RemoveMembers(
	removerIdentity *types.Identity,
	conversation *types.Conversation,
	groupState *GroupState,
	membersToRemove []types.KeyID,
	reason string,
	storage dropbox.StorageProvider,
) error {
	if err := m.identityMgr.ValidateIdentity(removerIdentity); err != nil {
		return fmt.Errorf("invalid remover identity: %w", err)
	}
	
	// Check if remover is an admin
	if !groupState.Admins[removerIdentity.KeyID] {
		return fmt.Errorf("only admins can remove members")
	}
	
	// Validate members exist
	var validRemovals []types.KeyID
	for _, keyID := range membersToRemove {
		if _, exists := groupState.Members[keyID]; exists {
			// Don't allow removing the creator
			if keyID == groupState.Creator {
				continue
			}
			validRemovals = append(validRemovals, keyID)
		}
	}
	
	if len(validRemovals) == 0 {
		return nil // No valid members to remove
	}
	
	// Create group remove message
	now := time.Now().Unix()
	removeBody := GroupRemoveBody{
		RemovedMembers: validRemovals,
		RemovedAt:      now,
		Reason:         reason,
	}
	
	removeBodyBytes, err := cbor.MarshalCanonical(removeBody)
	if err != nil {
		return fmt.Errorf("failed to marshal remove body: %w", err)
	}
	
	// Create and send remove message
	envelope, err := m.messageMgr.CreateMessage(
		removerIdentity,
		conversation,
		"group_remove",
		removeBodyBytes,
		nil,
		m.messageMgr.DefaultTTL(),
	)
	if err != nil {
		return fmt.Errorf("failed to create remove message: %w", err)
	}
	
	// Send remove message
	dropboxMgr := dropbox.NewManager(storage)
	if err := dropboxMgr.SendMessage(envelope); err != nil {
		return fmt.Errorf("failed to send remove message: %w", err)
	}
	
	// Update group state
	for _, keyID := range validRemovals {
		delete(groupState.Members, keyID)
		delete(groupState.Admins, keyID)
	}
	
	return nil
}

// PromoteToAdmin promotes a member to admin role
func (m *Manager) PromoteToAdmin(
	promoterIdentity *types.Identity,
	groupState *GroupState,
	memberKeyID types.KeyID,
) error {
	if err := m.identityMgr.ValidateIdentity(promoterIdentity); err != nil {
		return fmt.Errorf("invalid promoter identity: %w", err)
	}
	
	// Check if promoter is an admin
	if !groupState.Admins[promoterIdentity.KeyID] {
		return fmt.Errorf("only admins can promote members")
	}
	
	// Check if member exists
	member, exists := groupState.Members[memberKeyID]
	if !exists {
		return fmt.Errorf("member not found")
	}
	
	// Update role
	member.Role = "admin"
	groupState.Admins[memberKeyID] = true
	
	return nil
}

// ProcessGroupMessage processes a received group management message
func (m *Manager) ProcessGroupMessage(
	message *types.Message,
	groupState *GroupState,
) error {
	switch message.Inner.BodyType {
	case "group_genesis":
		return m.processGenesisMessage(message, groupState)
	case "group_add":
		return m.processAddMessage(message, groupState)
	case "group_remove":
		return m.processRemoveMessage(message, groupState)
	default:
		// Not a group management message, ignore
		return nil
	}
}

func (m *Manager) processGenesisMessage(message *types.Message, groupState *GroupState) error {
	var genesisBody GroupGenesisBody
	if err := cbor.UnmarshalCanonical(message.Inner.Body, &genesisBody); err != nil {
		return fmt.Errorf("failed to unmarshal genesis body: %w", err)
	}
	
	// Update group state from genesis
	groupState.GroupName = genesisBody.GroupName
	groupState.Description = genesisBody.Description
	groupState.CreatedAt = genesisBody.CreatedAt
	
	// Add founding members
	for _, member := range genesisBody.FoundingMembers {
		groupState.Members[member.KeyID] = &member
		if member.Role == "admin" {
			groupState.Admins[member.KeyID] = true
		}
	}
	
	// Set creator (first admin)
	for keyID, member := range groupState.Members {
		if member.Role == "admin" {
			groupState.Creator = keyID
			break
		}
	}
	
	return nil
}

func (m *Manager) processAddMessage(message *types.Message, groupState *GroupState) error {
	// Verify sender is an admin
	if !groupState.Admins[message.Inner.SenderKID] {
		return fmt.Errorf("only admins can add members")
	}
	
	var addBody GroupAddBody
	if err := cbor.UnmarshalCanonical(message.Inner.Body, &addBody); err != nil {
		return fmt.Errorf("failed to unmarshal add body: %w", err)
	}
	
	// Add new members to state
	for _, member := range addBody.NewMembers {
		groupState.Members[member.KeyID] = &member
		if member.Role == "admin" {
			groupState.Admins[member.KeyID] = true
		}
	}
	
	return nil
}

func (m *Manager) processRemoveMessage(message *types.Message, groupState *GroupState) error {
	// Verify sender is an admin
	if !groupState.Admins[message.Inner.SenderKID] {
		return fmt.Errorf("only admins can remove members")
	}
	
	var removeBody GroupRemoveBody
	if err := cbor.UnmarshalCanonical(message.Inner.Body, &removeBody); err != nil {
		return fmt.Errorf("failed to unmarshal remove body: %w", err)
	}
	
	// Remove members from state
	for _, keyID := range removeBody.RemovedMembers {
		// Don't allow removing the creator
		if keyID != groupState.Creator {
			delete(groupState.Members, keyID)
			delete(groupState.Admins, keyID)
		}
	}
	
	return nil
}

// IsMember checks if a key ID is a member of the group
func (m *Manager) IsMember(groupState *GroupState, keyID types.KeyID) bool {
	_, exists := groupState.Members[keyID]
	return exists
}

// IsAdmin checks if a key ID is an admin of the group
func (m *Manager) IsAdmin(groupState *GroupState, keyID types.KeyID) bool {
	return groupState.Admins[keyID]
}

// GetMemberCount returns the number of members in the group
func (m *Manager) GetMemberCount(groupState *GroupState) int {
	return len(groupState.Members)
}

// GetAdminCount returns the number of admins in the group
func (m *Manager) GetAdminCount(groupState *GroupState) int {
	return len(groupState.Admins)
}

// ListMembers returns a list of all member key IDs
func (m *Manager) ListMembers(groupState *GroupState) []types.KeyID {
	var members []types.KeyID
	for keyID := range groupState.Members {
		members = append(members, keyID)
	}
	return members
}

// ListAdmins returns a list of all admin key IDs
func (m *Manager) ListAdmins(groupState *GroupState) []types.KeyID {
	var admins []types.KeyID
	for keyID := range groupState.Admins {
		admins = append(admins, keyID)
	}
	return admins
}