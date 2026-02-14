package group

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// GroupRekeyBody represents the body of a group_rekey message (§1.3)
type GroupRekeyBody struct {
	NewConvEpoch uint                     `cbor:"new_conv_epoch"`
	WrappedKeys  map[string][]byte        `cbor:"wrapped_keys"` // kid (base64url) → wrapped blob
}

// RekeyMemberInfo holds the public key and kid for a recipient during rekey
type RekeyMemberInfo struct {
	KeyID     types.KeyID
	PublicKey ed25519.PublicKey
}

// CreateRekey generates a rekey message that rotates the group key to epoch N+1.
// The newGroupKey is wrapped for each member in `members`. Members not in the list are excluded.
func (m *Manager) CreateRekey(
	senderIdentity *types.Identity,
	conversation *types.Conversation,
	groupState *GroupState,
	members []RekeyMemberInfo, // Members to include in the new epoch
	storage dropbox.StorageProvider,
) (*types.OuterEnvelope, []byte, error) { // returns envelope, newGroupKey, error
	if err := m.identityMgr.ValidateIdentity(senderIdentity); err != nil {
		return nil, nil, fmt.Errorf("invalid sender identity: %w", err)
	}

	// Verify sender is a member
	if !m.IsMember(groupState, senderIdentity.KeyID) {
		return nil, nil, fmt.Errorf("sender is not a group member")
	}

	if len(members) > types.MaxGroupSize {
		return nil, nil, fmt.Errorf("group size exceeds maximum of %d", types.MaxGroupSize)
	}

	suite := crypto.NewQSP1Suite()

	// Generate new group key
	newGroupKey, err := suite.GenerateGroupKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new group key: %w", err)
	}

	newEpoch := conversation.CurrentEpoch + 1

	// Wrap key for each recipient
	wrappedKeys := make(map[string][]byte)
	for _, member := range members {
		kidStr, _ := member.KeyID.MarshalText()
		wrapped, err := suite.WrapKeyForRecipient(newGroupKey, member.PublicKey, member.KeyID, conversation.ID[:])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to wrap key for %s: %w", string(kidStr), err)
		}
		wrappedKeys[string(kidStr)] = wrapped
	}

	// Create rekey body
	rekeyBody := GroupRekeyBody{
		NewConvEpoch: newEpoch,
		WrappedKeys:  wrappedKeys,
	}

	rekeyBodyBytes, err := cbor.MarshalCanonical(rekeyBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal rekey body: %w", err)
	}

	// Create and send the rekey message (encrypted under current/old epoch)
	envelope, err := m.messageMgr.CreateMessage(
		senderIdentity,
		conversation,
		"group_rekey",
		rekeyBodyBytes,
		nil,
		m.messageMgr.DefaultTTL(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create rekey message: %w", err)
	}

	// Send via storage
	dropboxMgr := dropbox.NewManager(storage)
	if err := dropboxMgr.SendMessage(envelope); err != nil {
		return nil, nil, fmt.Errorf("failed to send rekey message: %w", err)
	}

	return envelope, newGroupKey, nil
}

// ProcessRekeyMessage processes a received group_rekey message.
// Returns the new group key if the recipient is included, or an error.
func (m *Manager) ProcessRekeyMessage(
	message *types.Message,
	conversation *types.Conversation,
	recipientIdentity *types.Identity,
) (newGroupKey []byte, newEpoch uint, err error) {
	if message.Inner.BodyType != "group_rekey" {
		return nil, 0, fmt.Errorf("not a group_rekey message")
	}

	var rekeyBody GroupRekeyBody
	if err := cbor.UnmarshalCanonical(message.Inner.Body, &rekeyBody); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal rekey body: %w", err)
	}

	// Verify new epoch is N+1
	if rekeyBody.NewConvEpoch != conversation.CurrentEpoch+1 {
		return nil, 0, fmt.Errorf("invalid new epoch: expected %d, got %d",
			conversation.CurrentEpoch+1, rekeyBody.NewConvEpoch)
	}

	// Look up own kid in wrapped_keys
	kidStr, _ := recipientIdentity.KeyID.MarshalText()
	wrappedBlob, exists := rekeyBody.WrappedKeys[string(kidStr)]
	if !exists {
		return nil, 0, fmt.Errorf("recipient excluded from rekey")
	}

	// Unwrap
	suite := crypto.NewQSP1Suite()
	newKey, err := suite.UnwrapKeyForRecipient(wrappedBlob, recipientIdentity.PrivateKey, recipientIdentity.KeyID, conversation.ID[:])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unwrap new group key: %w", err)
	}

	return newKey, rekeyBody.NewConvEpoch, nil
}

// ApplyRekey updates a conversation's keys to a new epoch.
// Old keys are retained for the grace period.
func (m *Manager) ApplyRekey(conversation *types.Conversation, newGroupKey []byte, newEpoch uint) error {
	suite := crypto.NewQSP1Suite()

	// Derive new epoch keys
	aeadKey, nonceKey, err := suite.DeriveEpochKeys(newGroupKey, conversation.ID[:], newEpoch)
	if err != nil {
		return fmt.Errorf("failed to derive epoch keys: %w", err)
	}

	// Save current keys as old epoch keys with grace period
	now := time.Now().Unix()
	oldEpochKeys := types.EpochKeys{
		Epoch:     conversation.CurrentEpoch,
		GroupKey:  conversation.Keys.Root,
		AEADKey:   conversation.Keys.AEADKey,
		NonceKey:  conversation.Keys.NonceKey,
		ExpiresAt: now + types.EpochGracePeriodSeconds,
	}
	conversation.EpochKeys = append(conversation.EpochKeys, oldEpochKeys)

	// Prune expired epoch keys
	var active []types.EpochKeys
	for _, ek := range conversation.EpochKeys {
		if ek.ExpiresAt > now {
			active = append(active, ek)
		}
	}
	conversation.EpochKeys = active

	// Update to new epoch
	conversation.CurrentEpoch = newEpoch
	conversation.Keys.Root = newGroupKey
	conversation.Keys.AEADKey = aeadKey
	conversation.Keys.NonceKey = nonceKey

	return nil
}

// RemoveMembersWithRekey removes members and issues a rekey excluding them.
func (m *Manager) RemoveMembersWithRekey(
	removerIdentity *types.Identity,
	conversation *types.Conversation,
	groupState *GroupState,
	membersToRemove []types.KeyID,
	reason string,
	storage dropbox.StorageProvider,
) error {
	// First send the group_remove message
	if err := m.RemoveMembers(removerIdentity, conversation, groupState, membersToRemove, reason, storage); err != nil {
		return fmt.Errorf("failed to send remove message: %w", err)
	}

	// Build remaining members list for rekey
	removedSet := make(map[types.KeyID]bool)
	for _, kid := range membersToRemove {
		removedSet[kid] = true
	}

	var remainingMembers []RekeyMemberInfo
	for kid, member := range groupState.Members {
		if !removedSet[kid] {
			remainingMembers = append(remainingMembers, RekeyMemberInfo{
				KeyID:     kid,
				PublicKey: member.PublicKey,
			})
		}
	}

	// Issue rekey excluding removed members
	_, newGroupKey, err := m.CreateRekey(removerIdentity, conversation, groupState, remainingMembers, storage)
	if err != nil {
		return fmt.Errorf("failed to create rekey: %w", err)
	}

	// Apply rekey locally
	if err := m.ApplyRekey(conversation, newGroupKey, conversation.CurrentEpoch+1); err != nil {
		return fmt.Errorf("failed to apply rekey: %w", err)
	}

	return nil
}

// AddMembersWithRekey adds members and issues a rekey including them.
func (m *Manager) AddMembersWithRekey(
	adderIdentity *types.Identity,
	conversation *types.Conversation,
	groupState *GroupState,
	newMembers []ed25519.PublicKey,
	storage dropbox.StorageProvider,
) error {
	// First send the group_add message
	if err := m.AddMembers(adderIdentity, conversation, groupState, newMembers, storage); err != nil {
		return fmt.Errorf("failed to send add message: %w", err)
	}

	// Build full member list for rekey (existing + new)
	var allMembers []RekeyMemberInfo
	for kid, member := range groupState.Members {
		allMembers = append(allMembers, RekeyMemberInfo{
			KeyID:     kid,
			PublicKey: member.PublicKey,
		})
		_ = kid // already used in struct
	}

	// Issue rekey with all members
	_, newGroupKey, err := m.CreateRekey(adderIdentity, conversation, groupState, allMembers, storage)
	if err != nil {
		return fmt.Errorf("failed to create rekey: %w", err)
	}

	// Apply rekey locally
	if err := m.ApplyRekey(conversation, newGroupKey, conversation.CurrentEpoch+1); err != nil {
		return fmt.Errorf("failed to apply rekey: %w", err)
	}

	return nil
}

// ResolveRekeyConflict implements §1.8: given multiple rekey envelopes targeting the same epoch,
// returns the canonical one (lowest msg_id lexicographically).
func ResolveRekeyConflict(envelopes []*types.OuterEnvelope) *types.OuterEnvelope {
	if len(envelopes) == 0 {
		return nil
	}
	winner := envelopes[0]
	for _, env := range envelopes[1:] {
		if bytes.Compare(env.MsgID[:], winner.MsgID[:]) < 0 {
			winner = env
		}
	}
	return winner
}
