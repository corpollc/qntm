package invite

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// Manager handles invite creation, parsing, and key schedule derivation
type Manager struct {
	suite       *crypto.QSP1Suite
	identityMgr *identity.Manager
}

// NewManager creates a new invite manager
func NewManager() *Manager {
	return &Manager{
		suite:       crypto.NewQSP1Suite(),
		identityMgr: identity.NewManager(),
	}
}

// CreateInvite creates a new conversation invite
func (m *Manager) CreateInvite(inviterIdentity *types.Identity, convType types.ConversationType) (*types.InvitePayload, error) {
	if err := m.identityMgr.ValidateIdentity(inviterIdentity); err != nil {
		return nil, fmt.Errorf("invalid inviter identity: %w", err)
	}
	
	// Generate conversation ID
	convID, err := m.identityMgr.GenerateConversationID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate conversation ID: %w", err)
	}
	
	// Generate invite secret (32 bytes high entropy)
	inviteSecret, err := m.identityMgr.GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite secret: %w", err)
	}
	
	// Generate invite salt (16-32 bytes, using 32 for extra security)
	inviteSalt, err := m.identityMgr.GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite salt: %w", err)
	}
	
	invite := &types.InvitePayload{
		Version:      types.ProtocolVersion,
		Suite:        types.DefaultSuite,
		Type:         string(convType),
		ConvID:       convID,
		InviterIKPK:  inviterIdentity.PublicKey,
		InviteSalt:   inviteSalt,
		InviteSecret: inviteSecret,
	}
	
	return invite, nil
}

// SerializeInvite serializes an invite to canonical CBOR
func (m *Manager) SerializeInvite(invite *types.InvitePayload) ([]byte, error) {
	return cbor.MarshalCanonical(invite)
}

// DeserializeInvite deserializes an invite from canonical CBOR
func (m *Manager) DeserializeInvite(data []byte) (*types.InvitePayload, error) {
	var invite types.InvitePayload
	if err := cbor.UnmarshalCanonical(data, &invite); err != nil {
		return nil, fmt.Errorf("failed to unmarshal invite: %w", err)
	}
	
	// Validate the invite
	if err := m.ValidateInvite(&invite); err != nil {
		return nil, fmt.Errorf("invalid invite: %w", err)
	}
	
	return &invite, nil
}

// ValidateInvite validates the structure and content of an invite
func (m *Manager) ValidateInvite(invite *types.InvitePayload) error {
	if invite == nil {
		return fmt.Errorf("invite is nil")
	}
	
	// Check version
	if invite.Version != types.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %d", invite.Version)
	}
	
	// Check suite
	if invite.Suite != types.DefaultSuite {
		return fmt.Errorf("unsupported crypto suite: %s", invite.Suite)
	}
	
	// Check conversation type
	if invite.Type != string(types.ConversationTypeDirect) && invite.Type != string(types.ConversationTypeGroup) {
		return fmt.Errorf("invalid conversation type: %s", invite.Type)
	}
	
	// Check public key length
	if len(invite.InviterIKPK) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid inviter public key length: %d", len(invite.InviterIKPK))
	}
	
	// Check invite salt length (should be 16-32 bytes)
	if len(invite.InviteSalt) < 16 || len(invite.InviteSalt) > 32 {
		return fmt.Errorf("invalid invite salt length: %d", len(invite.InviteSalt))
	}
	
	// Check invite secret length (must be exactly 32 bytes for security)
	if len(invite.InviteSecret) != 32 {
		return fmt.Errorf("invalid invite secret length: %d", len(invite.InviteSecret))
	}
	
	return nil
}

// InviteToToken encodes an invite as a base64url token string (no URL wrapping).
func (m *Manager) InviteToToken(invite *types.InvitePayload) (string, error) {
	inviteData, err := m.SerializeInvite(invite)
	if err != nil {
		return "", fmt.Errorf("failed to serialize invite: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(inviteData), nil
}

// InviteToURL encodes an invite as a URL with the invite data in the fragment
func (m *Manager) InviteToURL(invite *types.InvitePayload, baseURL string) (string, error) {
	// Serialize the invite
	inviteData, err := m.SerializeInvite(invite)
	if err != nil {
		return "", fmt.Errorf("failed to serialize invite: %w", err)
	}
	
	// Base64 encode for URL safety
	inviteB64 := base64.RawURLEncoding.EncodeToString(inviteData)
	
	// Create URL with invite in fragment to reduce server logging
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	parsedURL.Fragment = inviteB64
	
	return parsedURL.String(), nil
}

// InviteFromURL extracts an invite from a URL fragment
func (m *Manager) InviteFromURL(inviteURL string) (*types.InvitePayload, error) {
	parsedURL, err := url.Parse(inviteURL)
	if err != nil {
		return nil, fmt.Errorf("invalid invite URL: %w", err)
	}
	
	if parsedURL.Fragment == "" {
		return nil, fmt.Errorf("no invite data in URL fragment")
	}
	
	// Decode base64
	inviteData, err := base64.RawURLEncoding.DecodeString(parsedURL.Fragment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invite data: %w", err)
	}
	
	// Deserialize the invite
	return m.DeserializeInvite(inviteData)
}

// DeriveConversationKeys derives conversation keys from an invite
func (m *Manager) DeriveConversationKeys(invite *types.InvitePayload) (*types.ConversationKeys, error) {
	if err := m.ValidateInvite(invite); err != nil {
		return nil, fmt.Errorf("invalid invite: %w", err)
	}
	
	convIDBytes := invite.ConvID[:]
	
	// Derive root key
	rootKey, err := m.suite.DeriveRootKey(invite.InviteSecret, invite.InviteSalt, convIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive root key: %w", err)
	}
	
	// Derive conversation keys
	aeadKey, nonceKey, err := m.suite.DeriveConversationKeys(rootKey, convIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive conversation keys: %w", err)
	}
	
	keys := &types.ConversationKeys{
		Root:     rootKey,
		AEADKey:  aeadKey,
		NonceKey: nonceKey,
	}
	
	return keys, nil
}

// CreateConversation creates a conversation from an invite and keys
func (m *Manager) CreateConversation(invite *types.InvitePayload, keys *types.ConversationKeys) (*types.Conversation, error) {
	if err := m.ValidateInvite(invite); err != nil {
		return nil, fmt.Errorf("invalid invite: %w", err)
	}
	
	// Initial participants include the inviter
	inviterKeyID := m.identityMgr.KeyIDFromPublicKey(invite.InviterIKPK)
	participants := []types.KeyID{inviterKeyID}
	
	conversation := &types.Conversation{
		ID:           invite.ConvID,
		Type:         types.ConversationType(invite.Type),
		Keys:         *keys,
		Participants: participants,
	}
	
	return conversation, nil
}

// AddParticipant adds a participant to a conversation
func (m *Manager) AddParticipant(conv *types.Conversation, pubkey ed25519.PublicKey) {
	keyID := m.identityMgr.KeyIDFromPublicKey(pubkey)
	
	// Check if participant already exists
	for _, existing := range conv.Participants {
		if existing == keyID {
			return // Already a participant
		}
	}
	
	conv.Participants = append(conv.Participants, keyID)
}

// IsParticipant checks if a public key is a participant in the conversation
func (m *Manager) IsParticipant(conv *types.Conversation, pubkey ed25519.PublicKey) bool {
	keyID := m.identityMgr.KeyIDFromPublicKey(pubkey)
	
	for _, participant := range conv.Participants {
		if participant == keyID {
			return true
		}
	}
	
	return false
}

// GenerateInviteSecret generates a high-entropy 32-byte invite secret
func (m *Manager) GenerateInviteSecret() ([]byte, error) {
	return m.identityMgr.GenerateRandomBytes(32)
}

// GenerateInviteSalt generates a random invite salt
func (m *Manager) GenerateInviteSalt() ([]byte, error) {
	return m.identityMgr.GenerateRandomBytes(32)
}