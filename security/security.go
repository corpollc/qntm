package security

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

// PolicyEnforcer handles security policy enforcement
type PolicyEnforcer struct {
	identityMgr *identity.Manager
	
	// Replay protection
	seenMessages   map[types.ConversationID]map[types.MessageID]bool
	messagesMutex  sync.RWMutex
	
	// Clock skew configuration
	maxFutureSkew time.Duration
	maxPastSkew   time.Duration
	
	// Membership policies
	membershipPolicies map[types.ConversationID]*MembershipPolicy
	policiesMutex      sync.RWMutex
}

// MembershipPolicy defines who can participate in a conversation
type MembershipPolicy struct {
	AllowedMembers map[types.KeyID]bool      `json:"allowed_members"`
	Admins         map[types.KeyID]bool      `json:"admins"`
	RequireAdmin   bool                      `json:"require_admin"`
	MaxMembers     int                       `json:"max_members"`
	InviteOnly     bool                      `json:"invite_only"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	MaxFutureSkewSeconds int64 `json:"max_future_skew_seconds"`
	MaxPastSkewSeconds   int64 `json:"max_past_skew_seconds"`
	EnableReplayProtection bool `json:"enable_replay_protection"`
	EnableClockSkewCheck   bool `json:"enable_clock_skew_check"`
}

// NewPolicyEnforcer creates a new security policy enforcer
func NewPolicyEnforcer(config *SecurityConfig) *PolicyEnforcer {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	
	return &PolicyEnforcer{
		identityMgr:        identity.NewManager(),
		seenMessages:       make(map[types.ConversationID]map[types.MessageID]bool),
		maxFutureSkew:      time.Duration(config.MaxFutureSkewSeconds) * time.Second,
		maxPastSkew:        time.Duration(config.MaxPastSkewSeconds) * time.Second,
		membershipPolicies: make(map[types.ConversationID]*MembershipPolicy),
	}
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxFutureSkewSeconds:   600,  // 10 minutes
		MaxPastSkewSeconds:     3600, // 1 hour
		EnableReplayProtection: true,
		EnableClockSkewCheck:   true,
	}
}

// CheckMessageSecurity performs comprehensive security checks on a message
func (p *PolicyEnforcer) CheckMessageSecurity(
	envelope *types.OuterEnvelope,
	inner *types.InnerPayload,
	conversation *types.Conversation,
) error {
	// Check replay protection
	if err := p.CheckReplayProtection(envelope); err != nil {
		return fmt.Errorf("replay protection failed: %w", err)
	}
	
	// Check clock skew
	if err := p.CheckClockSkew(envelope); err != nil {
		return fmt.Errorf("clock skew check failed: %w", err)
	}
	
	// Check TTL
	if err := p.CheckTTL(envelope); err != nil {
		return fmt.Errorf("TTL check failed: %w", err)
	}
	
	// Check sender identity
	if err := p.CheckSenderIdentity(inner); err != nil {
		return fmt.Errorf("sender identity check failed: %w", err)
	}
	
	// Check membership policy
	if err := p.CheckMembershipPolicy(inner, conversation); err != nil {
		return fmt.Errorf("membership policy check failed: %w", err)
	}
	
	// Mark message as seen for replay protection
	p.MarkMessageSeen(envelope.ConvID, envelope.MsgID)
	
	return nil
}

// CheckReplayProtection checks if a message has already been seen
func (p *PolicyEnforcer) CheckReplayProtection(envelope *types.OuterEnvelope) error {
	p.messagesMutex.RLock()
	convMessages, exists := p.seenMessages[envelope.ConvID]
	if exists {
		if convMessages[envelope.MsgID] {
			p.messagesMutex.RUnlock()
			return fmt.Errorf("message %x already seen (replay attack)", envelope.MsgID[:])
		}
	}
	p.messagesMutex.RUnlock()
	
	return nil
}

// CheckClockSkew validates message timestamp against current time
func (p *PolicyEnforcer) CheckClockSkew(envelope *types.OuterEnvelope) error {
	now := time.Now().Unix()
	createdTime := time.Unix(envelope.CreatedTS, 0)
	currentTime := time.Unix(now, 0)
	
	// Check future skew
	if createdTime.After(currentTime.Add(p.maxFutureSkew)) {
		return fmt.Errorf("message timestamp %d is too far in the future (max skew: %v)", 
			envelope.CreatedTS, p.maxFutureSkew)
	}
	
	// Check past skew  
	if createdTime.Before(currentTime.Add(-p.maxPastSkew)) {
		return fmt.Errorf("message timestamp %d is too old (max age: %v)", 
			envelope.CreatedTS, p.maxPastSkew)
	}
	
	return nil
}

// CheckTTL validates message has not expired
func (p *PolicyEnforcer) CheckTTL(envelope *types.OuterEnvelope) error {
	now := time.Now().Unix()
	if now > envelope.ExpiryTS {
		return fmt.Errorf("message expired at %d (now: %d)", envelope.ExpiryTS, now)
	}
	
	// Verify expiry is after created
	if envelope.ExpiryTS <= envelope.CreatedTS {
		return fmt.Errorf("invalid TTL: expiry %d <= created %d", envelope.ExpiryTS, envelope.CreatedTS)
	}
	
	return nil
}

// CheckSenderIdentity validates sender key ID matches public key
func (p *PolicyEnforcer) CheckSenderIdentity(inner *types.InnerPayload) error {
	// Verify sender key ID matches public key
	if !p.identityMgr.VerifyKeyID(inner.SenderIKPK, inner.SenderKID) {
		return fmt.Errorf("sender key ID %x does not match public key", inner.SenderKID[:])
	}
	
	// Check public key is valid
	if len(inner.SenderIKPK) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid sender public key length: %d", len(inner.SenderIKPK))
	}
	
	return nil
}

// CheckMembershipPolicy validates sender is allowed in the conversation
func (p *PolicyEnforcer) CheckMembershipPolicy(inner *types.InnerPayload, conversation *types.Conversation) error {
	p.policiesMutex.RLock()
	policy, exists := p.membershipPolicies[conversation.ID]
	p.policiesMutex.RUnlock()
	
	// No policy set - allow all participants
	if !exists {
		// Check basic participation
		return p.checkBasicParticipation(inner, conversation)
	}
	
	// Check allowed members
	if len(policy.AllowedMembers) > 0 {
		if !policy.AllowedMembers[inner.SenderKID] {
			return fmt.Errorf("sender %x not in allowed members list", inner.SenderKID[:])
		}
	}
	
	// Check admin requirement for certain operations
	if policy.RequireAdmin {
		if !policy.Admins[inner.SenderKID] {
			return fmt.Errorf("sender %x is not an admin (admin required)", inner.SenderKID[:])
		}
	}
	
	// Check max members (for add operations)
	if policy.MaxMembers > 0 && inner.BodyType == "group_add" {
		currentMemberCount := len(policy.AllowedMembers)
		if currentMemberCount >= policy.MaxMembers {
			return fmt.Errorf("group has reached maximum members (%d)", policy.MaxMembers)
		}
	}
	
	return nil
}

func (p *PolicyEnforcer) checkBasicParticipation(inner *types.InnerPayload, conversation *types.Conversation) error {
	// Check if sender is a known participant in the conversation
	found := false
	for _, participantKID := range conversation.Participants {
		if participantKID == inner.SenderKID {
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("sender %x is not a participant in conversation %x", 
			inner.SenderKID[:], conversation.ID[:])
	}
	
	return nil
}

// MarkMessageSeen records a message as seen for replay protection
func (p *PolicyEnforcer) MarkMessageSeen(convID types.ConversationID, msgID types.MessageID) {
	p.messagesMutex.Lock()
	defer p.messagesMutex.Unlock()
	
	if p.seenMessages[convID] == nil {
		p.seenMessages[convID] = make(map[types.MessageID]bool)
	}
	
	p.seenMessages[convID][msgID] = true
}

// IsMessageSeen checks if a message has been seen before
func (p *PolicyEnforcer) IsMessageSeen(convID types.ConversationID, msgID types.MessageID) bool {
	p.messagesMutex.RLock()
	defer p.messagesMutex.RUnlock()
	
	convMessages, exists := p.seenMessages[convID]
	if !exists {
		return false
	}
	
	return convMessages[msgID]
}

// SetMembershipPolicy sets the membership policy for a conversation
func (p *PolicyEnforcer) SetMembershipPolicy(convID types.ConversationID, policy *MembershipPolicy) {
	p.policiesMutex.Lock()
	defer p.policiesMutex.Unlock()
	
	p.membershipPolicies[convID] = policy
}

// GetMembershipPolicy gets the membership policy for a conversation
func (p *PolicyEnforcer) GetMembershipPolicy(convID types.ConversationID) *MembershipPolicy {
	p.policiesMutex.RLock()
	defer p.policiesMutex.RUnlock()
	
	return p.membershipPolicies[convID]
}

// AddAllowedMember adds a member to the allowed list for a conversation
func (p *PolicyEnforcer) AddAllowedMember(convID types.ConversationID, keyID types.KeyID, isAdmin bool) {
	p.policiesMutex.Lock()
	defer p.policiesMutex.Unlock()
	
	policy := p.membershipPolicies[convID]
	if policy == nil {
		policy = &MembershipPolicy{
			AllowedMembers: make(map[types.KeyID]bool),
			Admins:         make(map[types.KeyID]bool),
		}
		p.membershipPolicies[convID] = policy
	}
	
	policy.AllowedMembers[keyID] = true
	if isAdmin {
		policy.Admins[keyID] = true
	}
}

// RemoveAllowedMember removes a member from the allowed list for a conversation
func (p *PolicyEnforcer) RemoveAllowedMember(convID types.ConversationID, keyID types.KeyID) {
	p.policiesMutex.Lock()
	defer p.policiesMutex.Unlock()
	
	policy := p.membershipPolicies[convID]
	if policy != nil {
		delete(policy.AllowedMembers, keyID)
		delete(policy.Admins, keyID)
	}
}

// CleanupOldMessages removes old seen messages to prevent memory growth
func (p *PolicyEnforcer) CleanupOldMessages(maxAge time.Duration) int {
	p.messagesMutex.Lock()
	defer p.messagesMutex.Unlock()
	
	cleaned := 0
	_ = maxAge // For future use when implementing proper time-based cleanup
	
	// Note: This is a simplified cleanup. In practice, you'd want to store
	// timestamps with the messages to do proper time-based cleanup.
	// For now, we just limit the size per conversation.
	const maxMessagesPerConv = 10000
	
	for convID, messages := range p.seenMessages {
		if len(messages) > maxMessagesPerConv {
			// Keep only the most recent messages (simplified)
			// In practice, you'd use a LRU cache or timestamp-based cleanup
			newMessages := make(map[types.MessageID]bool)
			count := 0
			for msgID, seen := range messages {
				if seen && count < maxMessagesPerConv/2 {
					newMessages[msgID] = true
					count++
				} else {
					cleaned++
				}
			}
			p.seenMessages[convID] = newMessages
		}
	}
	
	return cleaned
}

// GetSecurityStats returns security-related statistics
func (p *PolicyEnforcer) GetSecurityStats() *SecurityStats {
	p.messagesMutex.RLock()
	defer p.messagesMutex.RUnlock()
	
	stats := &SecurityStats{
		ConversationCount: len(p.seenMessages),
		TotalSeenMessages: 0,
	}
	
	for _, messages := range p.seenMessages {
		stats.TotalSeenMessages += len(messages)
	}
	
	p.policiesMutex.RLock()
	stats.PoliciesCount = len(p.membershipPolicies)
	p.policiesMutex.RUnlock()
	
	return stats
}

// SecurityStats holds security-related statistics
type SecurityStats struct {
	ConversationCount int `json:"conversation_count"`
	TotalSeenMessages int `json:"total_seen_messages"`
	PoliciesCount     int `json:"policies_count"`
}

// ValidateSecurityConfig validates security configuration
func ValidateSecurityConfig(config *SecurityConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	
	if config.MaxFutureSkewSeconds < 0 {
		return fmt.Errorf("max future skew cannot be negative")
	}
	
	if config.MaxPastSkewSeconds < 0 {
		return fmt.Errorf("max past skew cannot be negative")
	}
	
	if config.MaxFutureSkewSeconds > 7*24*3600 { // 1 week
		return fmt.Errorf("max future skew is too large (> 1 week)")
	}
	
	if config.MaxPastSkewSeconds > 30*24*3600 { // 30 days
		return fmt.Errorf("max past skew is too large (> 30 days)")
	}
	
	return nil
}