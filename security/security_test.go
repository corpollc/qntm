package security

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

func TestNewPolicyEnforcer(t *testing.T) {
	// Test with nil config (should use defaults)
	enforcer := NewPolicyEnforcer(nil)
	if enforcer == nil {
		t.Fatal("NewPolicyEnforcer should not return nil")
	}
	
	// Test with custom config
	config := &SecurityConfig{
		MaxFutureSkewSeconds:   300,  // 5 minutes
		MaxPastSkewSeconds:     1800, // 30 minutes
		EnableReplayProtection: true,
		EnableClockSkewCheck:   true,
	}
	
	customEnforcer := NewPolicyEnforcer(config)
	if customEnforcer == nil {
		t.Fatal("NewPolicyEnforcer should not return nil with custom config")
	}
	
	if customEnforcer.maxFutureSkew != 5*time.Minute {
		t.Errorf("Expected max future skew of 5 minutes, got %v", customEnforcer.maxFutureSkew)
	}
}

func TestPolicyEnforcer_ReplayProtection(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	// Create test envelope
	convID := types.ConversationID{1, 2, 3}
	msgID1 := types.MessageID{4, 5, 6}
	msgID2 := types.MessageID{7, 8, 9}
	
	envelope1 := &types.OuterEnvelope{
		ConvID: convID,
		MsgID:  msgID1,
	}
	
	envelope2 := &types.OuterEnvelope{
		ConvID: convID,
		MsgID:  msgID2,
	}
	
	// First message should pass replay protection
	err := enforcer.CheckReplayProtection(envelope1)
	if err != nil {
		t.Fatalf("First message should pass replay protection: %v", err)
	}
	
	// Mark message as seen
	enforcer.MarkMessageSeen(convID, msgID1)
	
	// Same message should fail replay protection
	err = enforcer.CheckReplayProtection(envelope1)
	if err == nil {
		t.Error("Replay attack should be detected")
	}
	
	// Different message should pass
	err = enforcer.CheckReplayProtection(envelope2)
	if err != nil {
		t.Fatalf("Different message should pass replay protection: %v", err)
	}
	
	// Test IsMessageSeen
	if !enforcer.IsMessageSeen(convID, msgID1) {
		t.Error("Message 1 should be marked as seen")
	}
	
	if enforcer.IsMessageSeen(convID, msgID2) {
		t.Error("Message 2 should not be marked as seen yet")
	}
}

func TestPolicyEnforcer_ClockSkew(t *testing.T) {
	config := &SecurityConfig{
		MaxFutureSkewSeconds: 300,  // 5 minutes
		MaxPastSkewSeconds:   1800, // 30 minutes
	}
	enforcer := NewPolicyEnforcer(config)
	
	now := time.Now().Unix()
	
	// Valid timestamp (current time)
	validEnvelope := &types.OuterEnvelope{
		CreatedTS: now,
		ExpiryTS:  now + 3600,
	}
	
	err := enforcer.CheckClockSkew(validEnvelope)
	if err != nil {
		t.Fatalf("Valid timestamp should pass: %v", err)
	}
	
	// Future timestamp beyond skew limit
	futureEnvelope := &types.OuterEnvelope{
		CreatedTS: now + 600, // 10 minutes in future
		ExpiryTS:  now + 4200,
	}
	
	err = enforcer.CheckClockSkew(futureEnvelope)
	if err == nil {
		t.Error("Future timestamp beyond limit should fail")
	}
	
	// Past timestamp beyond skew limit
	pastEnvelope := &types.OuterEnvelope{
		CreatedTS: now - 2000, // ~33 minutes in past
		ExpiryTS:  now + 1600,
	}
	
	err = enforcer.CheckClockSkew(pastEnvelope)
	if err == nil {
		t.Error("Past timestamp beyond limit should fail")
	}
	
	// Edge cases - exactly at limits
	edgeFutureEnvelope := &types.OuterEnvelope{
		CreatedTS: now + 299, // Just under 5 minutes
		ExpiryTS:  now + 3899,
	}
	
	err = enforcer.CheckClockSkew(edgeFutureEnvelope)
	if err != nil {
		t.Fatalf("Edge case future timestamp should pass: %v", err)
	}
}

func TestPolicyEnforcer_TTL(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	now := time.Now().Unix()
	
	// Valid TTL (not expired)
	validEnvelope := &types.OuterEnvelope{
		CreatedTS: now - 100,
		ExpiryTS:  now + 3500,
	}
	
	err := enforcer.CheckTTL(validEnvelope)
	if err != nil {
		t.Fatalf("Valid TTL should pass: %v", err)
	}
	
	// Expired message
	expiredEnvelope := &types.OuterEnvelope{
		CreatedTS: now - 3700,
		ExpiryTS:  now - 100,
	}
	
	err = enforcer.CheckTTL(expiredEnvelope)
	if err == nil {
		t.Error("Expired message should fail TTL check")
	}
	
	// Invalid TTL (expiry before created)
	invalidEnvelope := &types.OuterEnvelope{
		CreatedTS: now,
		ExpiryTS:  now - 100,
	}
	
	err = enforcer.CheckTTL(invalidEnvelope)
	if err == nil {
		t.Error("Invalid TTL (expiry before created) should fail")
	}
}

func TestPolicyEnforcer_SenderIdentity(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	identityMgr := identity.NewManager()
	
	// Generate valid identity
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}
	
	// Valid inner payload
	validInner := &types.InnerPayload{
		SenderIKPK: testIdentity.PublicKey,
		SenderKID:  testIdentity.KeyID,
		SigAlg:     "Ed25519",
		Signature:  make([]byte, ed25519.SignatureSize),
		BodyType:   "test",
		Body:       []byte("test"),
	}
	
	err = enforcer.CheckSenderIdentity(validInner)
	if err != nil {
		t.Fatalf("Valid sender identity should pass: %v", err)
	}
	
	// Mismatched key ID
	wrongKeyID := types.KeyID{0xFF, 0xFF, 0xFF, 0xFF}
	mismatchedInner := &types.InnerPayload{
		SenderIKPK: testIdentity.PublicKey,
		SenderKID:  wrongKeyID,
		SigAlg:     "Ed25519",
		Signature:  make([]byte, ed25519.SignatureSize),
		BodyType:   "test",
		Body:       []byte("test"),
	}
	
	err = enforcer.CheckSenderIdentity(mismatchedInner)
	if err == nil {
		t.Error("Mismatched key ID should fail sender identity check")
	}
	
	// Invalid public key length
	invalidPubkeyInner := &types.InnerPayload{
		SenderIKPK: make([]byte, 10), // wrong length
		SenderKID:  testIdentity.KeyID,
		SigAlg:     "Ed25519",
		Signature:  make([]byte, ed25519.SignatureSize),
		BodyType:   "test",
		Body:       []byte("test"),
	}
	
	err = enforcer.CheckSenderIdentity(invalidPubkeyInner)
	if err == nil {
		t.Error("Invalid public key length should fail sender identity check")
	}
}

func TestPolicyEnforcer_MembershipPolicy(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	// Create test setup
	conversation, senderIdentity := createSecurityTestSetup(t)
	
	// Valid inner payload
	validInner := &types.InnerPayload{
		SenderIKPK: senderIdentity.PublicKey,
		SenderKID:  senderIdentity.KeyID,
		BodyType:   "text",
		Body:       []byte("test"),
	}
	
	// Test with no policy (should use basic participation check)
	err := enforcer.CheckMembershipPolicy(validInner, conversation)
	if err != nil {
		t.Fatalf("Basic participation check should pass: %v", err)
	}
	
	// Set a restrictive membership policy
	policy := &MembershipPolicy{
		AllowedMembers: map[types.KeyID]bool{
			senderIdentity.KeyID: true,
		},
		Admins:       map[types.KeyID]bool{},
		RequireAdmin: false,
		MaxMembers:   5,
		InviteOnly:   true,
	}
	
	enforcer.SetMembershipPolicy(conversation.ID, policy)
	
	// Should pass with sender in allowed list
	err = enforcer.CheckMembershipPolicy(validInner, conversation)
	if err != nil {
		t.Fatalf("Sender in allowed list should pass: %v", err)
	}
	
	// Test with sender not in allowed list
	unauthorizedIdentity, err := identity.NewManager().GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate unauthorized identity: %v", err)
	}
	
	unauthorizedInner := &types.InnerPayload{
		SenderIKPK: unauthorizedIdentity.PublicKey,
		SenderKID:  unauthorizedIdentity.KeyID,
		BodyType:   "text",
		Body:       []byte("test"),
	}
	
	err = enforcer.CheckMembershipPolicy(unauthorizedInner, conversation)
	if err == nil {
		t.Error("Unauthorized sender should fail membership policy check")
	}
	
	// Test admin requirement
	policy.RequireAdmin = true
	enforcer.SetMembershipPolicy(conversation.ID, policy)
	
	err = enforcer.CheckMembershipPolicy(validInner, conversation)
	if err == nil {
		t.Error("Non-admin should fail when admin is required")
	}
	
	// Add sender as admin
	policy.Admins[senderIdentity.KeyID] = true
	enforcer.SetMembershipPolicy(conversation.ID, policy)
	
	err = enforcer.CheckMembershipPolicy(validInner, conversation)
	if err != nil {
		t.Fatalf("Admin should pass when admin is required: %v", err)
	}
}

func TestPolicyEnforcer_ComprehensiveSecurity(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	// Create test setup
	conversation, senderIdentity := createSecurityTestSetup(t)
	messageMgr := message.NewManager()
	
	// Create a valid message
	envelope, err := messageMgr.CreateMessage(
		senderIdentity,
		conversation,
		"text",
		[]byte("test message"),
		nil,
		3600, // 1 hour TTL
	)
	if err != nil {
		t.Fatalf("Failed to create test message: %v", err)
	}
	
	// Decrypt to get inner payload
	msg, err := messageMgr.DecryptMessage(envelope, conversation)
	if err != nil {
		t.Fatalf("Failed to decrypt test message: %v", err)
	}
	
	// Should pass all security checks
	err = enforcer.CheckMessageSecurity(envelope, msg.Inner, conversation)
	if err != nil {
		t.Fatalf("Valid message should pass all security checks: %v", err)
	}
	
	// Verify message was marked as seen
	if !enforcer.IsMessageSeen(envelope.ConvID, envelope.MsgID) {
		t.Error("Message should be marked as seen after security check")
	}
	
	// Try the same message again (should fail replay protection)
	err = enforcer.CheckMessageSecurity(envelope, msg.Inner, conversation)
	if err == nil {
		t.Error("Replay attack should be detected")
	}
}

func TestPolicyEnforcer_MembershipPolicyManagement(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	convID := types.ConversationID{1, 2, 3}
	keyID1 := types.KeyID{4, 5, 6}
	keyID2 := types.KeyID{7, 8, 9}
	
	// Initially no policy
	policy := enforcer.GetMembershipPolicy(convID)
	if policy != nil {
		t.Error("Initially should have no policy")
	}
	
	// Add allowed member
	enforcer.AddAllowedMember(convID, keyID1, true) // Admin
	enforcer.AddAllowedMember(convID, keyID2, false) // Regular member
	
	// Check policy was created
	policy = enforcer.GetMembershipPolicy(convID)
	if policy == nil {
		t.Fatal("Policy should be created after adding members")
	}
	
	if !policy.AllowedMembers[keyID1] {
		t.Error("KeyID1 should be in allowed members")
	}
	
	if !policy.AllowedMembers[keyID2] {
		t.Error("KeyID2 should be in allowed members")
	}
	
	if !policy.Admins[keyID1] {
		t.Error("KeyID1 should be an admin")
	}
	
	if policy.Admins[keyID2] {
		t.Error("KeyID2 should not be an admin")
	}
	
	// Remove member
	enforcer.RemoveAllowedMember(convID, keyID2)
	
	policy = enforcer.GetMembershipPolicy(convID)
	if policy.AllowedMembers[keyID2] {
		t.Error("KeyID2 should be removed from allowed members")
	}
	
	if policy.Admins[keyID2] {
		t.Error("KeyID2 should be removed from admins")
	}
}

func TestPolicyEnforcer_SecurityStats(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	// Initially empty stats
	stats := enforcer.GetSecurityStats()
	if stats.ConversationCount != 0 {
		t.Error("Initially should have 0 conversations")
	}
	
	if stats.TotalSeenMessages != 0 {
		t.Error("Initially should have 0 seen messages")
	}
	
	// Add some seen messages
	convID1 := types.ConversationID{1}
	convID2 := types.ConversationID{2}
	msgID1 := types.MessageID{1}
	msgID2 := types.MessageID{2}
	msgID3 := types.MessageID{3}
	
	enforcer.MarkMessageSeen(convID1, msgID1)
	enforcer.MarkMessageSeen(convID1, msgID2)
	enforcer.MarkMessageSeen(convID2, msgID3)
	
	stats = enforcer.GetSecurityStats()
	if stats.ConversationCount != 2 {
		t.Errorf("Expected 2 conversations, got %d", stats.ConversationCount)
	}
	
	if stats.TotalSeenMessages != 3 {
		t.Errorf("Expected 3 seen messages, got %d", stats.TotalSeenMessages)
	}
	
	// Add a policy
	enforcer.SetMembershipPolicy(convID1, &MembershipPolicy{})
	
	stats = enforcer.GetSecurityStats()
	if stats.PoliciesCount != 1 {
		t.Errorf("Expected 1 policy, got %d", stats.PoliciesCount)
	}
}

func TestPolicyEnforcer_CleanupOldMessages(t *testing.T) {
	enforcer := NewPolicyEnforcer(nil)
	
	// Add many messages to trigger cleanup
	convID := types.ConversationID{1}
	for i := 0; i < 15000; i++ {
		msgID := types.MessageID{}
		msgID[0] = byte(i % 256)
		msgID[1] = byte((i / 256) % 256)
		enforcer.MarkMessageSeen(convID, msgID)
	}
	
	// Check initial count
	stats := enforcer.GetSecurityStats()
	initialCount := stats.TotalSeenMessages
	
	// Cleanup
	cleaned := enforcer.CleanupOldMessages(24 * time.Hour)
	
	// Should have cleaned some messages
	if cleaned == 0 {
		t.Error("Should have cleaned some messages")
	}
	
	// Check final count
	stats = enforcer.GetSecurityStats()
	if stats.TotalSeenMessages >= initialCount {
		t.Error("Message count should have decreased after cleanup")
	}
}

func TestValidateSecurityConfig(t *testing.T) {
	// Test nil config
	err := ValidateSecurityConfig(nil)
	if err == nil {
		t.Error("Nil config should fail validation")
	}
	
	// Test valid config
	validConfig := DefaultSecurityConfig()
	err = ValidateSecurityConfig(validConfig)
	if err != nil {
		t.Fatalf("Default config should be valid: %v", err)
	}
	
	// Test negative values
	invalidConfig := &SecurityConfig{
		MaxFutureSkewSeconds: -1,
		MaxPastSkewSeconds:   600,
	}
	err = ValidateSecurityConfig(invalidConfig)
	if err == nil {
		t.Error("Negative future skew should fail validation")
	}
	
	invalidConfig.MaxFutureSkewSeconds = 600
	invalidConfig.MaxPastSkewSeconds = -1
	err = ValidateSecurityConfig(invalidConfig)
	if err == nil {
		t.Error("Negative past skew should fail validation")
	}
	
	// Test too large values
	tooLargeConfig := &SecurityConfig{
		MaxFutureSkewSeconds: 8 * 24 * 3600, // > 1 week
		MaxPastSkewSeconds:   600,
	}
	err = ValidateSecurityConfig(tooLargeConfig)
	if err == nil {
		t.Error("Too large future skew should fail validation")
	}
	
	tooLargeConfig.MaxFutureSkewSeconds = 600
	tooLargeConfig.MaxPastSkewSeconds = 31 * 24 * 3600 // > 30 days
	err = ValidateSecurityConfig(tooLargeConfig)
	if err == nil {
		t.Error("Too large past skew should fail validation")
	}
}

// Helper function to create test setup
func createSecurityTestSetup(t *testing.T) (*types.Conversation, *types.Identity) {
	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	
	// Create sender identity
	senderIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate sender identity: %v", err)
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
	
	return conversation, senderIdentity
}