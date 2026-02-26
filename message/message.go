package message

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// Manager handles message creation, encryption, decryption, and verification
type Manager struct {
	suite       *crypto.QSP1Suite
	identityMgr *identity.Manager
}

// NewManager creates a new message manager
func NewManager() *Manager {
	return &Manager{
		suite:       crypto.NewQSP1Suite(),
		identityMgr: identity.NewManager(),
	}
}

// CreateMessage creates a new encrypted message envelope
func (m *Manager) CreateMessage(
	senderIdentity *types.Identity,
	conversation *types.Conversation,
	bodyType string,
	body []byte,
	refs []interface{},
	ttlSeconds int64,
) (*types.OuterEnvelope, error) {
	if err := m.identityMgr.ValidateIdentity(senderIdentity); err != nil {
		return nil, fmt.Errorf("invalid sender identity: %w", err)
	}

	// Generate message ID
	msgID, err := m.identityMgr.GenerateMessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate message ID: %w", err)
	}

	now := time.Now().Unix()
	expiryTS := now + ttlSeconds

	// Create inner payload structure for signing
	bodyStruct := struct {
		BodyType string        `cbor:"body_type"`
		Body     []byte        `cbor:"body"`
		Refs     []interface{} `cbor:"refs,omitempty"`
	}{
		BodyType: bodyType,
		Body:     body,
		Refs:     refs,
	}

	bodyStructBytes, err := cbor.MarshalCanonical(bodyStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body struct: %w", err)
	}

	bodyHash := m.suite.Hash(bodyStructBytes)

	// Create signable structure
	signable := types.Signable{
		Proto:     crypto.ProtoPrefix,
		Suite:     types.DefaultSuite,
		ConvID:    conversation.ID,
		MsgID:     msgID,
		CreatedTS: now,
		ExpiryTS:  expiryTS,
		SenderKID: senderIdentity.KeyID,
		BodyHash:  bodyHash,
	}

	// Sign the message
	signableBytes, err := cbor.MarshalCanonical(signable)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signable: %w", err)
	}

	signature, err := m.suite.Sign(senderIdentity.PrivateKey, signableBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Create inner payload
	innerPayload := types.InnerPayload{
		SenderIKPK: senderIdentity.PublicKey,
		SenderKID:  senderIdentity.KeyID,
		BodyType:   bodyType,
		Body:       body,
		Refs:       refs,
		SigAlg:     "Ed25519",
		Signature:  signature,
	}

	// Serialize inner payload for encryption
	innerPayloadBytes, err := cbor.MarshalCanonical(innerPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inner payload: %w", err)
	}

	// Create AAD structure
	aadStruct := types.AADStruct{
		Version:   types.ProtocolVersion,
		Suite:     types.DefaultSuite,
		ConvID:    conversation.ID,
		MsgID:     msgID,
		CreatedTS: now,
		ExpiryTS:  expiryTS,
		ConvEpoch: conversation.CurrentEpoch,
	}

	aadBytes, err := cbor.MarshalCanonical(aadStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AAD: %w", err)
	}

	// Derive nonce for this message
	nonce, err := m.suite.DeriveNonce(conversation.Keys.NonceKey, msgID[:])
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce: %w", err)
	}

	// Encrypt inner payload
	ciphertext, err := m.suite.Encrypt(conversation.Keys.AEADKey, nonce, innerPayloadBytes, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt inner payload: %w", err)
	}

	// Compute AAD hash for optimization
	aadHash := m.suite.Hash(aadBytes)

	// Create outer envelope
	envelope := &types.OuterEnvelope{
		Version:    types.ProtocolVersion,
		Suite:      types.DefaultSuite,
		ConvID:     conversation.ID,
		MsgID:      msgID,
		CreatedTS:  now,
		ExpiryTS:   expiryTS,
		ConvEpoch:  conversation.CurrentEpoch,
		Ciphertext: ciphertext,
		AADHash:    aadHash,
	}

	return envelope, nil
}

// DecryptMessage decrypts and verifies a message envelope
func (m *Manager) DecryptMessage(
	envelope *types.OuterEnvelope,
	conversation *types.Conversation,
) (*types.Message, error) {
	if err := m.ValidateEnvelope(envelope); err != nil {
		return nil, fmt.Errorf("invalid envelope: %w", err)
	}

	// Check if message has expired
	if time.Now().Unix() > envelope.ExpiryTS {
		return nil, fmt.Errorf("message has expired")
	}

	// Check conversation ID matches
	if envelope.ConvID != conversation.ID {
		return nil, fmt.Errorf("conversation ID mismatch")
	}

	// Reconstruct AAD structure
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
		return nil, fmt.Errorf("failed to marshal AAD for decryption: %w", err)
	}

	// Verify AAD hash if present (optimization check)
	if len(envelope.AADHash) > 0 {
		computedAADHash := m.suite.Hash(aadBytes)
		if string(envelope.AADHash) != string(computedAADHash) {
			return nil, fmt.Errorf("AAD hash mismatch")
		}
	}

	// Derive nonce
	nonce, err := m.suite.DeriveNonce(conversation.Keys.NonceKey, envelope.MsgID[:])
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce for decryption: %w", err)
	}

	// Decrypt inner payload
	innerPayloadBytes, err := m.suite.Decrypt(conversation.Keys.AEADKey, nonce, envelope.Ciphertext, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	// Deserialize inner payload
	var innerPayload types.InnerPayload
	if err := cbor.UnmarshalCanonical(innerPayloadBytes, &innerPayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner payload: %w", err)
	}

	if err := m.ValidateInnerPayload(&innerPayload); err != nil {
		return nil, fmt.Errorf("invalid inner payload: %w", err)
	}

	// Verify the signature
	verified, err := m.VerifyMessageSignature(envelope, &innerPayload)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if !verified {
		return nil, fmt.Errorf("invalid message signature")
	}

	// Verify sender key ID matches public key
	if !m.identityMgr.VerifyKeyID(innerPayload.SenderIKPK, innerPayload.SenderKID) {
		return nil, fmt.Errorf("sender key ID does not match public key")
	}

	message := &types.Message{
		Envelope: envelope,
		Inner:    &innerPayload,
		Verified: verified,
	}

	return message, nil
}

// VerifyMessageSignature verifies the signature inside a decrypted message
func (m *Manager) VerifyMessageSignature(
	envelope *types.OuterEnvelope,
	innerPayload *types.InnerPayload,
) (bool, error) {
	// Reconstruct body structure for hashing
	bodyStruct := struct {
		BodyType string        `cbor:"body_type"`
		Body     []byte        `cbor:"body"`
		Refs     []interface{} `cbor:"refs,omitempty"`
	}{
		BodyType: innerPayload.BodyType,
		Body:     innerPayload.Body,
		Refs:     innerPayload.Refs,
	}

	bodyStructBytes, err := cbor.MarshalCanonical(bodyStruct)
	if err != nil {
		return false, fmt.Errorf("failed to marshal body struct for verification: %w", err)
	}

	bodyHash := m.suite.Hash(bodyStructBytes)

	// Reconstruct signable structure
	signable := types.Signable{
		Proto:     crypto.ProtoPrefix,
		Suite:     envelope.Suite,
		ConvID:    envelope.ConvID,
		MsgID:     envelope.MsgID,
		CreatedTS: envelope.CreatedTS,
		ExpiryTS:  envelope.ExpiryTS,
		SenderKID: innerPayload.SenderKID,
		BodyHash:  bodyHash,
	}

	signableBytes, err := cbor.MarshalCanonical(signable)
	if err != nil {
		return false, fmt.Errorf("failed to marshal signable for verification: %w", err)
	}

	// Verify signature
	err = m.suite.Verify(innerPayload.SenderIKPK, signableBytes, innerPayload.Signature)
	if err != nil {
		return false, nil // Signature verification failed, but no error in the process
	}

	return true, nil
}

// ValidateEnvelope validates the structure of an outer envelope
func (m *Manager) ValidateEnvelope(envelope *types.OuterEnvelope) error {
	if envelope == nil {
		return fmt.Errorf("envelope is nil")
	}

	// Check version
	if envelope.Version != types.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %d", envelope.Version)
	}

	// Check suite
	if envelope.Suite != types.DefaultSuite {
		return fmt.Errorf("unsupported crypto suite: %s", envelope.Suite)
	}

	// Check timestamps
	if envelope.CreatedTS <= 0 {
		return fmt.Errorf("invalid created timestamp: %d", envelope.CreatedTS)
	}

	if envelope.ExpiryTS <= envelope.CreatedTS {
		return fmt.Errorf("expiry timestamp must be after created timestamp")
	}

	// Check ciphertext is not empty
	if len(envelope.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is empty")
	}

	// Check for future timestamp (allow some clock skew)
	maxFutureSkew := int64(600) // 10 minutes
	if envelope.CreatedTS > time.Now().Unix()+maxFutureSkew {
		return fmt.Errorf("message created timestamp is too far in the future")
	}

	return nil
}

// ValidateInnerPayload validates the structure of an inner payload
func (m *Manager) ValidateInnerPayload(inner *types.InnerPayload) error {
	if inner == nil {
		return fmt.Errorf("inner payload is nil")
	}

	// Check sender public key length
	if len(inner.SenderIKPK) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid sender public key length: %d", len(inner.SenderIKPK))
	}

	// Check signature algorithm
	if inner.SigAlg != "Ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", inner.SigAlg)
	}

	// Check signature length
	if len(inner.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d", len(inner.Signature))
	}

	// Check body type is not empty
	if inner.BodyType == "" {
		return fmt.Errorf("body type is empty")
	}

	return nil
}

// SerializeEnvelope serializes an envelope to canonical CBOR
func (m *Manager) SerializeEnvelope(envelope *types.OuterEnvelope) ([]byte, error) {
	return cbor.MarshalCanonical(envelope)
}

// DeserializeEnvelope deserializes an envelope from canonical CBOR
func (m *Manager) DeserializeEnvelope(data []byte) (*types.OuterEnvelope, error) {
	var envelope types.OuterEnvelope
	if err := cbor.UnmarshalCanonical(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal envelope: %w", err)
	}

	if err := m.ValidateEnvelope(&envelope); err != nil {
		return nil, fmt.Errorf("invalid envelope: %w", err)
	}

	return &envelope, nil
}

// CheckExpiry checks if a message has expired
func (m *Manager) CheckExpiry(envelope *types.OuterEnvelope) bool {
	return time.Now().Unix() > envelope.ExpiryTS
}

// DefaultTTL returns a default TTL in seconds (30 days as per spec appendix)
func (m *Manager) DefaultTTL() int64 {
	return 30 * 24 * 60 * 60 // 30 days
}

// DefaultHandshakeTTL returns a default TTL for handshake messages (7 days as per spec appendix)
func (m *Manager) DefaultHandshakeTTL() int64 {
	return 7 * 24 * 60 * 60 // 7 days
}
