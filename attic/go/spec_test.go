// Package qntm_test contains protocol specification tests that document every type,
// action, response, and wire format in the qntm system. These tests serve as the
// canonical reference for implementing clients in other languages (e.g. TypeScript).
//
// Each test section corresponds to a protocol component and validates:
// - Type construction and field semantics
// - Serialization format (CBOR for wire, JSON for APIs)
// - Cryptographic operations and their inputs/outputs
// - Error conditions and edge cases
//
// A conforming client MUST pass equivalent tests.
package qntm_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

// acceptInvite derives keys and creates a conversation from an invite (helper)
func acceptInvite(t *testing.T, inviteMgr *invite.Manager, inv *types.InvitePayload) *types.Conversation {
	t.Helper()
	keys, err := inviteMgr.DeriveConversationKeys(inv)
	if err != nil {
		t.Fatal(err)
	}
	conv, err := inviteMgr.CreateConversation(inv, keys)
	if err != nil {
		t.Fatal(err)
	}
	return conv
}

// =============================================================================
// Section 1: Core Types — fixed-size identifiers and their encoding
// =============================================================================

func TestSpec_KeyID_Base64URLEncoding(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	pub, _, err := suite.GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	kid := suite.ComputeKeyID(pub)

	// KeyID is Trunc16(SHA-256(pubkey))
	h := sha256.Sum256(pub)
	var expected types.KeyID
	copy(expected[:], h[:16])
	if kid != expected {
		t.Fatalf("KeyID mismatch: got %x, want %x", kid, expected)
	}

	// Text marshaling uses base64url no-padding (RFC 4648 §5)
	var typedKID types.KeyID
	copy(typedKID[:], kid[:])
	text, err := typedKID.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(kid[:])
	if string(text) != encoded {
		t.Fatalf("MarshalText: got %q, want %q", string(text), encoded)
	}

	// Round-trip
	var decoded types.KeyID
	if err := decoded.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if decoded != typedKID {
		t.Fatal("KeyID round-trip failed")
	}
}

func TestSpec_KeyID_InvalidLength(t *testing.T) {
	var kid types.KeyID
	// Too short
	short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	if err := kid.UnmarshalText([]byte(short)); err == nil {
		t.Fatal("expected error for short KeyID")
	}
}

func TestSpec_ConversationID_Is16Bytes(t *testing.T) {
	var cid types.ConversationID
	if len(cid) != 16 {
		t.Fatalf("ConversationID should be 16 bytes, got %d", len(cid))
	}
}

func TestSpec_MessageID_Is16Bytes(t *testing.T) {
	var mid types.MessageID
	if len(mid) != 16 {
		t.Fatalf("MessageID should be 16 bytes, got %d", len(mid))
	}
}

func TestSpec_ProtocolConstants(t *testing.T) {
	if types.ProtocolVersion != 1 {
		t.Fatalf("ProtocolVersion: got %d, want 1", types.ProtocolVersion)
	}
	if types.DefaultSuite != "QSP-1" {
		t.Fatalf("DefaultSuite: got %q, want %q", types.DefaultSuite, "QSP-1")
	}
	if types.MaxGroupSize != 128 {
		t.Fatalf("MaxGroupSize: got %d, want 128", types.MaxGroupSize)
	}
	if types.EpochGracePeriodSeconds != 86400 {
		t.Fatalf("EpochGracePeriodSeconds: got %d, want 86400", types.EpochGracePeriodSeconds)
	}
}

func TestSpec_ConversationTypes(t *testing.T) {
	tests := []struct {
		ct   types.ConversationType
		want string
	}{
		{types.ConversationTypeDirect, "direct"},
		{types.ConversationTypeGroup, "group"},
		{types.ConversationTypeAnnounce, "announce"},
	}
	for _, tt := range tests {
		if string(tt.ct) != tt.want {
			t.Errorf("ConversationType: got %q, want %q", tt.ct, tt.want)
		}
	}
}

// =============================================================================
// Section 2: Identity — key generation, serialization, and KeyID derivation
// =============================================================================

func TestSpec_Identity_Generation(t *testing.T) {
	mgr := identity.NewManager()
	id, err := mgr.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 key sizes
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey: got %d bytes, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("PrivateKey: got %d bytes, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}

	// KeyID is derived from public key
	suite := crypto.NewQSP1Suite()
	expectedKID := suite.ComputeKeyID(id.PublicKey)
	if id.KeyID != expectedKID {
		t.Fatal("KeyID not derived from public key")
	}
}

func TestSpec_Identity_Serialization_CBOR(t *testing.T) {
	mgr := identity.NewManager()
	id, _ := mgr.GenerateIdentity()

	// Serialize
	data, err := mgr.SerializeIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("serialized identity should not be empty")
	}

	// Deserialize
	restored, err := mgr.DeserializeIdentity(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(id.PublicKey, restored.PublicKey) {
		t.Fatal("PublicKey mismatch after round-trip")
	}
	if !bytes.Equal(id.PrivateKey, restored.PrivateKey) {
		t.Fatal("PrivateKey mismatch after round-trip")
	}
	if id.KeyID != restored.KeyID {
		t.Fatal("KeyID mismatch after round-trip")
	}
}

func TestSpec_Identity_Uniqueness(t *testing.T) {
	mgr := identity.NewManager()
	id1, _ := mgr.GenerateIdentity()
	id2, _ := mgr.GenerateIdentity()

	if bytes.Equal(id1.PublicKey, id2.PublicKey) {
		t.Fatal("two generated identities should have different public keys")
	}
	if id1.KeyID == id2.KeyID {
		t.Fatal("two generated identities should have different KeyIDs")
	}
}

func TestSpec_Identity_KeyID_Derivation(t *testing.T) {
	// Deterministic: same pubkey always yields same KID
	suite := crypto.NewQSP1Suite()
	pub, _, _ := suite.GenerateIdentityKey()
	kid1 := suite.ComputeKeyID(pub)
	kid2 := suite.ComputeKeyID(pub)
	if kid1 != kid2 {
		t.Fatal("KeyID derivation should be deterministic")
	}
}

// =============================================================================
// Section 3: Cryptographic Suite (QSP-1)
// =============================================================================

func TestSpec_Suite_Name(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	if suite.Name() != "QSP-1" {
		t.Fatalf("suite name: got %q, want %q", suite.Name(), "QSP-1")
	}
}

func TestSpec_Suite_Ed25519_SignVerify(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	pub, priv, _ := suite.GenerateIdentityKey()

	msg := []byte("test message for signing")
	sig, err := suite.Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Signature is 64 bytes (Ed25519)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// Valid signature
	if err := suite.Verify(pub, msg, sig); err != nil {
		t.Fatal("valid signature rejected:", err)
	}

	// Wrong key
	pub2, _, _ := suite.GenerateIdentityKey()
	if err := suite.Verify(pub2, msg, sig); err == nil {
		t.Fatal("wrong key should fail verification")
	}

	// Tampered message
	if err := suite.Verify(pub, []byte("tampered"), sig); err == nil {
		t.Fatal("tampered message should fail verification")
	}

	// Tampered signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if err := suite.Verify(pub, msg, badSig); err == nil {
		t.Fatal("tampered signature should fail verification")
	}
}

func TestSpec_Suite_XChaCha20Poly1305_EncryptDecrypt(t *testing.T) {
	suite := crypto.NewQSP1Suite()

	// Key: 32 bytes, Nonce: 24 bytes (XChaCha20)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := [24]byte{}
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}

	plaintext := []byte("secret message content")
	aad := []byte("additional authenticated data")

	ciphertext, err := suite.Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Ciphertext is longer than plaintext (Poly1305 tag = 16 bytes)
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext length: got %d, want %d", len(ciphertext), len(plaintext)+16)
	}

	// Decrypt
	decrypted, err := suite.Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted text mismatch")
	}

	// Wrong key fails
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	if _, err := suite.Decrypt(wrongKey, nonce, ciphertext, aad); err == nil {
		t.Fatal("wrong key should fail decryption")
	}

	// Tampered AAD fails
	if _, err := suite.Decrypt(key, nonce, ciphertext, []byte("wrong aad")); err == nil {
		t.Fatal("wrong AAD should fail decryption")
	}

	// Tampered ciphertext fails
	badCT := make([]byte, len(ciphertext))
	copy(badCT, ciphertext)
	badCT[0] ^= 0xFF
	if _, err := suite.Decrypt(key, nonce, badCT, aad); err == nil {
		t.Fatal("tampered ciphertext should fail decryption")
	}
}

func TestSpec_Suite_Hash_SHA256(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	data := []byte("test data")
	hash := suite.Hash(data)

	if len(hash) != 32 {
		t.Fatalf("hash length: got %d, want 32", len(hash))
	}

	// Deterministic
	hash2 := suite.Hash(data)
	if !bytes.Equal(hash, hash2) {
		t.Fatal("SHA-256 should be deterministic")
	}

	// Different input gives different output
	hash3 := suite.Hash([]byte("different"))
	if bytes.Equal(hash, hash3) {
		t.Fatal("different inputs should give different hashes")
	}
}

func TestSpec_Suite_KeyDerivation_Root(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	secret := make([]byte, 32)
	salt := make([]byte, 32)
	convID := make([]byte, 16)

	root, err := suite.DeriveRootKey(secret, salt, convID)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 32 {
		t.Fatalf("root key length: got %d, want 32", len(root))
	}

	// Deterministic
	root2, _ := suite.DeriveRootKey(secret, salt, convID)
	if !bytes.Equal(root, root2) {
		t.Fatal("root key derivation should be deterministic")
	}

	// Different secret → different root
	secret2 := make([]byte, 32)
	secret2[0] = 1
	root3, _ := suite.DeriveRootKey(secret2, salt, convID)
	if bytes.Equal(root, root3) {
		t.Fatal("different secrets should produce different root keys")
	}
}

func TestSpec_Suite_KeyDerivation_Conversation(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	root := make([]byte, 32)
	convID := make([]byte, 16)

	aead, nonce, err := suite.DeriveConversationKeys(root, convID)
	if err != nil {
		t.Fatal(err)
	}
	if len(aead) != 32 {
		t.Fatalf("AEAD key length: got %d, want 32", len(aead))
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce key length: got %d, want 32", len(nonce))
	}

	// AEAD and nonce keys must be different
	if bytes.Equal(aead, nonce) {
		t.Fatal("AEAD and nonce keys should be different")
	}
}

func TestSpec_Suite_KeyDerivation_Epoch(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	groupKey := make([]byte, 32)
	convID := make([]byte, 16)

	// Epoch 0 should match v1.0 DeriveConversationKeys
	aead0, nonce0, err := suite.DeriveEpochKeys(groupKey, convID, 0)
	if err != nil {
		t.Fatal(err)
	}
	aeadConv, nonceConv, _ := suite.DeriveConversationKeys(groupKey, convID)
	if !bytes.Equal(aead0, aeadConv) {
		t.Fatal("epoch 0 AEAD key should match v1.0 conversation key")
	}
	if !bytes.Equal(nonce0, nonceConv) {
		t.Fatal("epoch 0 nonce key should match v1.0 conversation key")
	}

	// Different epochs produce different keys
	aead1, nonce1, _ := suite.DeriveEpochKeys(groupKey, convID, 1)
	if bytes.Equal(aead0, aead1) {
		t.Fatal("different epochs should produce different AEAD keys")
	}
	if bytes.Equal(nonce0, nonce1) {
		t.Fatal("different epochs should produce different nonce keys")
	}
}

func TestSpec_Suite_NonceDerivation(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	nonceKey := make([]byte, 32)
	msgID := make([]byte, 16)

	nonce, err := suite.DeriveNonce(nonceKey, msgID)
	if err != nil {
		t.Fatal(err)
	}
	// XChaCha20 nonce is 24 bytes
	if len(nonce) != 24 {
		t.Fatalf("nonce length: got %d, want 24", len(nonce))
	}

	// Deterministic
	nonce2, _ := suite.DeriveNonce(nonceKey, msgID)
	if nonce != nonce2 {
		t.Fatal("nonce derivation should be deterministic")
	}

	// Different msgID → different nonce
	msgID2 := make([]byte, 16)
	msgID2[0] = 1
	nonce3, _ := suite.DeriveNonce(nonceKey, msgID2)
	if nonce == nonce3 {
		t.Fatal("different message IDs should produce different nonces")
	}
}

func TestSpec_Suite_GroupKey_Generation(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	key, err := suite.GenerateGroupKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("group key length: got %d, want 32", len(key))
	}

	// Unique each time
	key2, _ := suite.GenerateGroupKey()
	if bytes.Equal(key, key2) {
		t.Fatal("generated group keys should be unique")
	}
}

func TestSpec_Suite_KeyWrapping(t *testing.T) {
	suite := crypto.NewQSP1Suite()

	// Generate sender and recipient
	recipientPub, recipientPriv, _ := suite.GenerateIdentityKey()
	recipientKID := suite.ComputeKeyID(recipientPub)
	convID := make([]byte, 16)

	groupKey := make([]byte, 32)
	for i := range groupKey {
		groupKey[i] = byte(i + 42)
	}

	// Wrap
	wrapped, err := suite.WrapKeyForRecipient(groupKey, recipientPub, recipientKID, convID)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped key should not be empty")
	}

	// Unwrap
	unwrapped, err := suite.UnwrapKeyForRecipient(wrapped, recipientPriv, recipientKID, convID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, groupKey) {
		t.Fatal("unwrapped key should match original")
	}

	// Wrong recipient fails
	_, wrongPriv, _ := suite.GenerateIdentityKey()
	wrongKID := suite.ComputeKeyID(recipientPub) // same KID but wrong key
	if _, err := suite.UnwrapKeyForRecipient(wrapped, wrongPriv, wrongKID, convID); err == nil {
		t.Fatal("wrong recipient should fail unwrapping")
	}
}

// =============================================================================
// Section 4: CBOR Canonical Encoding
// =============================================================================

func TestSpec_CBOR_Canonical_Deterministic(t *testing.T) {
	// Same struct produces identical bytes every time
	s := types.AADStruct{
		Version:   1,
		Suite:     "QSP-1",
		ConvEpoch: 0,
		CreatedTS: 1700000000,
		ExpiryTS:  1702592000,
	}

	b1, err := cbor.MarshalCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := cbor.MarshalCanonical(s)
	if !bytes.Equal(b1, b2) {
		t.Fatal("canonical CBOR encoding should be deterministic")
	}
}

func TestSpec_CBOR_RoundTrip_AAD(t *testing.T) {
	original := types.AADStruct{
		Version:   1,
		Suite:     "QSP-1",
		ConvEpoch: 3,
		CreatedTS: 1700000000,
		ExpiryTS:  1702592000,
	}
	data, err := cbor.MarshalCanonical(original)
	if err != nil {
		t.Fatal(err)
	}

	var restored types.AADStruct
	if err := cbor.UnmarshalCanonical(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Version != original.Version || restored.Suite != original.Suite ||
		restored.ConvEpoch != original.ConvEpoch || restored.CreatedTS != original.CreatedTS ||
		restored.ExpiryTS != original.ExpiryTS {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", restored, original)
	}
}

func TestSpec_CBOR_RoundTrip_Signable(t *testing.T) {
	original := types.Signable{
		Proto:     "qntm/qsp/v1",
		Suite:     "QSP-1",
		CreatedTS: 1700000000,
		ExpiryTS:  1702592000,
		BodyHash:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	data, _ := cbor.MarshalCanonical(original)
	var restored types.Signable
	if err := cbor.UnmarshalCanonical(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Proto != original.Proto {
		t.Fatalf("Proto: got %q, want %q", restored.Proto, original.Proto)
	}
	if !bytes.Equal(restored.BodyHash, original.BodyHash) {
		t.Fatal("BodyHash mismatch")
	}
}

func TestSpec_CBOR_RoundTrip_InvitePayload(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	original := types.InvitePayload{
		Version:      1,
		Suite:        "QSP-1",
		Type:         "direct",
		InviterIKPK:  pub,
		InviteSalt:   make([]byte, 32),
		InviteSecret: make([]byte, 32),
	}
	data, _ := cbor.MarshalCanonical(original)
	var restored types.InvitePayload
	if err := cbor.UnmarshalCanonical(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Type != "direct" {
		t.Fatalf("Type: got %q, want %q", restored.Type, "direct")
	}
	if !bytes.Equal(restored.InviterIKPK, pub) {
		t.Fatal("InviterIKPK mismatch")
	}
}

// =============================================================================
// Section 5: Invites — creation, serialization, key derivation
// =============================================================================

func TestSpec_Invite_Creation(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()

	inv, err := inviteMgr.CreateInvite(sender, "direct")
	if err != nil {
		t.Fatal(err)
	}

	if inv.Version != types.ProtocolVersion {
		t.Fatalf("Version: got %d, want %d", inv.Version, types.ProtocolVersion)
	}
	if inv.Suite != types.DefaultSuite {
		t.Fatalf("Suite: got %q, want %q", inv.Suite, types.DefaultSuite)
	}
	if inv.Type != "direct" {
		t.Fatalf("Type: got %q, want direct", inv.Type)
	}
	if len(inv.InviteSalt) != 32 {
		t.Fatalf("InviteSalt: got %d bytes, want 32", len(inv.InviteSalt))
	}
	if len(inv.InviteSecret) != 32 {
		t.Fatalf("InviteSecret: got %d bytes, want 32", len(inv.InviteSecret))
	}
}

func TestSpec_Invite_Serialization(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")

	data, err := inviteMgr.SerializeInvite(inv)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := inviteMgr.DeserializeInvite(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Type != inv.Type {
		t.Fatal("Type mismatch")
	}
	if !bytes.Equal(restored.InviteSecret, inv.InviteSecret) {
		t.Fatal("InviteSecret mismatch")
	}
}

func TestSpec_Invite_URL_RoundTrip(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")

	invURL, err := inviteMgr.InviteToURL(inv, "https://qntm.example.com/invite")
	if err != nil {
		t.Fatal(err)
	}
	if invURL == "" {
		t.Fatal("URL should not be empty")
	}

	restored, err := inviteMgr.InviteFromURL(invURL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.InviteSecret, inv.InviteSecret) {
		t.Fatal("InviteSecret mismatch after URL round-trip")
	}
}

func TestSpec_Invite_KeyDerivation_Deterministic(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")

	conv1 := acceptInvite(t, inviteMgr, inv)
	conv2 := acceptInvite(t, inviteMgr, inv)

	// Same invite → same conversation keys
	if !bytes.Equal(conv1.Keys.Root, conv2.Keys.Root) {
		t.Fatal("same invite should derive same root key")
	}
	if !bytes.Equal(conv1.Keys.AEADKey, conv2.Keys.AEADKey) {
		t.Fatal("same invite should derive same AEAD key")
	}
}

func TestSpec_Invite_GroupType(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, err := inviteMgr.CreateInvite(sender, "group")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Type != "group" {
		t.Fatalf("Type: got %q, want group", inv.Type)
	}
}

// =============================================================================
// Section 6: Messages — envelope creation, encryption, decryption, signatures
// =============================================================================

func TestSpec_Message_CreateAndDecrypt(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()

	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")
	conv := acceptInvite(t, inviteMgr, inv)

	body := []byte("hello world")
	envelope, err := msgMgr.CreateMessage(sender, conv, "text", body, nil, 86400)
	if err != nil {
		t.Fatal(err)
	}

	// Envelope structure
	if envelope.Version != types.ProtocolVersion {
		t.Fatalf("Version: got %d, want %d", envelope.Version, types.ProtocolVersion)
	}
	if envelope.Suite != types.DefaultSuite {
		t.Fatalf("Suite: got %q, want %q", envelope.Suite, types.DefaultSuite)
	}
	if envelope.ConvID != conv.ID {
		t.Fatal("ConvID mismatch")
	}
	if len(envelope.Ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}
	if envelope.CreatedTS == 0 {
		t.Fatal("CreatedTS should be set")
	}
	if envelope.ExpiryTS == 0 {
		t.Fatal("ExpiryTS should be set")
	}

	// Decrypt
	msg, err := msgMgr.DecryptMessage(envelope, conv)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Verified {
		t.Fatal("message should be verified")
	}
	if msg.Inner.BodyType != "text" {
		t.Fatalf("BodyType: got %q, want text", msg.Inner.BodyType)
	}
	if !bytes.Equal(msg.Inner.Body, body) {
		t.Fatalf("Body: got %q, want %q", msg.Inner.Body, body)
	}
	if msg.Inner.SigAlg != "Ed25519" {
		t.Fatalf("SigAlg: got %q, want Ed25519", msg.Inner.SigAlg)
	}
	if len(msg.Inner.Signature) != ed25519.SignatureSize {
		t.Fatalf("Signature: got %d bytes, want %d", len(msg.Inner.Signature), ed25519.SignatureSize)
	}
}

func TestSpec_Message_DifferentBodyTypes(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")
	conv := acceptInvite(t, inviteMgr, inv)

	bodyTypes := []string{"text", "json", "cbor", "invite", "group_rekey", "ack"}
	for _, bt := range bodyTypes {
		t.Run(bt, func(t *testing.T) {
			env, err := msgMgr.CreateMessage(sender, conv, bt, []byte("data"), nil, 86400)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := msgMgr.DecryptMessage(env, conv)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Inner.BodyType != bt {
				t.Fatalf("BodyType: got %q, want %q", msg.Inner.BodyType, bt)
			}
		})
	}
}

func TestSpec_Message_Serialization_CBOR(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")
	conv := acceptInvite(t, inviteMgr, inv)

	envelope, _ := msgMgr.CreateMessage(sender, conv, "text", []byte("serialize me"), nil, 86400)

	// Serialize to CBOR bytes (wire format)
	data, err := msgMgr.SerializeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("serialized envelope should not be empty")
	}

	// Deserialize
	restored, err := msgMgr.DeserializeEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Version != envelope.Version {
		t.Fatal("Version mismatch")
	}
	if restored.ConvID != envelope.ConvID {
		t.Fatal("ConvID mismatch")
	}
	if !bytes.Equal(restored.Ciphertext, envelope.Ciphertext) {
		t.Fatal("Ciphertext mismatch")
	}

	// Can still decrypt the deserialized envelope
	msg, err := msgMgr.DecryptMessage(restored, conv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.Inner.Body, []byte("serialize me")) {
		t.Fatal("decrypted body mismatch after serialization round-trip")
	}
}

func TestSpec_Message_WrongConversation_FailsDecrypt(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()
	sender, _ := idMgr.GenerateIdentity()

	inv1, _ := inviteMgr.CreateInvite(sender, "direct")
	conv1 := acceptInvite(t, inviteMgr, inv1)
	inv2, _ := inviteMgr.CreateInvite(sender, "direct")
	conv2 := acceptInvite(t, inviteMgr, inv2)

	envelope, _ := msgMgr.CreateMessage(sender, conv1, "text", []byte("secret"), nil, 86400)

	// Decrypting with wrong conversation keys should fail
	if _, err := msgMgr.DecryptMessage(envelope, conv2); err == nil {
		t.Fatal("decrypting with wrong conversation should fail")
	}
}

func TestSpec_Message_Validation(t *testing.T) {
	msgMgr := message.NewManager()

	// Invalid version
	if err := msgMgr.ValidateEnvelope(&types.OuterEnvelope{Version: 99, Suite: "QSP-1", Ciphertext: []byte{1}}); err == nil {
		t.Fatal("version 99 should be invalid")
	}

	// Invalid suite
	if err := msgMgr.ValidateEnvelope(&types.OuterEnvelope{Version: 1, Suite: "WRONG", Ciphertext: []byte{1}}); err == nil {
		t.Fatal("wrong suite should be invalid")
	}

	// Empty ciphertext
	if err := msgMgr.ValidateEnvelope(&types.OuterEnvelope{Version: 1, Suite: "QSP-1"}); err == nil {
		t.Fatal("empty ciphertext should be invalid")
	}
}

func TestSpec_Message_TTL(t *testing.T) {
	msgMgr := message.NewManager()

	// Default TTL
	if msgMgr.DefaultTTL() != 30*86400 {
		t.Fatalf("DefaultTTL: got %d, want %d", msgMgr.DefaultTTL(), 30*86400)
	}

	// Handshake TTL
	if msgMgr.DefaultHandshakeTTL() != 7*86400 {
		t.Fatalf("DefaultHandshakeTTL: got %d, want %d", msgMgr.DefaultHandshakeTTL(), 7*86400)
	}
}

func TestSpec_Message_Expiry(t *testing.T) {
	msgMgr := message.NewManager()

	// Not expired: CheckExpiry returns true when expired (now > expiry)
	future := &types.OuterEnvelope{ExpiryTS: time.Now().Add(1 * time.Hour).Unix()}
	if msgMgr.CheckExpiry(future) {
		t.Fatal("future message should not be expired")
	}

	// Expired
	past := &types.OuterEnvelope{ExpiryTS: time.Now().Add(-1 * time.Second).Unix()}
	if !msgMgr.CheckExpiry(past) {
		t.Fatal("past message should be expired")
	}
}

// =============================================================================
// Section 7: Conversation — structure and epoch management
// =============================================================================

func TestSpec_Conversation_Structure(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")
	conv := acceptInvite(t, inviteMgr, inv)

	if conv.Type != types.ConversationTypeDirect {
		t.Fatalf("Type: got %q, want direct", conv.Type)
	}
	if len(conv.Keys.Root) != 32 {
		t.Fatalf("Root key: got %d bytes, want 32", len(conv.Keys.Root))
	}
	if len(conv.Keys.AEADKey) != 32 {
		t.Fatalf("AEAD key: got %d bytes, want 32", len(conv.Keys.AEADKey))
	}
	if len(conv.Keys.NonceKey) != 32 {
		t.Fatalf("Nonce key: got %d bytes, want 32", len(conv.Keys.NonceKey))
	}
	if conv.CurrentEpoch != 0 {
		t.Fatalf("initial epoch should be 0, got %d", conv.CurrentEpoch)
	}
}

func TestSpec_Conversation_JSON_Serialization(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	sender, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(sender, "direct")
	conv := acceptInvite(t, inviteMgr, inv)

	data, err := json.Marshal(conv)
	if err != nil {
		t.Fatal(err)
	}

	var restored types.Conversation
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Type != conv.Type {
		t.Fatal("Type mismatch")
	}
	if !bytes.Equal(restored.Keys.Root, conv.Keys.Root) {
		t.Fatal("Root key mismatch")
	}
}

// =============================================================================
// Section 8: X25519 Key Conversion
// =============================================================================

func TestSpec_X25519_Ed25519Conversion(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	edPub, edPriv, _ := suite.GenerateIdentityKey()

	// Convert to X25519
	x25519Pub, err := crypto.Ed25519PublicKeyToX25519(edPub)
	if err != nil {
		t.Fatal(err)
	}
	x25519Priv, err := crypto.Ed25519PrivateKeyToX25519(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	if len(x25519Pub) != 32 {
		t.Fatalf("X25519 public key: got %d bytes, want 32", len(x25519Pub))
	}
	if len(x25519Priv) != 32 {
		t.Fatalf("X25519 private key: got %d bytes, want 32", len(x25519Priv))
	}

	// Deterministic
	x25519Pub2, _ := crypto.Ed25519PublicKeyToX25519(edPub)
	if !bytes.Equal(x25519Pub, x25519Pub2) {
		t.Fatal("X25519 conversion should be deterministic")
	}
}

func TestSpec_X25519_SharedSecret(t *testing.T) {
	privA, pubA, _ := crypto.GenerateX25519Keypair()
	privB, pubB, _ := crypto.GenerateX25519Keypair()

	// Shared secret from both sides should match (Diffie-Hellman)
	secretAB, err := crypto.X25519SharedSecret(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	secretBA, err := crypto.X25519SharedSecret(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretAB, secretBA) {
		t.Fatal("X25519 shared secrets should match")
	}
	if len(secretAB) != 32 {
		t.Fatalf("shared secret: got %d bytes, want 32", len(secretAB))
	}
}

// =============================================================================
// Section 9: End-to-End Protocol Flow
// =============================================================================

func TestSpec_E2E_DirectMessaging(t *testing.T) {
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()

	// Alice creates identity and invite
	alice, _ := idMgr.GenerateIdentity()
	inv, _ := inviteMgr.CreateInvite(alice, "direct")

	// Bob accepts invite
	conv := acceptInvite(t, inviteMgr, inv)

	// Both derive same conversation (deterministic)
	bobConv := acceptInvite(t, inviteMgr, inv)
	if !bytes.Equal(conv.Keys.AEADKey, bobConv.Keys.AEADKey) {
		t.Fatal("both parties should derive same keys")
	}

	// Alice sends
	env, _ := msgMgr.CreateMessage(alice, conv, "text", []byte("Hello Bob!"), nil, 86400)

	// Serialize for transport (CBOR wire format)
	wireBytes, _ := msgMgr.SerializeEnvelope(env)
	if len(wireBytes) == 0 {
		t.Fatal("wire bytes should not be empty")
	}

	// Bob receives and deserializes
	received, _ := msgMgr.DeserializeEnvelope(wireBytes)

	// Bob decrypts
	msg, err := msgMgr.DecryptMessage(received, bobConv)
	if err != nil {
		t.Fatal("Bob should decrypt Alice's message:", err)
	}
	if !msg.Verified {
		t.Fatal("message should be signature-verified")
	}
	if string(msg.Inner.Body) != "Hello Bob!" {
		t.Fatalf("Body: got %q, want %q", msg.Inner.Body, "Hello Bob!")
	}
	if !bytes.Equal(msg.Inner.SenderIKPK, alice.PublicKey) {
		t.Fatal("sender public key should match Alice")
	}
}

func TestSpec_E2E_MessageIsolation(t *testing.T) {
	// Messages in one conversation cannot be decrypted in another
	idMgr := identity.NewManager()
	inviteMgr := invite.NewManager()
	msgMgr := message.NewManager()

	alice, _ := idMgr.GenerateIdentity()
	inv1, _ := inviteMgr.CreateInvite(alice, "direct")
	inv2, _ := inviteMgr.CreateInvite(alice, "direct")
	conv1 := acceptInvite(t, inviteMgr, inv1)
	conv2 := acceptInvite(t, inviteMgr, inv2)

	env, _ := msgMgr.CreateMessage(alice, conv1, "text", []byte("conv1 only"), nil, 86400)

	if _, err := msgMgr.DecryptMessage(env, conv2); err == nil {
		t.Fatal("cross-conversation decryption should fail")
	}
}

// =============================================================================
// Section 10: Wire Format Documentation (for TypeScript client)
// =============================================================================

func TestSpec_WireFormat_OuterEnvelope_Fields(t *testing.T) {
	// Documents the exact CBOR field names used on the wire
	// TypeScript client must use these exact field names
	type wireEnvelope struct {
		Version    int    `cbor:"v"`
		Suite      string `cbor:"suite"`
		ConvID     []byte `cbor:"conv_id"`
		MsgID      []byte `cbor:"msg_id"`
		CreatedTS  int64  `cbor:"created_ts"`
		ExpiryTS   int64  `cbor:"expiry_ts"`
		ConvEpoch  uint   `cbor:"conv_epoch"`
		Ciphertext []byte `cbor:"ciphertext"`
		AADHash    []byte `cbor:"aad_hash,omitempty"`
	}

	env := wireEnvelope{
		Version:    1,
		Suite:      "QSP-1",
		ConvID:     make([]byte, 16),
		MsgID:      make([]byte, 16),
		CreatedTS:  1700000000,
		ExpiryTS:   1702592000,
		ConvEpoch:  0,
		Ciphertext: []byte{1, 2, 3},
	}

	data, err := cbor.MarshalCanonical(env)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the types.OuterEnvelope can decode what we encoded
	var decoded types.OuterEnvelope
	if err := cbor.UnmarshalCanonical(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 {
		t.Fatal("Version mismatch")
	}
	if decoded.Suite != "QSP-1" {
		t.Fatal("Suite mismatch")
	}
	if decoded.ConvEpoch != 0 {
		t.Fatal("ConvEpoch mismatch")
	}
}

func TestSpec_WireFormat_InnerPayload_Fields(t *testing.T) {
	// Documents CBOR field names for the encrypted inner payload
	type wireInner struct {
		SenderIKPK []byte `cbor:"sender_ik_pk"`
		SenderKID  []byte `cbor:"sender_kid"`
		BodyType   string `cbor:"body_type"`
		Body       []byte `cbor:"body"`
		SigAlg     string `cbor:"sig_alg"`
		Signature  []byte `cbor:"signature"`
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	inner := wireInner{
		SenderIKPK: pub,
		SenderKID:  make([]byte, 16),
		BodyType:   "text",
		Body:       []byte("hello"),
		SigAlg:     "Ed25519",
		Signature:  make([]byte, 64),
	}

	data, err := cbor.MarshalCanonical(inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("inner payload wire format should not be empty")
	}

	// Round-trip
	var decoded wireInner
	if err := cbor.UnmarshalCanonical(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BodyType != "text" {
		t.Fatal("BodyType mismatch")
	}
}

func TestSpec_WireFormat_InvitePayload_Fields(t *testing.T) {
	// Documents CBOR field names for invite payloads
	type wireInvite struct {
		Version      int    `cbor:"v"`
		Suite        string `cbor:"suite"`
		Type         string `cbor:"type"`
		ConvID       []byte `cbor:"conv_id"`
		InviterIKPK  []byte `cbor:"inviter_ik_pk"`
		InviteSalt   []byte `cbor:"invite_salt"`
		InviteSecret []byte `cbor:"invite_secret"`
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	inv := wireInvite{
		Version:      1,
		Suite:        "QSP-1",
		Type:         "direct",
		ConvID:       make([]byte, 16),
		InviterIKPK:  pub,
		InviteSalt:   make([]byte, 32),
		InviteSecret: make([]byte, 32),
	}

	data, _ := cbor.MarshalCanonical(inv)
	var decoded wireInvite
	if err := cbor.UnmarshalCanonical(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "direct" {
		t.Fatal("Type mismatch in wire format")
	}
}

// =============================================================================
// Section 11: Gate API Types — request/response schemas
// =============================================================================

func TestSpec_Gate_API_Types_JSON(t *testing.T) {
	// Documents JSON field names for all gate API types.
	// TypeScript client must use these exact field names.

	t.Run("ThresholdRule", func(t *testing.T) {
		rule := struct {
			Service  string `json:"service"`
			Endpoint string `json:"endpoint"`
			Verb     string `json:"verb"`
			M        int    `json:"m"`
			N        int    `json:"n"`
		}{
			Service: "stripe", Endpoint: "/v1/charges", Verb: "POST", M: 2, N: 3,
		}
		data, _ := json.Marshal(rule)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["service"] != "stripe" {
			t.Fatal("service field mismatch")
		}
		if decoded["m"].(float64) != 2 {
			t.Fatal("m field mismatch")
		}
	})

	t.Run("Credential", func(t *testing.T) {
		cred := struct {
			ID          string `json:"id"`
			Service     string `json:"service"`
			Value       string `json:"value"`
			HeaderName  string `json:"header_name"`
			HeaderValue string `json:"header_value"`
			Description string `json:"description"`
		}{
			ID: "stripe-key", Service: "stripe", Value: "sk_test_xxx",
			HeaderName: "Authorization", HeaderValue: "Bearer {value}",
			Description: "Stripe test key",
		}
		data, _ := json.Marshal(cred)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["header_value"] != "Bearer {value}" {
			t.Fatal("header_value template mismatch")
		}
	})

	t.Run("GateConversationMessage_Request", func(t *testing.T) {
		msg := struct {
			Type           string          `json:"type"`
			OrgID          string          `json:"org_id"`
			RequestID      string          `json:"request_id"`
			Verb           string          `json:"verb"`
			TargetEndpoint string          `json:"target_endpoint"`
			TargetService  string          `json:"target_service"`
			TargetURL      string          `json:"target_url"`
			Payload        json.RawMessage `json:"payload"`
			ExpiresAt      time.Time       `json:"expires_at"`
			SignerKID      string          `json:"signer_kid"`
			Signature      string          `json:"signature"`
		}{
			Type: "gate.request", OrgID: "acme-corp", RequestID: "req-001",
			Verb: "POST", TargetEndpoint: "/v1/charges", TargetService: "stripe",
			TargetURL: "https://api.stripe.com/v1/charges",
			Payload:   json.RawMessage(`{"amount":1000}`),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			SignerKID: "abc123", Signature: "base64sig",
		}
		data, _ := json.Marshal(msg)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["type"] != "gate.request" {
			t.Fatal("type mismatch")
		}
		if decoded["target_service"] != "stripe" {
			t.Fatal("target_service mismatch")
		}
	})

	t.Run("GateConversationMessage_Approval", func(t *testing.T) {
		msg := struct {
			Type      string `json:"type"`
			OrgID     string `json:"org_id"`
			RequestID string `json:"request_id"`
			SignerKID string `json:"signer_kid"`
			Signature string `json:"signature"`
		}{
			Type: "gate.approval", OrgID: "acme-corp", RequestID: "req-001",
			SignerKID: "def456", Signature: "approval_sig",
		}
		data, _ := json.Marshal(msg)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["type"] != "gate.approval" {
			t.Fatal("approval type mismatch")
		}
	})

	t.Run("GateConversationMessage_Executed", func(t *testing.T) {
		msg := struct {
			Type                string    `json:"type"`
			OrgID               string    `json:"org_id"`
			RequestID           string    `json:"request_id"`
			ExecutedAt          time.Time `json:"executed_at"`
			ExecutionStatusCode int       `json:"execution_status_code"`
		}{
			Type: "gate.executed", OrgID: "acme-corp", RequestID: "req-001",
			ExecutedAt: time.Now(), ExecutionStatusCode: 200,
		}
		data, _ := json.Marshal(msg)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["type"] != "gate.executed" {
			t.Fatal("executed type mismatch")
		}
		if decoded["execution_status_code"].(float64) != 200 {
			t.Fatal("status code mismatch")
		}
	})

	t.Run("ScanResult", func(t *testing.T) {
		result := struct {
			Found        bool     `json:"found"`
			ThresholdMet bool     `json:"threshold_met"`
			Expired      bool     `json:"expired"`
			SignerKIDs   []string `json:"signer_kids"`
			Threshold    int      `json:"threshold"`
			Status       string   `json:"status"`
		}{
			Found: true, ThresholdMet: true, Expired: false,
			SignerKIDs: []string{"kid1", "kid2"}, Threshold: 2, Status: "approved",
		}
		data, _ := json.Marshal(result)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["status"] != "approved" {
			t.Fatal("status mismatch")
		}
		kids := decoded["signer_kids"].([]interface{})
		if len(kids) != 2 {
			t.Fatal("signer_kids count mismatch")
		}
	})

	t.Run("ExecuteResult", func(t *testing.T) {
		result := struct {
			OrgID          string   `json:"org_id"`
			RequestID      string   `json:"request_id"`
			Verb           string   `json:"verb"`
			TargetEndpoint string   `json:"target_endpoint"`
			TargetService  string   `json:"target_service"`
			Status         string   `json:"status"`
			SignatureCount int      `json:"signature_count"`
			SignerKIDs     []string `json:"signer_kids"`
			Threshold      int      `json:"threshold"`
			ExpiresAt      string   `json:"expires_at"`
			ExecutionResult *struct {
				StatusCode    int    `json:"status_code"`
				ContentType   string `json:"content_type"`
				ContentLength int64  `json:"content_length"`
			} `json:"execution_result,omitempty"`
		}{
			OrgID: "acme", RequestID: "req-001", Verb: "POST",
			TargetEndpoint: "/charges", TargetService: "stripe",
			Status: "executed", SignatureCount: 2,
			SignerKIDs: []string{"kid1", "kid2"}, Threshold: 2,
			ExecutionResult: &struct {
				StatusCode    int    `json:"status_code"`
				ContentType   string `json:"content_type"`
				ContentLength int64  `json:"content_length"`
			}{StatusCode: 200, ContentType: "application/json", ContentLength: 42},
		}
		data, _ := json.Marshal(result)
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		if decoded["status"] != "executed" {
			t.Fatal("status mismatch")
		}
		er := decoded["execution_result"].(map[string]interface{})
		if er["status_code"].(float64) != 200 {
			t.Fatal("execution status mismatch")
		}
	})
}

// =============================================================================
// Section 12: Gate CBOR Signing Types
// =============================================================================

func TestSpec_Gate_GateSignable_CBOR_Fields(t *testing.T) {
	// Documents the canonical CBOR structure that gets signed for gate requests
	type wireGateSignable struct {
		OrgID          string `cbor:"org_id"`
		RequestID      string `cbor:"request_id"`
		Verb           string `cbor:"verb"`
		TargetEndpoint string `cbor:"target_endpoint"`
		TargetService  string `cbor:"target_service"`
		TargetURL      string `cbor:"target_url"`
		ExpiresAtUnix  int64  `cbor:"expires_at_unix"`
		PayloadHash    []byte `cbor:"payload_hash"`
	}

	s := wireGateSignable{
		OrgID: "acme", RequestID: "req-001", Verb: "POST",
		TargetEndpoint: "/charges", TargetService: "stripe",
		TargetURL:     "https://api.stripe.com/v1/charges",
		ExpiresAtUnix: 1700000000,
		PayloadHash:   sha256.New().Sum(nil),
	}

	data, err := cbor.MarshalCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("GateSignable CBOR should not be empty")
	}

	// Deterministic
	data2, _ := cbor.MarshalCanonical(s)
	if !bytes.Equal(data, data2) {
		t.Fatal("GateSignable CBOR should be deterministic")
	}
}

func TestSpec_Gate_ApprovalSignable_CBOR_Fields(t *testing.T) {
	type wireApprovalSignable struct {
		OrgID       string `cbor:"org_id"`
		RequestID   string `cbor:"request_id"`
		RequestHash []byte `cbor:"request_hash"`
	}

	s := wireApprovalSignable{
		OrgID: "acme", RequestID: "req-001",
		RequestHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	}

	data, err := cbor.MarshalCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("ApprovalSignable CBOR should not be empty")
	}
}

// =============================================================================
// Section 13: Gate Request Status Values
// =============================================================================

func TestSpec_Gate_RequestStatus_Values(t *testing.T) {
	// TypeScript enum: "pending" | "approved" | "executed" | "expired"
	statuses := map[string]bool{
		"pending":  true,
		"approved": true,
		"executed": true,
		"expired":  true,
	}
	for s := range statuses {
		if len(s) == 0 {
			t.Fatal("empty status")
		}
	}
	if len(statuses) != 4 {
		t.Fatal("expected exactly 4 status values")
	}
}

func TestSpec_Gate_MessageType_Values(t *testing.T) {
	// TypeScript enum: "gate.request" | "gate.approval" | "gate.executed"
	types := map[string]bool{
		"gate.request":  true,
		"gate.approval": true,
		"gate.executed": true,
	}
	if len(types) != 3 {
		t.Fatal("expected exactly 3 message types")
	}
}

// =============================================================================
// Section 14: Crypto Constants for TypeScript Implementation
// =============================================================================

func TestSpec_CryptoConstants(t *testing.T) {
	// Key sizes
	if ed25519.PublicKeySize != 32 {
		t.Fatal("Ed25519 public key should be 32 bytes")
	}
	if ed25519.PrivateKeySize != 64 {
		t.Fatal("Ed25519 private key should be 64 bytes")
	}
	if ed25519.SignatureSize != 64 {
		t.Fatal("Ed25519 signature should be 64 bytes")
	}

	// Info strings for HKDF derivation
	if crypto.SuiteQSP1 != "QSP-1" {
		t.Fatal("SuiteQSP1 constant mismatch")
	}
	if crypto.ProtoPrefix != "qntm/qsp/v1" {
		t.Fatal("ProtoPrefix mismatch")
	}
	if crypto.InfoRoot != "qntm/qsp/v1/root" {
		t.Fatal("InfoRoot mismatch")
	}
	if crypto.InfoAEAD != "qntm/qsp/v1/aead" {
		t.Fatal("InfoAEAD mismatch")
	}
	if crypto.InfoNonce != "qntm/qsp/v1/nonce" {
		t.Fatal("InfoNonce mismatch")
	}
}
