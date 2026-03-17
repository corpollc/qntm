package announce

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

// TestAnnounceChannelFullFlow simulates the complete announce channel lifecycle:
// key generation → channel registration signing → posting with transport sig →
// subscriber decryption → unauthorized post rejection → deletion signing.
func TestAnnounceChannelFullFlow(t *testing.T) {
	mgr := NewManager()
	idMgr := identity.NewManager()
	msgMgr := message.NewManager()

	// --- Step 1: Owner generates channel keys ---
	keys, err := mgr.GenerateChannelKeys()
	if err != nil {
		t.Fatalf("GenerateChannelKeys: %v", err)
	}

	// --- Step 2: Owner generates conversation ID and invite secret ---
	convID, err := idMgr.GenerateConversationID()
	if err != nil {
		t.Fatalf("GenerateConversationID: %v", err)
	}
	convIDHex := hex.EncodeToString(convID[:])

	inviteSecret, err := idMgr.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes: %v", err)
	}

	// --- Step 3: Sign the register request ---
	masterPKB64 := base64.RawURLEncoding.EncodeToString(keys.MasterPublic)
	postingPKB64 := base64.RawURLEncoding.EncodeToString(keys.PostingPublic)

	regSig, err := mgr.SignRegister(keys.MasterPrivate, "test-announce", convIDHex, postingPKB64)
	if err != nil {
		t.Fatalf("SignRegister: %v", err)
	}
	if err := mgr.VerifyRegister(keys.MasterPublic, "test-announce", convIDHex, postingPKB64, regSig); err != nil {
		t.Fatalf("VerifyRegister: %v", err)
	}
	t.Logf("Channel registered: %s master_pk=%s", convIDHex, masterPKB64)

	// --- Step 4: Owner derives conversation keys ---
	suite := crypto.NewQSP1Suite()
	rootKey, err := suite.DeriveRootKey(inviteSecret, convID[:], convID[:])
	if err != nil {
		t.Fatalf("DeriveRootKey: %v", err)
	}
	aeadKey, nonceKey, err := suite.DeriveConversationKeys(rootKey, convID[:])
	if err != nil {
		t.Fatalf("DeriveConversationKeys: %v", err)
	}

	ownerConv := &types.Conversation{
		ID:           convID,
		Name:         "test-announce",
		Type:         types.ConversationTypeAnnounce,
		Keys:         types.ConversationKeys{Root: rootKey, AEADKey: aeadKey, NonceKey: nonceKey},
		CreatedAt:    time.Now(),
		CurrentEpoch: 0,
	}

	// --- Step 5: Owner creates identity and posts a message ---
	ownerIdentity, err := idMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity (owner): %v", err)
	}

	envelope, err := msgMgr.CreateMessage(ownerIdentity, ownerConv, "text", []byte("Hello subscribers!"), nil, 3600)
	if err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}

	envelopeData, err := msgMgr.SerializeEnvelope(envelope)
	if err != nil {
		t.Fatalf("SerializeEnvelope: %v", err)
	}
	envelopeB64 := base64.StdEncoding.EncodeToString(envelopeData)

	// Sign with posting key
	announceSig := mgr.SignEnvelope(keys.PostingPrivate, envelopeB64)
	t.Logf("Envelope signed: sig=%s...", announceSig[:16])

	// Verify posting key signature (what the worker would do)
	if err := mgr.VerifyEnvelope(keys.PostingPublic, envelopeB64, announceSig); err != nil {
		t.Fatalf("worker-side VerifyEnvelope should pass: %v", err)
	}

	// --- Step 6: Subscriber derives same keys and decrypts ---
	subRootKey, err := suite.DeriveRootKey(inviteSecret, convID[:], convID[:])
	if err != nil {
		t.Fatalf("subscriber DeriveRootKey: %v", err)
	}
	subAEADKey, subNonceKey, err := suite.DeriveConversationKeys(subRootKey, convID[:])
	if err != nil {
		t.Fatalf("subscriber DeriveConversationKeys: %v", err)
	}

	// Keys must match
	if hex.EncodeToString(aeadKey) != hex.EncodeToString(subAEADKey) {
		t.Fatal("subscriber AEAD key does not match owner AEAD key")
	}
	if hex.EncodeToString(nonceKey) != hex.EncodeToString(subNonceKey) {
		t.Fatal("subscriber nonce key does not match owner nonce key")
	}

	subConv := &types.Conversation{
		ID:           convID,
		Name:         "test-announce",
		Type:         types.ConversationTypeAnnounce,
		Keys:         types.ConversationKeys{Root: subRootKey, AEADKey: subAEADKey, NonceKey: subNonceKey},
		CreatedAt:    time.Now(),
		CurrentEpoch: 0,
	}

	// Subscriber decrypts the message
	deserializedEnv, err := msgMgr.DeserializeEnvelope(envelopeData)
	if err != nil {
		t.Fatalf("subscriber DeserializeEnvelope: %v", err)
	}

	msg, err := msgMgr.DecryptMessage(deserializedEnv, subConv)
	if err != nil {
		t.Fatalf("subscriber DecryptMessage: %v", err)
	}
	if !msg.Verified {
		t.Error("message should be verified")
	}
	if string(msg.Inner.Body) != "Hello subscribers!" {
		t.Errorf("message body: got %q, want %q", msg.Inner.Body, "Hello subscribers!")
	}
	t.Log("Subscriber decrypted message successfully")

	// --- Step 7: Unauthorized poster should be rejected ---
	// Generate a random key (not the posting key)
	unauthorizedIdentity, _ := idMgr.GenerateIdentity()
	badSig := mgr.SignEnvelope(unauthorizedIdentity.PrivateKey, envelopeB64)

	// Worker-side verification should fail
	if err := mgr.VerifyEnvelope(keys.PostingPublic, envelopeB64, badSig); err == nil {
		t.Error("unauthorized signature should be rejected by worker")
	}
	t.Log("Unauthorized post correctly rejected")

	// --- Step 8: Delete channel ---
	delSig, err := mgr.SignDelete(keys.MasterPrivate, convIDHex)
	if err != nil {
		t.Fatalf("SignDelete: %v", err)
	}
	if err := mgr.VerifyDelete(keys.MasterPublic, convIDHex, delSig); err != nil {
		t.Fatalf("VerifyDelete: %v", err)
	}

	// Non-master key cannot delete
	badDelSig, _ := mgr.SignDelete(keys.PostingPrivate, convIDHex)
	if err := mgr.VerifyDelete(keys.MasterPublic, convIDHex, badDelSig); err == nil {
		t.Error("posting key should not be able to delete channel")
	}
	t.Log("Channel deletion correctly authorized only by master key")
}
