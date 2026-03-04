package announce

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestGenerateChannelKeys(t *testing.T) {
	mgr := NewManager()
	keys, err := mgr.GenerateChannelKeys()
	if err != nil {
		t.Fatalf("GenerateChannelKeys failed: %v", err)
	}

	if len(keys.MasterPrivate) != ed25519.PrivateKeySize {
		t.Errorf("master private key size: got %d, want %d", len(keys.MasterPrivate), ed25519.PrivateKeySize)
	}
	if len(keys.MasterPublic) != ed25519.PublicKeySize {
		t.Errorf("master public key size: got %d, want %d", len(keys.MasterPublic), ed25519.PublicKeySize)
	}
	if len(keys.PostingPrivate) != ed25519.PrivateKeySize {
		t.Errorf("posting private key size: got %d, want %d", len(keys.PostingPrivate), ed25519.PrivateKeySize)
	}
	if len(keys.PostingPublic) != ed25519.PublicKeySize {
		t.Errorf("posting public key size: got %d, want %d", len(keys.PostingPublic), ed25519.PublicKeySize)
	}

	// Master and posting keys should be different
	if hex.EncodeToString(keys.MasterPublic) == hex.EncodeToString(keys.PostingPublic) {
		t.Error("master and posting public keys should be different")
	}
}

func TestSignVerifyRegister(t *testing.T) {
	mgr := NewManager()
	keys, _ := mgr.GenerateChannelKeys()

	name := "test-channel"
	convID := "0123456789abcdef0123456789abcdef"
	postingPK := "dGVzdC1wb3N0aW5nLWtleQ" // dummy base64url

	sig, err := mgr.SignRegister(keys.MasterPrivate, name, convID, postingPK)
	if err != nil {
		t.Fatalf("SignRegister failed: %v", err)
	}
	if sig == "" {
		t.Fatal("SignRegister returned empty signature")
	}

	// Verify with correct master key
	if err := mgr.VerifyRegister(keys.MasterPublic, name, convID, postingPK, sig); err != nil {
		t.Errorf("VerifyRegister failed with correct key: %v", err)
	}

	// Verify with wrong key should fail
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := mgr.VerifyRegister(wrongPub, name, convID, postingPK, sig); err == nil {
		t.Error("VerifyRegister should fail with wrong key")
	}

	// Verify with tampered name should fail
	if err := mgr.VerifyRegister(keys.MasterPublic, "wrong-name", convID, postingPK, sig); err == nil {
		t.Error("VerifyRegister should fail with wrong name")
	}
}

func TestSignVerifyRotate(t *testing.T) {
	mgr := NewManager()
	keys, _ := mgr.GenerateChannelKeys()

	convID := "0123456789abcdef0123456789abcdef"
	newPostingPK := "bmV3LXBvc3Rpbmcta2V5"

	sig, err := mgr.SignRotate(keys.MasterPrivate, convID, newPostingPK)
	if err != nil {
		t.Fatalf("SignRotate failed: %v", err)
	}

	if err := mgr.VerifyRotate(keys.MasterPublic, convID, newPostingPK, sig); err != nil {
		t.Errorf("VerifyRotate failed with correct key: %v", err)
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := mgr.VerifyRotate(wrongPub, convID, newPostingPK, sig); err == nil {
		t.Error("VerifyRotate should fail with wrong key")
	}
}

func TestSignVerifyDelete(t *testing.T) {
	mgr := NewManager()
	keys, _ := mgr.GenerateChannelKeys()

	convID := "0123456789abcdef0123456789abcdef"

	sig, err := mgr.SignDelete(keys.MasterPrivate, convID)
	if err != nil {
		t.Fatalf("SignDelete failed: %v", err)
	}

	if err := mgr.VerifyDelete(keys.MasterPublic, convID, sig); err != nil {
		t.Errorf("VerifyDelete failed with correct key: %v", err)
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := mgr.VerifyDelete(wrongPub, convID, sig); err == nil {
		t.Error("VerifyDelete should fail with wrong key")
	}

	// Tampered conv_id should fail
	if err := mgr.VerifyDelete(keys.MasterPublic, "ffffffffffffffffffffffffffffffff", sig); err == nil {
		t.Error("VerifyDelete should fail with wrong conv_id")
	}
}

func TestSignVerifyEnvelope(t *testing.T) {
	mgr := NewManager()
	keys, _ := mgr.GenerateChannelKeys()

	envelopeB64 := "dGVzdCBlbnZlbG9wZSBkYXRh"

	sig := mgr.SignEnvelope(keys.PostingPrivate, envelopeB64)
	if sig == "" {
		t.Fatal("SignEnvelope returned empty signature")
	}

	// Verify with correct posting key
	if err := mgr.VerifyEnvelope(keys.PostingPublic, envelopeB64, sig); err != nil {
		t.Errorf("VerifyEnvelope failed with correct key: %v", err)
	}

	// Verify with wrong key should fail
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := mgr.VerifyEnvelope(wrongPub, envelopeB64, sig); err == nil {
		t.Error("VerifyEnvelope should fail with wrong key")
	}

	// Verify with tampered data should fail
	if err := mgr.VerifyEnvelope(keys.PostingPublic, "tampered", sig); err == nil {
		t.Error("VerifyEnvelope should fail with tampered data")
	}

	// Master key should not be able to verify envelope sig
	if err := mgr.VerifyEnvelope(keys.MasterPublic, envelopeB64, sig); err == nil {
		t.Error("VerifyEnvelope should fail with master key (only posting key signs envelopes)")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	// Simulate the full flow: generate keys, sign register, verify register,
	// sign envelope, verify envelope.
	mgr := NewManager()
	keys, err := mgr.GenerateChannelKeys()
	if err != nil {
		t.Fatalf("GenerateChannelKeys: %v", err)
	}

	name := "qntm-announce"
	convID := "abcdef0123456789abcdef0123456789"
	postingPK := "cG9zdGluZy1rZXk"

	// Register
	regSig, _ := mgr.SignRegister(keys.MasterPrivate, name, convID, postingPK)
	if err := mgr.VerifyRegister(keys.MasterPublic, name, convID, postingPK, regSig); err != nil {
		t.Fatalf("register round-trip failed: %v", err)
	}

	// Post envelope
	envelope := "c29tZSBlbmNyeXB0ZWQgZW52ZWxvcGU"
	envSig := mgr.SignEnvelope(keys.PostingPrivate, envelope)
	if err := mgr.VerifyEnvelope(keys.PostingPublic, envelope, envSig); err != nil {
		t.Fatalf("envelope round-trip failed: %v", err)
	}

	// Rotate posting key
	newKeys, _ := mgr.GenerateChannelKeys()
	newPostingPK := "bmV3LXBvc3Rpbmcta2V5"
	rotSig, _ := mgr.SignRotate(keys.MasterPrivate, convID, newPostingPK)
	if err := mgr.VerifyRotate(keys.MasterPublic, convID, newPostingPK, rotSig); err != nil {
		t.Fatalf("rotate round-trip failed: %v", err)
	}

	// Old posting key should still verify old envelope
	if err := mgr.VerifyEnvelope(keys.PostingPublic, envelope, envSig); err != nil {
		t.Error("old posting key should still verify old envelope")
	}

	// New posting key can sign new envelopes
	newEnvSig := mgr.SignEnvelope(newKeys.PostingPrivate, envelope)
	if err := mgr.VerifyEnvelope(newKeys.PostingPublic, envelope, newEnvSig); err != nil {
		t.Error("new posting key should verify new envelope")
	}

	// Delete
	delSig, _ := mgr.SignDelete(keys.MasterPrivate, convID)
	if err := mgr.VerifyDelete(keys.MasterPublic, convID, delSig); err != nil {
		t.Fatalf("delete round-trip failed: %v", err)
	}
}

func TestInvalidSignatureFormats(t *testing.T) {
	mgr := NewManager()
	keys, _ := mgr.GenerateChannelKeys()

	// Empty signature
	if err := mgr.VerifyEnvelope(keys.PostingPublic, "data", ""); err == nil {
		t.Error("should reject empty signature")
	}

	// Invalid hex
	if err := mgr.VerifyEnvelope(keys.PostingPublic, "data", "not-hex"); err == nil {
		t.Error("should reject invalid hex")
	}

	// Too short
	if err := mgr.VerifyEnvelope(keys.PostingPublic, "data", "aabb"); err == nil {
		t.Error("should reject too-short signature")
	}
}
