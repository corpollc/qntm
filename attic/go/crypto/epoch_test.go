package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestDeriveEpochKeys_Epoch0_BackwardCompat(t *testing.T) {
	suite := NewQSP1Suite()

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	convID := make([]byte, 16)
	rand.Read(convID)

	// Epoch 0 should produce same keys as DeriveConversationKeys (v1.0 compat)
	aeadOld, nonceOld, err := suite.DeriveConversationKeys(groupKey, convID)
	if err != nil {
		t.Fatal(err)
	}

	aead0, nonce0, err := suite.DeriveEpochKeys(groupKey, convID, 0)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aeadOld, aead0) {
		t.Error("epoch 0 AEAD key differs from v1.0 derivation")
	}
	if !bytes.Equal(nonceOld, nonce0) {
		t.Error("epoch 0 nonce key differs from v1.0 derivation")
	}
}

func TestDeriveEpochKeys_DifferentEpochs(t *testing.T) {
	suite := NewQSP1Suite()

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	convID := make([]byte, 16)
	rand.Read(convID)

	aead1, nonce1, err := suite.DeriveEpochKeys(groupKey, convID, 1)
	if err != nil {
		t.Fatal(err)
	}
	aead2, nonce2, err := suite.DeriveEpochKeys(groupKey, convID, 2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(aead1, aead2) {
		t.Error("different epochs should produce different AEAD keys")
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Error("different epochs should produce different nonce keys")
	}
}

func TestDeriveEpochKeys_Deterministic(t *testing.T) {
	suite := NewQSP1Suite()

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	convID := make([]byte, 16)
	rand.Read(convID)

	aead1, nonce1, _ := suite.DeriveEpochKeys(groupKey, convID, 5)
	aead2, nonce2, _ := suite.DeriveEpochKeys(groupKey, convID, 5)

	if !bytes.Equal(aead1, aead2) {
		t.Error("same inputs should produce same AEAD key")
	}
	if !bytes.Equal(nonce1, nonce2) {
		t.Error("same inputs should produce same nonce key")
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	suite := NewQSP1Suite()

	// Generate recipient Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	kid := suite.ComputeKeyID(pub)
	convID := make([]byte, 16)
	rand.Read(convID)

	// Generate a group key to wrap
	groupKey := make([]byte, 32)
	rand.Read(groupKey)

	// Wrap
	wrapped, err := suite.WrapKeyForRecipient(groupKey, pub, kid, convID)
	if err != nil {
		t.Fatalf("WrapKeyForRecipient failed: %v", err)
	}

	// Unwrap
	unwrapped, err := suite.UnwrapKeyForRecipient(wrapped, priv, kid, convID)
	if err != nil {
		t.Fatalf("UnwrapKeyForRecipient failed: %v", err)
	}

	if !bytes.Equal(groupKey, unwrapped) {
		t.Error("unwrapped key does not match original")
	}
}

func TestWrapKey_DifferentRecipients(t *testing.T) {
	suite := NewQSP1Suite()

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	convID := make([]byte, 16)
	rand.Read(convID)

	// Two different recipients
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	kid1 := suite.ComputeKeyID(pub1)

	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	kid2 := suite.ComputeKeyID(pub2)

	wrapped1, err := suite.WrapKeyForRecipient(groupKey, pub1, kid1, convID)
	if err != nil {
		t.Fatal(err)
	}

	wrapped2, err := suite.WrapKeyForRecipient(groupKey, pub2, kid2, convID)
	if err != nil {
		t.Fatal(err)
	}

	// Each can unwrap their own
	unwrapped1, err := suite.UnwrapKeyForRecipient(wrapped1, priv1, kid1, convID)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped2, err := suite.UnwrapKeyForRecipient(wrapped2, priv2, kid2, convID)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(groupKey, unwrapped1) || !bytes.Equal(groupKey, unwrapped2) {
		t.Error("both recipients should recover the same group key")
	}

	// Recipient 1 cannot unwrap recipient 2's blob
	_, err = suite.UnwrapKeyForRecipient(wrapped2, priv1, kid1, convID)
	if err == nil {
		t.Error("recipient 1 should not be able to unwrap recipient 2's blob")
	}
}

func TestWrapKey_WrongKID(t *testing.T) {
	suite := NewQSP1Suite()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := suite.ComputeKeyID(pub)
	convID := make([]byte, 16)
	rand.Read(convID)

	groupKey := make([]byte, 32)
	rand.Read(groupKey)

	wrapped, err := suite.WrapKeyForRecipient(groupKey, pub, kid, convID)
	if err != nil {
		t.Fatal(err)
	}

	// Try unwrapping with wrong kid
	wrongKID := [16]byte{0xff, 0xff}
	_, err = suite.UnwrapKeyForRecipient(wrapped, priv, wrongKID, convID)
	if err == nil {
		t.Error("unwrap with wrong KID should fail")
	}
}

func TestX25519Conversion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	x25519PK, err := Ed25519PublicKeyToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(x25519PK) != 32 {
		t.Errorf("X25519 public key should be 32 bytes, got %d", len(x25519PK))
	}

	x25519SK, err := Ed25519PrivateKeyToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(x25519SK) != 32 {
		t.Errorf("X25519 private key should be 32 bytes, got %d", len(x25519SK))
	}
}
