package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestQSP1Suite_GenerateIdentityKey(t *testing.T) {
	suite := NewQSP1Suite()
	
	pub, priv, err := suite.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("Failed to generate identity key: %v", err)
	}
	
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("Invalid public key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("Invalid private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	
	// Verify the key pair works for signing
	message := []byte("test message")
	signature, err := suite.Sign(priv, message)
	if err != nil {
		t.Fatalf("Failed to sign with generated key: %v", err)
	}
	
	err = suite.Verify(pub, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature with generated key: %v", err)
	}
}

func TestQSP1Suite_ComputeKeyID(t *testing.T) {
	suite := NewQSP1Suite()
	
	pub, _, err := suite.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	
	keyID := suite.ComputeKeyID(pub)
	
	if len(keyID) != 16 {
		t.Errorf("Invalid key ID length: got %d, want 16", len(keyID))
	}
	
	// Test deterministic - same key should produce same key ID
	keyID2 := suite.ComputeKeyID(pub)
	if keyID != keyID2 {
		t.Error("Key ID generation is not deterministic")
	}
}

func TestQSP1Suite_KeyDerivation(t *testing.T) {
	suite := NewQSP1Suite()
	
	// Test data
	inviteSecret := make([]byte, 32)
	inviteSalt := make([]byte, 16)
	convID := make([]byte, 16)
	
	if _, err := rand.Read(inviteSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(inviteSalt); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(convID); err != nil {
		t.Fatal(err)
	}
	
	// Test root key derivation
	rootKey, err := suite.DeriveRootKey(inviteSecret, inviteSalt, convID)
	if err != nil {
		t.Fatalf("Failed to derive root key: %v", err)
	}
	
	if len(rootKey) != 32 {
		t.Errorf("Invalid root key length: got %d, want 32", len(rootKey))
	}
	
	// Test conversation key derivation
	aeadKey, nonceKey, err := suite.DeriveConversationKeys(rootKey, convID)
	if err != nil {
		t.Fatalf("Failed to derive conversation keys: %v", err)
	}
	
	if len(aeadKey) != 32 {
		t.Errorf("Invalid AEAD key length: got %d, want 32", len(aeadKey))
	}
	
	if len(nonceKey) != 32 {
		t.Errorf("Invalid nonce key length: got %d, want 32", len(nonceKey))
	}
	
	// Test deterministic - same inputs should produce same outputs
	rootKey2, err := suite.DeriveRootKey(inviteSecret, inviteSalt, convID)
	if err != nil {
		t.Fatalf("Failed to derive root key again: %v", err)
	}
	
	if !bytes.Equal(rootKey, rootKey2) {
		t.Error("Root key derivation is not deterministic")
	}
	
	aeadKey2, nonceKey2, err := suite.DeriveConversationKeys(rootKey, convID)
	if err != nil {
		t.Fatalf("Failed to derive conversation keys again: %v", err)
	}
	
	if !bytes.Equal(aeadKey, aeadKey2) {
		t.Error("AEAD key derivation is not deterministic")
	}
	
	if !bytes.Equal(nonceKey, nonceKey2) {
		t.Error("Nonce key derivation is not deterministic")
	}
}

func TestQSP1Suite_NonceDerivation(t *testing.T) {
	suite := NewQSP1Suite()
	
	nonceKey := make([]byte, 32)
	msgID := make([]byte, 16)
	
	if _, err := rand.Read(nonceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgID); err != nil {
		t.Fatal(err)
	}
	
	nonce, err := suite.DeriveNonce(nonceKey, msgID)
	if err != nil {
		t.Fatalf("Failed to derive nonce: %v", err)
	}
	
	if len(nonce) != 24 {
		t.Errorf("Invalid nonce length: got %d, want 24", len(nonce))
	}
	
	// Test deterministic
	nonce2, err := suite.DeriveNonce(nonceKey, msgID)
	if err != nil {
		t.Fatalf("Failed to derive nonce again: %v", err)
	}
	
	if nonce != nonce2 {
		t.Error("Nonce derivation is not deterministic")
	}
	
	// Different message IDs should produce different nonces
	msgID2 := make([]byte, 16)
	if _, err := rand.Read(msgID2); err != nil {
		t.Fatal(err)
	}
	
	nonce3, err := suite.DeriveNonce(nonceKey, msgID2)
	if err != nil {
		t.Fatalf("Failed to derive nonce with different msgID: %v", err)
	}
	
	if nonce == nonce3 {
		t.Error("Different message IDs should produce different nonces")
	}
}

func TestQSP1Suite_Encryption(t *testing.T) {
	suite := NewQSP1Suite()
	
	// Generate test data
	aeadKey := make([]byte, 32)
	nonceKey := make([]byte, 32)
	msgID := make([]byte, 16)
	plaintext := []byte("Hello, qntm secure messaging!")
	aad := []byte("additional authenticated data")
	
	if _, err := rand.Read(aeadKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgID); err != nil {
		t.Fatal(err)
	}
	
	// Derive nonce
	nonce, err := suite.DeriveNonce(nonceKey, msgID)
	if err != nil {
		t.Fatalf("Failed to derive nonce: %v", err)
	}
	
	// Encrypt
	ciphertext, err := suite.Encrypt(aeadKey, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	
	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext (includes auth tag)")
	}
	
	// Decrypt
	decrypted, err := suite.Decrypt(aeadKey, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original plaintext")
	}
	
	// Test with wrong AAD should fail
	wrongAAD := []byte("wrong aad")
	_, err = suite.Decrypt(aeadKey, nonce, ciphertext, wrongAAD)
	if err == nil {
		t.Error("Decryption should fail with wrong AAD")
	}
	
	// Test with corrupted ciphertext should fail
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF // flip bits
	
	_, err = suite.Decrypt(aeadKey, nonce, corruptedCiphertext, aad)
	if err == nil {
		t.Error("Decryption should fail with corrupted ciphertext")
	}
}

func TestQSP1Suite_Signing(t *testing.T) {
	suite := NewQSP1Suite()
	
	// Generate test key pair
	pub, priv, err := suite.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	
	message := []byte("test message for signing")
	
	// Sign
	signature, err := suite.Sign(priv, message)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Invalid signature length: got %d, want %d", len(signature), ed25519.SignatureSize)
	}
	
	// Verify
	err = suite.Verify(pub, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify valid signature: %v", err)
	}
	
	// Test with wrong message should fail
	wrongMessage := []byte("different message")
	err = suite.Verify(pub, wrongMessage, signature)
	if err == nil {
		t.Error("Verification should fail with wrong message")
	}
	
	// Test with corrupted signature should fail
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xFF // flip bits
	
	err = suite.Verify(pub, message, corruptedSig)
	if err == nil {
		t.Error("Verification should fail with corrupted signature")
	}
}