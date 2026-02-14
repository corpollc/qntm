package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// Ed25519PublicKeyToX25519 converts an Ed25519 public key to an X25519 public key
// using the standard birational map (RFC 7748 / libsodium crypto_sign_ed25519_pk_to_curve25519).
func Ed25519PublicKeyToX25519(edPK ed25519.PublicKey) ([]byte, error) {
	if len(edPK) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(edPK))
	}

	// Decode the Ed25519 point
	p, err := new(edwards25519.Point).SetBytes(edPK)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}

	// Convert to Montgomery form (X25519)
	return p.BytesMontgomery(), nil
}

// Ed25519PrivateKeyToX25519 converts an Ed25519 private key to an X25519 private key.
// Uses the same clamping as libsodium crypto_sign_ed25519_sk_to_curve25519.
func Ed25519PrivateKeyToX25519(edSK ed25519.PrivateKey) ([]byte, error) {
	if len(edSK) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(edSK))
	}

	// Hash the seed (first 32 bytes of Ed25519 private key)
	h := sha512.Sum512(edSK[:32])

	// Clamp
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	x25519SK := make([]byte, 32)
	copy(x25519SK, h[:32])
	return x25519SK, nil
}

// GenerateX25519Keypair generates an ephemeral X25519 keypair.
func GenerateX25519Keypair() (privateKey, publicKey []byte, err error) {
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	pk, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute X25519 public key: %w", err)
	}

	return sk, pk, nil
}

// X25519SharedSecret computes a shared secret from a private key and a public key.
func X25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	ss, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}
	return ss, nil
}
