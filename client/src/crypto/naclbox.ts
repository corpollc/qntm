/**
 * NaCl box (X25519-XSalsa20-Poly1305) for secret provisioning.
 *
 * This implements the same protocol as Go's golang.org/x/crypto/nacl/box:
 *   1. Compute X25519 DH shared secret
 *   2. Derive symmetric key with HSalsa20
 *   3. Encrypt with XSalsa20-Poly1305
 *
 * Wire format: nonce(24 bytes) || ciphertext(plaintext.length + 16 bytes poly1305 tag)
 */

import { x25519 } from '@noble/curves/ed25519';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { hsalsa } from '@noble/ciphers/salsa';
import { randomBytes } from '@noble/hashes/utils';
import { ed25519PrivateKeyToX25519, ed25519PublicKeyToX25519 } from './x25519.js';

/**
 * Derive NaCl box shared key from X25519 DH shared secret.
 * This matches the Go nacl/box precompute step: hsalsa20(sharedPoint, [0;16]).
 */
function boxSharedKey(dhShared: Uint8Array): Uint8Array {
  // NaCl box uses hsalsa20(dhShared, sigma=[0;16]) to derive the key.
  // hsalsa takes (sigma, key, input) where we use the DH shared secret as key
  // and 16 zero bytes as input.
  const sigma = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
  ]);
  // Copy to aligned buffer for Uint32Array view safety
  const kBuf = new ArrayBuffer(32);
  new Uint8Array(kBuf).set(dhShared);
  const k = new Uint32Array(kBuf);
  const zeroInput = new Uint32Array(4); // 16 zero bytes as 4 uint32
  const out = new Uint32Array(8);
  hsalsa(sigma, k, zeroInput, out);
  return new Uint8Array(out.buffer);
}

/**
 * Seal encrypts plaintext using NaCl box (X25519-XSalsa20-Poly1305).
 * Compatible with Go's nacl/box.Seal.
 *
 * @param senderEdPrivKey - Ed25519 private key (64 bytes)
 * @param recipientEdPubKey - Ed25519 public key (32 bytes)
 * @param plaintext - data to encrypt
 * @returns nonce(24) || ciphertext
 */
export function sealSecret(
  senderEdPrivKey: Uint8Array,
  recipientEdPubKey: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // Convert Ed25519 keys to X25519
  const senderX = ed25519PrivateKeyToX25519(senderEdPrivKey);
  const recipientX = ed25519PublicKeyToX25519(recipientEdPubKey);

  // X25519 DH
  const dhShared = x25519.getSharedSecret(senderX, recipientX);

  // Derive box key
  const key = boxSharedKey(dhShared);

  // Generate random nonce
  const nonce = randomBytes(24);

  // Encrypt
  const cipher = xsalsa20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  // Wire format: nonce || ciphertext
  const result = new Uint8Array(24 + ciphertext.length);
  result.set(nonce);
  result.set(ciphertext, 24);
  return result;
}

/**
 * Open decrypts a NaCl box sealed by sealSecret.
 * Compatible with Go's nacl/box.Open.
 *
 * @param recipientEdPrivKey - Ed25519 private key (64 bytes)
 * @param senderEdPubKey - Ed25519 public key (32 bytes)
 * @param sealed - nonce(24) || ciphertext
 * @returns decrypted plaintext
 */
export function openSecret(
  recipientEdPrivKey: Uint8Array,
  senderEdPubKey: Uint8Array,
  sealed: Uint8Array,
): Uint8Array {
  if (sealed.length < 24 + 16) {
    throw new Error('sealed data too short');
  }

  // Convert Ed25519 keys to X25519
  const recipientX = ed25519PrivateKeyToX25519(recipientEdPrivKey);
  const senderX = ed25519PublicKeyToX25519(senderEdPubKey);

  // X25519 DH
  const dhShared = x25519.getSharedSecret(recipientX, senderX);

  // Derive box key
  const key = boxSharedKey(dhShared);

  // Extract nonce and ciphertext
  const nonce = sealed.slice(0, 24);
  const ciphertext = sealed.slice(24);

  // Decrypt
  const cipher = xsalsa20poly1305(key, nonce);
  return cipher.decrypt(ciphertext);
}
