import { edwardsToMontgomeryPub, x25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
/**
 * Convert an Ed25519 public key to an X25519 public key.
 * Uses the standard birational map (RFC 7748).
 */
export function ed25519PublicKeyToX25519(edPK) {
    if (edPK.length !== 32) {
        throw new Error(`invalid Ed25519 public key length: ${edPK.length}`);
    }
    return edwardsToMontgomeryPub(edPK);
}
/**
 * Convert an Ed25519 private key (64-byte seed+pub) to an X25519 private key.
 * Uses the same clamping as libsodium crypto_sign_ed25519_sk_to_curve25519.
 */
export function ed25519PrivateKeyToX25519(edSK) {
    if (edSK.length !== 64) {
        throw new Error(`invalid Ed25519 private key length: ${edSK.length}`);
    }
    // Hash the seed (first 32 bytes of Ed25519 private key)
    const h = sha512(edSK.slice(0, 32));
    // Clamp (same as Go/libsodium)
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    return h.slice(0, 32);
}
/**
 * Generate an ephemeral X25519 keypair.
 */
export function generateX25519Keypair() {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { publicKey, privateKey };
}
/**
 * Compute a shared secret from a private key and a public key via X25519 DH.
 */
export function x25519SharedSecret(privateKey, publicKey) {
    return x25519.getSharedSecret(privateKey, publicKey);
}
//# sourceMappingURL=x25519.js.map