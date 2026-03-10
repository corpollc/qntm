/**
 * Convert an Ed25519 public key to an X25519 public key.
 * Uses the standard birational map (RFC 7748).
 */
export declare function ed25519PublicKeyToX25519(edPK: Uint8Array): Uint8Array;
/**
 * Convert an Ed25519 private key (64-byte seed+pub) to an X25519 private key.
 * Uses the same clamping as libsodium crypto_sign_ed25519_sk_to_curve25519.
 */
export declare function ed25519PrivateKeyToX25519(edSK: Uint8Array): Uint8Array;
/**
 * Generate an ephemeral X25519 keypair.
 */
export declare function generateX25519Keypair(): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
};
/**
 * Compute a shared secret from a private key and a public key via X25519 DH.
 */
export declare function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
