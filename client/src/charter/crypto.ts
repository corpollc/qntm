import { isValidEd25519PublicKey, verifyEd25519Signature } from '../crypto/ed25519.js';

/** Charter keys use canonical, non-identity points in the prime-order subgroup. */
export function validateCharterPublicKey(publicKey: Uint8Array): void {
  if (!isValidEd25519PublicKey(publicKey)) {
    throw new Error('Invalid prime-order Ed25519 charter key');
  }
}

export function verifyCharterSignature(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  validateCharterPublicKey(publicKey);
  return verifyEd25519Signature(publicKey, message, signature);
}
