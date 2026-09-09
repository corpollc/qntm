import { ed25519 } from '@noble/curves/ed25519';

/** Charter keys use canonical, non-identity points in the prime-order subgroup. */
export function validateCharterPublicKey(publicKey: Uint8Array): void {
  const point = ed25519.ExtendedPoint.fromHex(publicKey, false);
  if (publicKey.length !== 32 || point.isSmallOrder() || !point.isTorsionFree() ||
      !point.toRawBytes().every((byte, i) => byte === publicKey[i])) {
    throw new Error('Invalid prime-order Ed25519 charter key');
  }
}

export function verifyCharterSignature(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  validateCharterPublicKey(publicKey);
  // Noble also clears the cofactor with zip215:false. With prime-order A and R,
  // that equation is equivalent to Go's uncofactored equation.
  try {
    if (signature.length !== 64 || !ed25519.ExtendedPoint.fromHex(signature.subarray(0, 32), false).isTorsionFree()) return false;
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch { return false; }
}
