import { ed25519 } from '@noble/curves/ed25519';

/** Canonical, nonidentity public keys in the prime-order subgroup. */
export function isValidEd25519PublicKey(publicKey: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    const point = ed25519.ExtendedPoint.fromHex(publicKey, false);
    return !point.isSmallOrder() && point.isTorsionFree() &&
      point.toRawBytes().every((byte, i) => byte === publicKey[i]);
  } catch { return false; }
}

/** Strict Ed25519 profile shared by QSP, relay authentication and charters.
 * R must be canonical and in the prime subgroup (identity is allowed).
 * With prime-subgroup A and R, Noble's cofactored equation is equivalent to
 * the uncofactored equation used by Go. Noble enforces canonical S < L. */
export function verifyEd25519Signature(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (!isValidEd25519PublicKey(publicKey) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
    const r = signature.subarray(0, 32), point = ed25519.ExtendedPoint.fromHex(r, false);
    if (!point.isTorsionFree() || !point.toRawBytes().every((byte, i) => byte === r[i])) return false;
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch { return false; }
}
