// Public synthetic keys and deliberately invalid signatures; never operator keys.
import { writeFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
const hex = b => Buffer.from(b).toString('hex');
const le = n => new Uint8Array(Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse());
const integer = b => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
const seed = new Uint8Array(32).fill(17), key = ed25519.getPublicKey(seed);
const message = new TextEncoder().encode('qntm signature acceptance profile');
const signature = ed25519.sign(message, seed), identity = ed25519.ExtendedPoint.ZERO.toRawBytes();
const torsion = ed25519.ExtendedPoint.fromHex(new Uint8Array(32));
const scalar = ed25519.utils.getExtendedPublicKey(seed).scalar, order = ed25519.CURVE.n;
const cases = [];
function add(name, publicKey, sig, keyValid, valid, body = message) {
  cases.push({ name, public_key_hex: hex(publicKey), message_hex: hex(body), signature_hex: hex(sig), key_valid: keyValid, valid });
}
add('ordinary signature', key, signature, true, true);
add('wrong message', key, signature, true, false, new TextEncoder().encode('different'));
add('identity-key forgery', identity, new Uint8Array([...identity, ...new Uint8Array(32)]), false, false);
add('zero-key forgery', new Uint8Array(32), new Uint8Array(64), false, false, new TextEncoder().encode('body'));
for (const [name, publicKey] of [
  ['mixed-order key', ed25519.ExtendedPoint.BASE.add(torsion).toRawBytes()],
  ['noncanonical identity', le(2n ** 255n - 18n)],
  ['identity with negative zero', le(2n ** 255n + 1n)],
  ['invalid point', new Uint8Array(32).fill(255)],
  ['short key', key.slice(0, 31)], ['long key', new Uint8Array([...key, 0])],
]) add(name, publicKey, signature, false, false);
for (const [name, r, nonce, valid] of [
  ['canonical identity R', identity, 0n, true],
  ['mixed-order R', ed25519.ExtendedPoint.BASE.add(torsion).toRawBytes(), 1n, false],
  ['small-order R', torsion.toRawBytes(), 0n, false],
  ['noncanonical R', le(2n ** 255n - 18n), 0n, false],
  ['negative zero R', le(2n ** 255n + 1n), 0n, false],
]) {
  // Exercise the installed permissive verifier, which re-encodes R for hashing.
  const hashedR = ed25519.ExtendedPoint.fromHex(r, true).toRawBytes();
  const challenge = integer(sha512(new Uint8Array([...hashedR, ...key, ...message]))) % order;
  const sig = new Uint8Array([...r, ...le((nonce + challenge * scalar) % order)]);
  if (!ed25519.verify(sig, message, key)) throw new Error(`Fixture does not exercise permissive verification: ${name}`);
  add(name, key, sig, true, valid);
}
add('scalar equals order', key, new Uint8Array([...signature.slice(0, 32), ...le(order)]), true, false);
add('scalar plus order', key, new Uint8Array([...signature.slice(0, 32), ...le(integer(signature.slice(32)) + order)]), true, false);
add('short signature', key, signature.slice(0, 63), true, false);
add('long signature', key, new Uint8Array([...signature, 0]), true, false);
// RFC 8032 section 7.1 TEST 1: independent known-answer positive control.
add('RFC 8032 empty message', Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex'),
  Buffer.from('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex'), true, true, new Uint8Array());
writeFileSync(new URL('../../specs/test-vectors/ed25519-verification.json', import.meta.url), JSON.stringify({
  description: 'Canonical nonidentity prime-order public keys; canonical prime-subgroup R (identity allowed), S < L, uncofactored equation. Public test material only.', cases,
}, null, 2) + '\n');
