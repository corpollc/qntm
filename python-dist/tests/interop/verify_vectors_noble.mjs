#!/usr/bin/env node
/**
 * Verify Ed25519→X25519 interop vectors using @noble/curves
 * 
 * Tests the birational equivalence (RFC 7748 §4.1) that maps
 * Ed25519 public keys to X25519 public keys.
 * 
 * Compatible with aeoess/agent-passport-system's crypto stack.
 * 
 * Run: node verify_vectors_noble.mjs
 * Requires: @noble/curves (installed in repo root)
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { mod } from '@noble/curves/abstract/modular.js';

// Ed25519 field prime: p = 2^255 - 19
const P = 2n ** 255n - 19n;

/**
 * Convert Ed25519 public key bytes to X25519 public key bytes.
 * Uses the birational map: u = (1 + y) / (1 - y) mod p
 * where y is the y-coordinate of the Ed25519 point.
 */
function ed25519PubToX25519(edPubBytes) {
  // Ed25519 public key is the compressed y-coordinate (little-endian)
  // with the sign of x in the high bit
  const y = bytesToBigInt(edPubBytes) & ((1n << 255n) - 1n); // mask off high bit
  
  // Birational map: u = (1 + y) * inverse(1 - y) mod p
  const numerator = mod(1n + y, P);
  const denominator = mod(1n - y, P);
  const u = mod(numerator * modInverse(denominator, P), P);
  
  // Encode as 32-byte little-endian
  return bigIntToBytes(u, 32);
}

function modInverse(a, p) {
  // Fermat's little theorem: a^(p-2) mod p
  return modPow(mod(a, p), p - 2n, p);
}

function modPow(base, exp, modulus) {
  let result = 1n;
  base = mod(base, modulus);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, modulus);
    exp >>= 1n;
    base = mod(base * base, modulus);
  }
  return result;
}

function bytesToBigInt(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function bigIntToBytes(n, length) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return bytes;
}

// Known-answer vectors from VECTORS.md
const VECTORS = [
  {
    name: 'Vector 1 (zero seed)',
    seed: '0000000000000000000000000000000000000000000000000000000000000000',
    ed25519_pk: '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29',
    x25519_pk: '5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d',
  },
  {
    name: 'Vector 2 (incrementing bytes)',
    seed: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    ed25519_pk: '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
    x25519_pk: '4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38',
  },
  {
    name: 'Vector 3 (all 0xFF)',
    seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    ed25519_pk: '76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5',
    x25519_pk: 'd1fa3f01826bd8b78e057c086c7b22c7ad4358ca918099cd7b7e5d3acd7e285b',
  },
  {
    name: 'Vector 4 (RFC 8032 test vector 1)',
    seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    ed25519_pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    x25519_pk: 'd85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e',
  },
  {
    name: 'Vector 5 (random)',
    seed: 'a3c4e2f1b8d7954c6e0f3a2b1d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
    ed25519_pk: 'ea21e5719500ca99648e2693eec7dd40ff1ace600f5a70a1071f797be6d23316',
    x25519_pk: '2eb1f20188c191df7f49958c80baebd923f9f88fe3e5bbf79cc1201a417f3b38',
  },
];

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

let passed = 0;
let failed = 0;

console.log('Ed25519 → X25519 Interop Vector Verification (@noble/curves)\n');

for (const v of VECTORS) {
  const seed = hexToBytes(v.seed);
  
  // Derive Ed25519 public key from seed using @noble/curves
  const edPubKey = ed25519.getPublicKey(seed);
  const edPubHex = bytesToHex(edPubKey);
  
  // Convert Ed25519 public key to X25519 using birational map
  const xPubKey = ed25519PubToX25519(edPubKey);
  const xPubHex = bytesToHex(xPubKey);
  
  const edMatch = edPubHex === v.ed25519_pk;
  const xMatch = xPubHex === v.x25519_pk;
  
  if (edMatch && xMatch) {
    console.log(`✅ ${v.name}: PASS`);
    passed++;
  } else {
    console.log(`❌ ${v.name}: FAIL`);
    if (!edMatch) {
      console.log(`   Ed25519 PK: expected ${v.ed25519_pk}`);
      console.log(`   Ed25519 PK: got      ${edPubHex}`);
    }
    if (!xMatch) {
      console.log(`   X25519 PK:  expected ${v.x25519_pk}`);
      console.log(`   X25519 PK:  got      ${xPubHex}`);
    }
    failed++;
  }
}

console.log(`\n${passed}/${passed + failed} vectors passed`);
if (failed === 0) {
  console.log('\n🎉 All vectors match! Ed25519→X25519 derivation is compatible');
  console.log('   between qntm (Python/cryptography) and @noble/curves (TypeScript).');
}
process.exit(failed > 0 ? 1 : 0);
