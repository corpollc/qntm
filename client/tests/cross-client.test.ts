/**
 * Cross-client compatibility tests.
 * Verifies that TypeScript crypto primitives produce identical output to the shared spec vectors.
 * Regenerate vectors after any wire-format or crypto spec change:
 *   (cd attic/go && go run ./crosstest/generate_vectors.go > ../../client/tests/vectors.json)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  QSP1Suite,
  marshalCanonical, unmarshalCanonical,
  ed25519PublicKeyToX25519, ed25519PrivateKeyToX25519,
  deriveConversationKeys,
  decryptMessage, deserializeEnvelope,
  keyIDFromPublicKey, keyIDToString,
  signRequest, hashRequest, signApproval, verifyRequest, verifyApproval,
} from '../src/index.js';
import { ed25519 } from '@noble/curves/ed25519';

const vectors = JSON.parse(readFileSync(join(__dirname, 'vectors.json'), 'utf-8'));

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const suite = new QSP1Suite();

describe('Cross-Client: Identity', () => {
  it('derives same public key from seed', () => {
    const seed = hexToBytes(vectors.seed);
    const pubKey = ed25519.getPublicKey(seed);
    expect(bytesToHex(pubKey)).toBe(vectors.identity_vectors.public_key);
  });

  it('derives same key ID from public key', () => {
    const pubKey = hexToBytes(vectors.identity_vectors.public_key);
    const keyID = suite.computeKeyID(pubKey);
    expect(bytesToHex(keyID)).toBe(vectors.identity_vectors.key_id);
  });
});

describe('Cross-Client: CBOR Encoding', () => {
  for (const vec of vectors.cbor_vectors) {
    it(`matches Go canonical CBOR for ${vec.name}`, () => {
      // Convert the JSON input back to the appropriate types
      const input = convertCBORInput(vec.input);
      const encoded = marshalCanonical(input);
      expect(bytesToHex(encoded)).toBe(vec.encoded);
    });
  }
});

function looksLikeBase64(s: string): boolean {
  return /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0 && s.length > 0;
}

function convertCBORInput(input: any): any {
  if (input === null || input === undefined) return input;
  if (Array.isArray(input)) return input.map(convertCBORInput);

  if (typeof input === 'object') {
    const result: Record<string, any> = {};
    for (const [key, value] of Object.entries(input)) {
      if (typeof value === 'string' && looksLikeBase64(value)) {
        // Go encodes []byte as base64 in JSON
        try {
          result[key] = Uint8Array.from(atob(value), c => c.charCodeAt(0));
        } catch {
          result[key] = convertCBORInput(value);
        }
      } else {
        result[key] = convertCBORInput(value);
      }
    }
    return result;
  }

  return input;
}

describe('Cross-Client: Key Derivation', () => {
  it('derives same root key', () => {
    const invSecret = hexToBytes(vectors.key_derivation.invite_secret);
    const invSalt = hexToBytes(vectors.key_derivation.invite_salt);
    const convID = hexToBytes(vectors.key_derivation.conv_id);

    const rootKey = suite.deriveRootKey(invSecret, invSalt, convID);
    expect(bytesToHex(rootKey)).toBe(vectors.key_derivation.root_key);
  });

  it('derives same AEAD key', () => {
    const rootKey = hexToBytes(vectors.key_derivation.root_key);
    const convID = hexToBytes(vectors.key_derivation.conv_id);

    const { aeadKey, nonceKey } = suite.deriveConversationKeys(rootKey, convID);
    expect(bytesToHex(aeadKey)).toBe(vectors.key_derivation.aead_key);
    expect(bytesToHex(nonceKey)).toBe(vectors.key_derivation.nonce_key);
  });
});

describe('Cross-Client: Signing', () => {
  it('produces same signature as Go', () => {
    const seed = hexToBytes(vectors.signing_vector.seed);
    const message = hexToBytes(vectors.signing_vector.message);

    // Create 64-byte private key (seed + pubkey)
    const pubKey = ed25519.getPublicKey(seed);
    const fullPrivKey = new Uint8Array(64);
    fullPrivKey.set(seed, 0);
    fullPrivKey.set(pubKey, 32);

    const sig = suite.sign(fullPrivKey, message);
    expect(bytesToHex(sig)).toBe(vectors.signing_vector.signature);
  });

  it('verifies Go signature', () => {
    const pubKey = hexToBytes(vectors.signing_vector.public_key);
    const message = hexToBytes(vectors.signing_vector.message);
    const signature = hexToBytes(vectors.signing_vector.signature);

    expect(suite.verify(pubKey, message, signature)).toBe(true);
  });
});

describe('Cross-Client: Hashing', () => {
  it('produces same SHA-256 hash', () => {
    const input = hexToBytes(vectors.hash_vector.input);
    const hash = suite.hash(input);
    expect(bytesToHex(hash)).toBe(vectors.hash_vector.output);
  });
});

describe('Cross-Client: Nonce Derivation', () => {
  it('derives same nonce', () => {
    const nonceKey = hexToBytes(vectors.nonce_vector.nonce_key);
    const msgID = hexToBytes(vectors.nonce_vector.msg_id);

    const nonce = suite.deriveNonce(nonceKey, msgID);
    expect(bytesToHex(nonce)).toBe(vectors.nonce_vector.nonce);
  });
});

describe('Cross-Client: AEAD', () => {
  it('decrypts Go ciphertext', () => {
    const key = hexToBytes(vectors.aead_vector.key);
    const nonce = hexToBytes(vectors.aead_vector.nonce);
    const ciphertext = hexToBytes(vectors.aead_vector.ciphertext);
    const aad = hexToBytes(vectors.aead_vector.aad);
    const expectedPlaintext = hexToBytes(vectors.aead_vector.plaintext);

    const plaintext = suite.decrypt(key, nonce, ciphertext, aad);
    expect(plaintext).toEqual(expectedPlaintext);
  });

  it('produces same ciphertext as Go', () => {
    const key = hexToBytes(vectors.aead_vector.key);
    const nonce = hexToBytes(vectors.aead_vector.nonce);
    const plaintext = hexToBytes(vectors.aead_vector.plaintext);
    const aad = hexToBytes(vectors.aead_vector.aad);

    const ct = suite.encrypt(key, nonce, plaintext, aad);
    expect(bytesToHex(ct)).toBe(vectors.aead_vector.ciphertext);
  });
});

describe('Cross-Client: X25519', () => {
  it('converts Ed25519 public key to same X25519 key as Go', () => {
    const edPK = hexToBytes(vectors.x25519_vector.ed25519_public_key);
    const x25519PK = ed25519PublicKeyToX25519(edPK);
    expect(bytesToHex(x25519PK)).toBe(vectors.x25519_vector.x25519_public_key);
  });

  it('converts Ed25519 private key to same X25519 key as Go', () => {
    const seed = hexToBytes(vectors.x25519_vector.ed25519_seed);
    const pubKey = hexToBytes(vectors.x25519_vector.ed25519_public_key);
    const fullPrivKey = new Uint8Array(64);
    fullPrivKey.set(seed, 0);
    fullPrivKey.set(pubKey, 32);

    const x25519SK = ed25519PrivateKeyToX25519(fullPrivKey);
    expect(bytesToHex(x25519SK)).toBe(vectors.x25519_vector.x25519_private_key);
  });
});

describe('Cross-Client: Epoch Keys', () => {
  const groupKey = hexToBytes(vectors.epoch_vectors.group_key);
  const convID = hexToBytes(vectors.epoch_vectors.conv_id);

  for (const epochVec of vectors.epoch_vectors.epochs) {
    it(`matches Go epoch ${epochVec.epoch} keys`, () => {
      const keys = suite.deriveEpochKeys(groupKey, convID, epochVec.epoch);
      expect(bytesToHex(keys.aeadKey)).toBe(epochVec.aead_key);
      expect(bytesToHex(keys.nonceKey)).toBe(epochVec.nonce_key);
    });
  }
});

describe('Cross-Client: E2E Message', () => {
  it('decrypts Go-encrypted message', () => {
    const invSecret = hexToBytes(vectors.e2e_vector.invite_secret);
    const invSalt = hexToBytes(vectors.e2e_vector.invite_salt);
    const convID = hexToBytes(vectors.e2e_vector.conv_id);

    // Derive same keys as Go
    const rootKey = suite.deriveRootKey(invSecret, invSalt, convID);
    expect(bytesToHex(rootKey)).toBe(vectors.e2e_vector.root_key);

    const { aeadKey, nonceKey } = suite.deriveConversationKeys(rootKey, convID);
    expect(bytesToHex(aeadKey)).toBe(vectors.e2e_vector.aead_key);
    expect(bytesToHex(nonceKey)).toBe(vectors.e2e_vector.nonce_key);

    // Deserialize Go envelope
    const envelopeBytes = hexToBytes(vectors.e2e_vector.envelope_cbor);
    const envelope = deserializeEnvelope(envelopeBytes);

    // Decrypt with derived keys
    const conv = {
      id: convID,
      type: 'direct' as const,
      keys: { root: rootKey, aeadKey, nonceKey },
      participants: [],
      createdAt: new Date(),
      currentEpoch: 0,
    };

    const message = decryptMessage(envelope, conv);
    expect(message.verified).toBe(true);
    expect(message.inner.body_type).toBe(vectors.e2e_vector.body_type);
    expect(bytesToHex(new Uint8Array(message.inner.body))).toBe(vectors.e2e_vector.body);
    expect(bytesToHex(new Uint8Array(message.inner.sender_ik_pk))).toBe(vectors.e2e_vector.sender_pub_key);
  });
});

// ---------------------------------------------------------------------------
// Cross-Client: Gate Signing
// Verifies that TypeScript gate signing produces identical CBOR-encoded bytes
// and Ed25519 signatures as the Python client for the same inputs.
// Expected values were computed from this (canonical) TypeScript implementation.
// ---------------------------------------------------------------------------

describe('Cross-Client: Gate Signing', () => {
  // Deterministic seed shared with Python test (0x01..0x20)
  const gateSeed = hexToBytes(
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  );
  const gatePubKey = ed25519.getPublicKey(gateSeed);
  const gatePrivKey = new Uint8Array(64);
  gatePrivKey.set(gateSeed, 0);
  gatePrivKey.set(gatePubKey, 32);

  const EXPECTED_KID = 'ZbYGc9btiEvwHCwiLYKtoA';
  const EXPECTED_PAYLOAD_HASH =
    '4d4bbe59c6aad22442cde199a6a8a5f034405fcd78fb5a81c24ef249de1c45f1';
  const EXPECTED_REQUEST_HASH =
    '29c92653c04007fbabf1feae1e42ba3a16a00bc3e83d099763bfe60d5c85e94c';
  const EXPECTED_REQUEST_SIG =
    'ed6474e054e9b30a51c0c672f51bbb068251ef70bfdf87bd1b09757eaf3cabe3100de97271ae9bc9b71b0043ebf03af1088f36bb2c6402a705c5f0a5bbb31803';
  const EXPECTED_APPROVAL_SIG =
    'ad0a0eb3fb501b9c3c33996ce9eba67a28a581f41af1f57ca0f37777f200569105f0f0598c76f77ede439f9c9252df592e347a2301e25da90d4d2b951ee15005';

  it('derives same KID as Python', () => {
    const kid = keyIDFromPublicKey(gatePubKey);
    expect(keyIDToString(kid)).toBe(EXPECTED_KID);
  });

  it('produces same payload hash as Python', () => {
    const hash = suite.hash(new TextEncoder().encode('{"amount":100}'));
    expect(bytesToHex(hash)).toBe(EXPECTED_PAYLOAD_HASH);
  });

  it('produces same request hash as Python', () => {
    const signable = {
      conv_id: 'test-conv',
      request_id: 'req-001',
      verb: 'POST',
      target_endpoint: '/v1/transfers',
      target_service: 'bank-api',
      target_url: 'https://api.bank.test/v1/transfers',
      expires_at_unix: 1700000000,
      payload_hash: hexToBytes(EXPECTED_PAYLOAD_HASH),
      eligible_signer_kids: [EXPECTED_KID],
      required_approvals: 1,
    };
    const h = hashRequest(signable);
    expect(bytesToHex(h)).toBe(EXPECTED_REQUEST_HASH);
  });

  it('produces same request signature as Python', () => {
    const signable = {
      conv_id: 'test-conv',
      request_id: 'req-001',
      verb: 'POST',
      target_endpoint: '/v1/transfers',
      target_service: 'bank-api',
      target_url: 'https://api.bank.test/v1/transfers',
      expires_at_unix: 1700000000,
      payload_hash: hexToBytes(EXPECTED_PAYLOAD_HASH),
      eligible_signer_kids: [EXPECTED_KID],
      required_approvals: 1,
    };
    const sig = signRequest(gatePrivKey, signable);
    expect(bytesToHex(sig)).toBe(EXPECTED_REQUEST_SIG);
  });

  it('verifies request signature from Python', () => {
    const signable = {
      conv_id: 'test-conv',
      request_id: 'req-001',
      verb: 'POST',
      target_endpoint: '/v1/transfers',
      target_service: 'bank-api',
      target_url: 'https://api.bank.test/v1/transfers',
      expires_at_unix: 1700000000,
      payload_hash: hexToBytes(EXPECTED_PAYLOAD_HASH),
      eligible_signer_kids: [EXPECTED_KID],
      required_approvals: 1,
    };
    const sig = hexToBytes(EXPECTED_REQUEST_SIG);
    expect(verifyRequest(gatePubKey, signable, sig)).toBe(true);
  });

  it('produces same approval signature as Python', () => {
    const approval = {
      conv_id: 'test-conv',
      request_id: 'req-001',
      request_hash: hexToBytes(EXPECTED_REQUEST_HASH),
    };
    const sig = signApproval(gatePrivKey, approval);
    expect(bytesToHex(sig)).toBe(EXPECTED_APPROVAL_SIG);
  });

  it('verifies approval signature from Python', () => {
    const approval = {
      conv_id: 'test-conv',
      request_id: 'req-001',
      request_hash: hexToBytes(EXPECTED_REQUEST_HASH),
    };
    const sig = hexToBytes(EXPECTED_APPROVAL_SIG);
    expect(verifyApproval(gatePubKey, approval, sig)).toBe(true);
  });
});
