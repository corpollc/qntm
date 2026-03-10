import { describe, it, expect } from 'vitest';
import {
  QSP1Suite,
  generateIdentity, keyIDFromPublicKey, verifyKeyID,
  serializeIdentity, deserializeIdentity,
  publicKeyToString, publicKeyFromString,
  keyIDToString, keyIDFromString,
  generateConversationID, generateMessageID,
  validateIdentity,
  base64UrlEncode, base64UrlDecode,
  createInvite, serializeInvite, deserializeInvite, validateInvite,
  inviteToToken, inviteToURL, inviteFromURL,
  deriveConversationKeys, createConversation,
  addParticipant, isParticipant,
  createMessage, decryptMessage, verifyMessageSignature,
  validateEnvelope, validateInnerPayload,
  serializeEnvelope, deserializeEnvelope,
  checkExpiry, defaultTTL, defaultHandshakeTTL,
  signRequest, verifyRequest, signApproval, verifyApproval,
  hashRequest, computePayloadHash,
  lookupThreshold,
  marshalCanonical, unmarshalCanonical,
  ed25519PublicKeyToX25519, ed25519PrivateKeyToX25519,
  generateX25519Keypair, x25519SharedSecret,
  PROTOCOL_VERSION, DEFAULT_SUITE, PROTO_PREFIX,
  INFO_ROOT, INFO_AEAD, INFO_NONCE,
  INFO_AEAD_V11, INFO_NONCE_V11, INFO_WRAP_V11,
  DEFAULT_TTL_SECONDS, DEFAULT_HANDSHAKE_TTL_SECONDS,
  CLOCK_SKEW_SECONDS, MAX_GROUP_SIZE, EPOCH_GRACE_PERIOD_SECONDS,
} from '../src/index.js';
import type {
  Identity, InvitePayload, ConversationKeys, Conversation,
  OuterEnvelope, InnerPayload, ThresholdRule, GateSignable, ApprovalSignable,
} from '../src/types.js';

// === 1. Crypto Constants ===
describe('Crypto Constants', () => {
  it('has correct protocol version', () => {
    expect(PROTOCOL_VERSION).toBe(1);
  });

  it('has correct default suite', () => {
    expect(DEFAULT_SUITE).toBe('QSP-1');
  });

  it('has correct proto prefix', () => {
    expect(PROTO_PREFIX).toBe('qntm/qsp/v1');
  });

  it('has correct HKDF info strings', () => {
    expect(INFO_ROOT).toBe('qntm/qsp/v1/root');
    expect(INFO_AEAD).toBe('qntm/qsp/v1/aead');
    expect(INFO_NONCE).toBe('qntm/qsp/v1/nonce');
    expect(INFO_AEAD_V11).toBe('qntm/qsp/v1.1/aead');
    expect(INFO_NONCE_V11).toBe('qntm/qsp/v1.1/nonce');
    expect(INFO_WRAP_V11).toBe('qntm/qsp/v1.1/wrap');
  });

  it('has correct TTL defaults', () => {
    expect(DEFAULT_TTL_SECONDS).toBe(30 * 86400);
    expect(DEFAULT_HANDSHAKE_TTL_SECONDS).toBe(7 * 86400);
  });

  it('has correct clock skew', () => {
    expect(CLOCK_SKEW_SECONDS).toBe(300);
  });

  it('has correct max group size', () => {
    expect(MAX_GROUP_SIZE).toBe(128);
  });

  it('has correct epoch grace period', () => {
    expect(EPOCH_GRACE_PERIOD_SECONDS).toBe(86400);
  });
});

// === 2. QSP1Suite Core Crypto ===
describe('QSP1Suite', () => {
  const suite = new QSP1Suite();

  it('reports correct suite name', () => {
    expect(suite.name()).toBe('QSP-1');
  });

  describe('Identity Key Generation', () => {
    it('generates valid keypair', () => {
      const { publicKey, privateKey } = suite.generateIdentityKey();
      expect(publicKey.length).toBe(32);
      expect(privateKey.length).toBe(64);
      // Private key contains public key in last 32 bytes
      expect(privateKey.slice(32)).toEqual(publicKey);
    });

    it('generates unique keypairs', () => {
      const kp1 = suite.generateIdentityKey();
      const kp2 = suite.generateIdentityKey();
      expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    });
  });

  describe('Key ID', () => {
    it('computes 16-byte key ID from public key', () => {
      const { publicKey } = suite.generateIdentityKey();
      const keyID = suite.computeKeyID(publicKey);
      expect(keyID.length).toBe(16);
    });

    it('is deterministic', () => {
      const { publicKey } = suite.generateIdentityKey();
      const id1 = suite.computeKeyID(publicKey);
      const id2 = suite.computeKeyID(publicKey);
      expect(id1).toEqual(id2);
    });

    it('is different for different keys', () => {
      const kp1 = suite.generateIdentityKey();
      const kp2 = suite.generateIdentityKey();
      expect(suite.computeKeyID(kp1.publicKey)).not.toEqual(suite.computeKeyID(kp2.publicKey));
    });
  });

  describe('Group Key', () => {
    it('generates 32-byte group key', () => {
      const gk = suite.generateGroupKey();
      expect(gk.length).toBe(32);
    });
  });

  describe('Signing and Verification', () => {
    it('sign and verify round-trip', () => {
      const { publicKey, privateKey } = suite.generateIdentityKey();
      const message = new TextEncoder().encode('hello world');
      const sig = suite.sign(privateKey, message);
      expect(sig.length).toBe(64);
      expect(suite.verify(publicKey, message, sig)).toBe(true);
    });

    it('rejects tampered message', () => {
      const { publicKey, privateKey } = suite.generateIdentityKey();
      const message = new TextEncoder().encode('hello world');
      const sig = suite.sign(privateKey, message);
      const tampered = new TextEncoder().encode('hello world!');
      expect(suite.verify(publicKey, tampered, sig)).toBe(false);
    });

    it('rejects wrong key', () => {
      const kp1 = suite.generateIdentityKey();
      const kp2 = suite.generateIdentityKey();
      const message = new TextEncoder().encode('test');
      const sig = suite.sign(kp1.privateKey, message);
      expect(suite.verify(kp2.publicKey, message, sig)).toBe(false);
    });
  });

  describe('Hashing', () => {
    it('produces 32-byte SHA-256 hash', () => {
      const data = new TextEncoder().encode('test data');
      const hash = suite.hash(data);
      expect(hash.length).toBe(32);
    });

    it('is deterministic', () => {
      const data = new TextEncoder().encode('test data');
      expect(suite.hash(data)).toEqual(suite.hash(data));
    });
  });

  describe('AEAD Encryption', () => {
    it('encrypt and decrypt round-trip', () => {
      const key = suite.generateGroupKey();
      const nonce = new Uint8Array(24);
      crypto.getRandomValues(nonce);
      const plaintext = new TextEncoder().encode('secret message');
      const aad = new TextEncoder().encode('additional data');

      const ciphertext = suite.encrypt(key, nonce, plaintext, aad);
      expect(ciphertext.length).toBeGreaterThan(plaintext.length); // includes poly1305 tag

      const decrypted = suite.decrypt(key, nonce, ciphertext, aad);
      expect(decrypted).toEqual(plaintext);
    });

    it('rejects tampered ciphertext', () => {
      const key = suite.generateGroupKey();
      const nonce = new Uint8Array(24);
      const plaintext = new TextEncoder().encode('secret');
      const aad = new TextEncoder().encode('aad');

      const ciphertext = suite.encrypt(key, nonce, plaintext, aad);
      ciphertext[0] ^= 0xff; // tamper

      expect(() => suite.decrypt(key, nonce, ciphertext, aad)).toThrow();
    });

    it('rejects wrong AAD', () => {
      const key = suite.generateGroupKey();
      const nonce = new Uint8Array(24);
      const plaintext = new TextEncoder().encode('secret');
      const aad = new TextEncoder().encode('correct aad');

      const ciphertext = suite.encrypt(key, nonce, plaintext, aad);
      const wrongAAD = new TextEncoder().encode('wrong aad');

      expect(() => suite.decrypt(key, nonce, ciphertext, wrongAAD)).toThrow();
    });
  });

  describe('Key Derivation', () => {
    it('derives root key deterministically', () => {
      const secret = new Uint8Array(32);
      const salt = new Uint8Array(32);
      const convID = new Uint8Array(16);
      crypto.getRandomValues(secret);
      crypto.getRandomValues(salt);
      crypto.getRandomValues(convID);

      const root1 = suite.deriveRootKey(secret, salt, convID);
      const root2 = suite.deriveRootKey(secret, salt, convID);
      expect(root1).toEqual(root2);
      expect(root1.length).toBe(32);
    });

    it('derives conversation keys deterministically', () => {
      const rootKey = new Uint8Array(32);
      const convID = new Uint8Array(16);
      crypto.getRandomValues(rootKey);
      crypto.getRandomValues(convID);

      const keys1 = suite.deriveConversationKeys(rootKey, convID);
      const keys2 = suite.deriveConversationKeys(rootKey, convID);
      expect(keys1.aeadKey).toEqual(keys2.aeadKey);
      expect(keys1.nonceKey).toEqual(keys2.nonceKey);
      expect(keys1.aeadKey.length).toBe(32);
      expect(keys1.nonceKey.length).toBe(32);
    });

    it('derives different keys for different convIDs', () => {
      const rootKey = new Uint8Array(32);
      crypto.getRandomValues(rootKey);
      const convID1 = new Uint8Array(16);
      const convID2 = new Uint8Array(16);
      crypto.getRandomValues(convID1);
      crypto.getRandomValues(convID2);

      const keys1 = suite.deriveConversationKeys(rootKey, convID1);
      const keys2 = suite.deriveConversationKeys(rootKey, convID2);
      expect(keys1.aeadKey).not.toEqual(keys2.aeadKey);
    });
  });

  describe('Epoch Keys', () => {
    it('epoch 0 matches conversation keys', () => {
      const groupKey = suite.generateGroupKey();
      const convID = new Uint8Array(16);
      crypto.getRandomValues(convID);

      const epochKeys = suite.deriveEpochKeys(groupKey, convID, 0);
      const convKeys = suite.deriveConversationKeys(groupKey, convID);
      expect(epochKeys.aeadKey).toEqual(convKeys.aeadKey);
      expect(epochKeys.nonceKey).toEqual(convKeys.nonceKey);
    });

    it('epoch 1+ uses v1.1 derivation', () => {
      const groupKey = suite.generateGroupKey();
      const convID = new Uint8Array(16);
      crypto.getRandomValues(convID);

      const e0 = suite.deriveEpochKeys(groupKey, convID, 0);
      const e1 = suite.deriveEpochKeys(groupKey, convID, 1);
      expect(e0.aeadKey).not.toEqual(e1.aeadKey);
    });

    it('different epochs produce different keys', () => {
      const groupKey = suite.generateGroupKey();
      const convID = new Uint8Array(16);
      crypto.getRandomValues(convID);

      const e1 = suite.deriveEpochKeys(groupKey, convID, 1);
      const e2 = suite.deriveEpochKeys(groupKey, convID, 2);
      expect(e1.aeadKey).not.toEqual(e2.aeadKey);
      expect(e1.nonceKey).not.toEqual(e2.nonceKey);
    });
  });

  describe('Nonce Derivation', () => {
    it('derives 24-byte nonce', () => {
      const nonceKey = new Uint8Array(32);
      const msgID = new Uint8Array(16);
      crypto.getRandomValues(nonceKey);
      crypto.getRandomValues(msgID);

      const nonce = suite.deriveNonce(nonceKey, msgID);
      expect(nonce.length).toBe(24);
    });

    it('is deterministic', () => {
      const nonceKey = new Uint8Array(32);
      const msgID = new Uint8Array(16);
      crypto.getRandomValues(nonceKey);
      crypto.getRandomValues(msgID);

      expect(suite.deriveNonce(nonceKey, msgID)).toEqual(suite.deriveNonce(nonceKey, msgID));
    });
  });

  describe('Key Wrapping', () => {
    it('wrap and unwrap round-trip', () => {
      const newGroupKey = suite.generateGroupKey();
      const recipient = suite.generateIdentityKey();
      const recipientKID = suite.computeKeyID(recipient.publicKey);
      const convID = new Uint8Array(16);
      crypto.getRandomValues(convID);

      const wrapped = suite.wrapKeyForRecipient(newGroupKey, recipient.publicKey, recipientKID, convID);
      const unwrapped = suite.unwrapKeyForRecipient(wrapped, recipient.privateKey, recipientKID, convID);
      expect(unwrapped).toEqual(newGroupKey);
    });

    it('rejects wrong recipient', () => {
      const newGroupKey = suite.generateGroupKey();
      const recipient = suite.generateIdentityKey();
      const wrongRecipient = suite.generateIdentityKey();
      const recipientKID = suite.computeKeyID(recipient.publicKey);
      const convID = new Uint8Array(16);
      crypto.getRandomValues(convID);

      const wrapped = suite.wrapKeyForRecipient(newGroupKey, recipient.publicKey, recipientKID, convID);
      expect(() => {
        suite.unwrapKeyForRecipient(wrapped, wrongRecipient.privateKey, recipientKID, convID);
      }).toThrow();
    });
  });
});

// === 3. X25519 Conversion ===
describe('X25519', () => {
  const suite = new QSP1Suite();

  it('converts Ed25519 public key to X25519', () => {
    const { publicKey } = suite.generateIdentityKey();
    const x25519PK = ed25519PublicKeyToX25519(publicKey);
    expect(x25519PK.length).toBe(32);
  });

  it('converts Ed25519 private key to X25519', () => {
    const { privateKey } = suite.generateIdentityKey();
    const x25519SK = ed25519PrivateKeyToX25519(privateKey);
    expect(x25519SK.length).toBe(32);
  });

  it('generates X25519 keypair', () => {
    const { publicKey, privateKey } = generateX25519Keypair();
    expect(publicKey.length).toBe(32);
    expect(privateKey.length).toBe(32);
  });

  it('computes shared secret (ECDH)', () => {
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();

    const ssAlice = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const ssBob = x25519SharedSecret(bob.privateKey, alice.publicKey);
    expect(ssAlice).toEqual(ssBob);
  });

  it('Ed25519-to-X25519 shared secret works', () => {
    const aliceEd = suite.generateIdentityKey();
    const bobEd = suite.generateIdentityKey();

    const aliceX25519SK = ed25519PrivateKeyToX25519(aliceEd.privateKey);
    const bobX25519PK = ed25519PublicKeyToX25519(bobEd.publicKey);
    const bobX25519SK = ed25519PrivateKeyToX25519(bobEd.privateKey);
    const aliceX25519PK = ed25519PublicKeyToX25519(aliceEd.publicKey);

    const ss1 = x25519SharedSecret(aliceX25519SK, bobX25519PK);
    const ss2 = x25519SharedSecret(bobX25519SK, aliceX25519PK);
    expect(ss1).toEqual(ss2);
  });

  it('rejects invalid Ed25519 public key length', () => {
    expect(() => ed25519PublicKeyToX25519(new Uint8Array(16))).toThrow();
  });

  it('rejects invalid Ed25519 private key length', () => {
    expect(() => ed25519PrivateKeyToX25519(new Uint8Array(32))).toThrow();
  });
});

// === 4. CBOR Encoding ===
describe('CBOR Encoding', () => {
  it('marshal and unmarshal round-trip', () => {
    const obj = { hello: 'world', num: 42 };
    const data = marshalCanonical(obj);
    const decoded = unmarshalCanonical<{ hello: string; num: number }>(data);
    expect(decoded.hello).toBe('world');
    expect(decoded.num).toBe(42);
  });

  it('handles Uint8Array values', () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const obj = { data: bytes };
    const encoded = marshalCanonical(obj);
    const decoded = unmarshalCanonical<{ data: Uint8Array }>(encoded);
    expect(new Uint8Array(decoded.data)).toEqual(bytes);
  });

  it('canonical encoding sorts keys deterministically', () => {
    const obj1 = { z: 1, a: 2, m: 3 };
    const obj2 = { a: 2, m: 3, z: 1 };
    const enc1 = marshalCanonical(obj1);
    const enc2 = marshalCanonical(obj2);
    expect(enc1).toEqual(enc2);
  });

  it('sorts by key length first, then alphabetic', () => {
    const obj = { bb: 2, a: 1, ccc: 3 };
    const encoded = marshalCanonical(obj);
    const decoded = unmarshalCanonical<Record<string, number>>(encoded);
    const keys = Object.keys(decoded);
    // Should be sorted: 'a' (len 1), 'bb' (len 2), 'ccc' (len 3)
    expect(keys).toEqual(['a', 'bb', 'ccc']);
  });
});

// === 5. Identity ===
describe('Identity', () => {
  it('generates valid identity', () => {
    const id = generateIdentity();
    expect(id.publicKey.length).toBe(32);
    expect(id.privateKey.length).toBe(64);
    expect(id.keyID.length).toBe(16);
    expect(verifyKeyID(id.publicKey, id.keyID)).toBe(true);
  });

  it('validates identity', () => {
    const id = generateIdentity();
    expect(() => validateIdentity(id)).not.toThrow();
  });

  it('serialize and deserialize round-trip', () => {
    const id = generateIdentity();
    const data = serializeIdentity(id);
    const restored = deserializeIdentity(data);
    expect(restored.publicKey).toEqual(id.publicKey);
    expect(restored.privateKey).toEqual(id.privateKey);
    expect(restored.keyID).toEqual(id.keyID);
  });

  it('public key base64url round-trip', () => {
    const id = generateIdentity();
    const str = publicKeyToString(id.publicKey);
    const restored = publicKeyFromString(str);
    expect(restored).toEqual(id.publicKey);
  });

  it('key ID base64url round-trip', () => {
    const id = generateIdentity();
    const str = keyIDToString(id.keyID);
    const restored = keyIDFromString(str);
    expect(restored).toEqual(id.keyID);
  });

  it('generates unique conversation IDs', () => {
    const id1 = generateConversationID();
    const id2 = generateConversationID();
    expect(id1.length).toBe(16);
    expect(id2.length).toBe(16);
    expect(id1).not.toEqual(id2);
  });

  it('generates unique message IDs', () => {
    const id1 = generateMessageID();
    const id2 = generateMessageID();
    expect(id1.length).toBe(16);
    expect(id2.length).toBe(16);
    expect(id1).not.toEqual(id2);
  });
});

// === 6. Invites ===
describe('Invites', () => {
  it('creates valid invite', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    expect(invite.v).toBe(PROTOCOL_VERSION);
    expect(invite.suite).toBe(DEFAULT_SUITE);
    expect(invite.type).toBe('direct');
    expect(invite.conv_id.length).toBe(16);
    expect(invite.inviter_ik_pk).toEqual(id.publicKey);
    expect(invite.invite_salt.length).toBe(32);
    expect(invite.invite_secret.length).toBe(32);
  });

  it('creates group invite', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'group');
    expect(invite.type).toBe('group');
  });

  it('serialize and deserialize round-trip', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const data = serializeInvite(invite);
    const restored = deserializeInvite(data);
    expect(restored.v).toBe(invite.v);
    expect(restored.suite).toBe(invite.suite);
    expect(restored.type).toBe(invite.type);
    expect(new Uint8Array(restored.conv_id)).toEqual(new Uint8Array(invite.conv_id));
    expect(new Uint8Array(restored.invite_secret)).toEqual(new Uint8Array(invite.invite_secret));
  });

  it('token round-trip', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const token = inviteToToken(invite);
    expect(typeof token).toBe('string');
    const restored = inviteFromURL(token);
    expect(restored.v).toBe(invite.v);
    expect(new Uint8Array(restored.conv_id)).toEqual(new Uint8Array(invite.conv_id));
  });

  it('URL round-trip', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const url = inviteToURL(invite, 'https://qntm.example.com/invite');
    expect(url).toContain('https://qntm.example.com/invite#');
    const restored = inviteFromURL(url);
    expect(restored.v).toBe(invite.v);
    expect(new Uint8Array(restored.conv_id)).toEqual(new Uint8Array(invite.conv_id));
  });

  it('validates invite structure', () => {
    const invite: InvitePayload = {
      v: 999,
      suite: DEFAULT_SUITE,
      type: 'direct',
      conv_id: new Uint8Array(16),
      inviter_ik_pk: new Uint8Array(32),
      invite_salt: new Uint8Array(32),
      invite_secret: new Uint8Array(32),
    };
    expect(() => validateInvite(invite)).toThrow('unsupported protocol version');
  });
});

// === 7. Key Derivation from Invite ===
describe('Key Derivation', () => {
  it('derives conversation keys from invite', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const keys = deriveConversationKeys(invite);
    expect(keys.root.length).toBe(32);
    expect(keys.aeadKey.length).toBe(32);
    expect(keys.nonceKey.length).toBe(32);
  });

  it('is deterministic', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const keys1 = deriveConversationKeys(invite);
    const keys2 = deriveConversationKeys(invite);
    expect(keys1.root).toEqual(keys2.root);
    expect(keys1.aeadKey).toEqual(keys2.aeadKey);
    expect(keys1.nonceKey).toEqual(keys2.nonceKey);
  });

  it('different invites produce different keys', () => {
    const id = generateIdentity();
    const invite1 = createInvite(id, 'direct');
    const invite2 = createInvite(id, 'direct');
    const keys1 = deriveConversationKeys(invite1);
    const keys2 = deriveConversationKeys(invite2);
    expect(keys1.root).not.toEqual(keys2.root);
  });
});

// === 8. Conversations ===
describe('Conversations', () => {
  it('creates conversation from invite and keys', () => {
    const id = generateIdentity();
    const invite = createInvite(id, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);

    expect(conv.id).toEqual(invite.conv_id);
    expect(conv.type).toBe('direct');
    expect(conv.keys).toBe(keys);
    expect(conv.participants.length).toBe(1);
    expect(conv.currentEpoch).toBe(0);
  });

  it('adds participant', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);

    addParticipant(conv, bob.publicKey);
    expect(conv.participants.length).toBe(2);
    expect(isParticipant(conv, bob.publicKey)).toBe(true);
  });

  it('does not add duplicate participant', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);

    addParticipant(conv, bob.publicKey);
    addParticipant(conv, bob.publicKey); // duplicate
    expect(conv.participants.length).toBe(2);
  });

  it('isParticipant returns false for non-participant', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);

    expect(isParticipant(conv, bob.publicKey)).toBe(false);
  });
});

// === 9. Messages (E2E Encrypt/Decrypt) ===
describe('Messages', () => {
  function setupConversation() {
    const alice = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    return { alice, conv };
  }

  it('creates and decrypts message', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('hello world');

    const envelope = createMessage(alice, conv, 'text/plain', body, undefined, defaultTTL());
    expect(envelope.v).toBe(PROTOCOL_VERSION);
    expect(envelope.suite).toBe(DEFAULT_SUITE);
    expect(envelope.ciphertext.length).toBeGreaterThan(0);

    const message = decryptMessage(envelope, conv);
    expect(message.verified).toBe(true);
    expect(message.inner.body_type).toBe('text/plain');
    expect(new Uint8Array(message.inner.body)).toEqual(body);
    expect(new Uint8Array(message.inner.sender_ik_pk)).toEqual(alice.publicKey);
  });

  it('decrypts message with refs', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('replying');
    const refs = ['ref-123', 'ref-456'];

    const envelope = createMessage(alice, conv, 'text/plain', body, refs, defaultTTL());
    const message = decryptMessage(envelope, conv);
    expect(message.inner.refs).toBeDefined();
    expect(message.inner.refs!.length).toBe(2);
  });

  it('rejects tampered ciphertext', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('secret');
    const envelope = createMessage(alice, conv, 'text/plain', body, undefined, defaultTTL());
    envelope.ciphertext[0] ^= 0xff;

    expect(() => decryptMessage(envelope, conv)).toThrow();
  });

  it('rejects wrong conversation keys', () => {
    const alice = generateIdentity();
    const invite1 = createInvite(alice, 'direct');
    const keys1 = deriveConversationKeys(invite1);
    const conv1 = createConversation(invite1, keys1);

    const invite2 = createInvite(alice, 'direct');
    const keys2 = deriveConversationKeys(invite2);
    const conv2 = createConversation(invite2, keys2);
    // Make conv2 have same ID as conv1 so it passes the ID check
    conv2.id = conv1.id;

    const body = new TextEncoder().encode('secret');
    const envelope = createMessage(alice, conv1, 'text/plain', body, undefined, defaultTTL());

    expect(() => decryptMessage(envelope, conv2)).toThrow();
  });

  it('validates envelope structure', () => {
    const envelope: OuterEnvelope = {
      v: 999,
      suite: DEFAULT_SUITE,
      conv_id: new Uint8Array(16),
      msg_id: new Uint8Array(16),
      created_ts: Math.floor(Date.now() / 1000),
      expiry_ts: Math.floor(Date.now() / 1000) + 3600,
      conv_epoch: 0,
      ciphertext: new Uint8Array([1]),
    };
    expect(() => validateEnvelope(envelope)).toThrow('unsupported protocol version');
  });

  it('serialize and deserialize envelope', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('hello');
    const envelope = createMessage(alice, conv, 'text/plain', body, undefined, defaultTTL());

    const data = serializeEnvelope(envelope);
    const restored = deserializeEnvelope(data);
    expect(restored.v).toBe(envelope.v);
    expect(new Uint8Array(restored.conv_id)).toEqual(new Uint8Array(envelope.conv_id));
    expect(new Uint8Array(restored.msg_id)).toEqual(new Uint8Array(envelope.msg_id));
    expect(restored.created_ts).toBe(envelope.created_ts);
    expect(restored.expiry_ts).toBe(envelope.expiry_ts);
  });

  it('checkExpiry returns false for fresh message', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('hello');
    const envelope = createMessage(alice, conv, 'text/plain', body, undefined, defaultTTL());
    expect(checkExpiry(envelope)).toBe(false);
  });

  it('checkExpiry returns true for expired message', () => {
    const { alice, conv } = setupConversation();
    const body = new TextEncoder().encode('hello');
    const envelope = createMessage(alice, conv, 'text/plain', body, undefined, 1);
    // Force expiry by setting expiry_ts to the past
    envelope.expiry_ts = Math.floor(Date.now() / 1000) - 100;
    expect(checkExpiry(envelope)).toBe(true);
  });

  it('defaultTTL is 30 days', () => {
    expect(defaultTTL()).toBe(30 * 86400);
  });

  it('defaultHandshakeTTL is 7 days', () => {
    expect(defaultHandshakeTTL()).toBe(7 * 86400);
  });
});

// === 10. E2E Flow: Alice sends to Bob ===
describe('E2E Flow', () => {
  it('Alice creates invite, Bob joins and reads message', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();

    // Alice creates invite
    const invite = createInvite(alice, 'direct');

    // Both derive the same keys
    const aliceKeys = deriveConversationKeys(invite);
    const bobKeys = deriveConversationKeys(invite);
    expect(aliceKeys.root).toEqual(bobKeys.root);
    expect(aliceKeys.aeadKey).toEqual(bobKeys.aeadKey);
    expect(aliceKeys.nonceKey).toEqual(bobKeys.nonceKey);

    // Alice creates conversation and adds Bob
    const aliceConv = createConversation(invite, aliceKeys);
    addParticipant(aliceConv, bob.publicKey);

    // Bob creates conversation from same invite
    const bobConv = createConversation(invite, bobKeys);
    addParticipant(bobConv, bob.publicKey);

    // Alice sends message
    const body = new TextEncoder().encode('Hello Bob!');
    const envelope = createMessage(alice, aliceConv, 'text/plain', body, undefined, defaultTTL());

    // Bob decrypts and verifies
    const message = decryptMessage(envelope, bobConv);
    expect(message.verified).toBe(true);
    expect(new TextDecoder().decode(message.inner.body)).toBe('Hello Bob!');
    expect(new Uint8Array(message.inner.sender_ik_pk)).toEqual(alice.publicKey);
  });

  it('bidirectional messaging', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();

    const invite = createInvite(alice, 'direct');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    addParticipant(conv, bob.publicKey);

    // Alice sends
    const env1 = createMessage(alice, conv, 'text/plain', new TextEncoder().encode('Hi Bob'), undefined, defaultTTL());
    const msg1 = decryptMessage(env1, conv);
    expect(msg1.verified).toBe(true);

    // Bob sends
    const env2 = createMessage(bob, conv, 'text/plain', new TextEncoder().encode('Hi Alice'), undefined, defaultTTL());
    const msg2 = decryptMessage(env2, conv);
    expect(msg2.verified).toBe(true);
    expect(new TextDecoder().decode(msg2.inner.body)).toBe('Hi Alice');
  });
});

// === 11. Gate Signing ===
describe('Gate Signing', () => {
  it('sign and verify request', () => {
    const id = generateIdentity();
    const signable: GateSignable = {
      org_id: 'test-org',
      request_id: 'req-1',
      verb: 'POST',
      target_endpoint: '/api/deploy',
      target_service: 'deploy-svc',
      target_url: 'https://api.example.com/api/deploy',
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
      payload_hash: computePayloadHash({ action: 'deploy' }),
    };

    const sig = signRequest(id.privateKey, signable);
    expect(sig.length).toBe(64);
    expect(verifyRequest(id.publicKey, signable, sig)).toBe(true);
  });

  it('rejects tampered request', () => {
    const id = generateIdentity();
    const signable: GateSignable = {
      org_id: 'test-org',
      request_id: 'req-1',
      verb: 'POST',
      target_endpoint: '/api/deploy',
      target_service: 'deploy-svc',
      target_url: 'https://api.example.com/api/deploy',
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
      payload_hash: computePayloadHash(null),
    };

    const sig = signRequest(id.privateKey, signable);
    signable.verb = 'DELETE'; // tamper
    expect(verifyRequest(id.publicKey, signable, sig)).toBe(false);
  });

  it('sign and verify approval', () => {
    const id = generateIdentity();
    const requestSignable: GateSignable = {
      org_id: 'test-org',
      request_id: 'req-1',
      verb: 'POST',
      target_endpoint: '/api/deploy',
      target_service: 'deploy-svc',
      target_url: 'https://api.example.com/api/deploy',
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
      payload_hash: computePayloadHash(null),
    };

    const reqHash = hashRequest(requestSignable);

    const approval: ApprovalSignable = {
      org_id: 'test-org',
      request_id: 'req-1',
      request_hash: reqHash,
    };

    const sig = signApproval(id.privateKey, approval);
    expect(verifyApproval(id.publicKey, approval, sig)).toBe(true);
  });
});

// === 12. Gate Threshold Matching ===
describe('Gate Threshold Matching', () => {
  const rules: ThresholdRule[] = [
    { service: '*', endpoint: '', verb: '', m: 1 },
    { service: 'deploy-svc', endpoint: '', verb: '', m: 2 },
    { service: 'deploy-svc', endpoint: '', verb: 'DELETE', m: 3 },
    { service: 'deploy-svc', endpoint: '/api/prod', verb: 'POST', m: 4 },
  ];

  it('matches exact rule (service+endpoint+verb)', () => {
    const rule = lookupThreshold(rules, 'deploy-svc', '/api/prod', 'POST');
    expect(rule?.m).toBe(4);
  });

  it('matches service+verb', () => {
    const rule = lookupThreshold(rules, 'deploy-svc', '/api/staging', 'DELETE');
    expect(rule?.m).toBe(3);
  });

  it('matches service only', () => {
    const rule = lookupThreshold(rules, 'deploy-svc', '/api/staging', 'GET');
    expect(rule?.m).toBe(2);
  });

  it('matches default rule', () => {
    const rule = lookupThreshold(rules, 'unknown-svc', '/api/foo', 'GET');
    expect(rule?.m).toBe(1);
  });
});

// === 13. Base64URL Encoding ===
describe('Base64URL Encoding', () => {
  it('encode and decode round-trip', () => {
    const data = new Uint8Array([0, 1, 2, 255, 254, 253]);
    const encoded = base64UrlEncode(data);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(data);
  });

  it('handles empty data', () => {
    const encoded = base64UrlEncode(new Uint8Array(0));
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(new Uint8Array(0));
  });
});
