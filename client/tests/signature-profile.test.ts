import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { QSP1Suite } from '../src/crypto/qsp1.js';
import { validateCharterPublicKey, verifyCharterSignature } from '../src/charter/crypto.js';
import { isValidEd25519PublicKey, verifyEd25519Signature, generateIdentity, createInvite, validateInvite,
  base64UrlEncode, keyIDFromPublicKey, validateGatewayIdentity, createConversation, deriveConversationKeys,
  createMessage, decryptMessage, marshalCanonical, unmarshalCanonical,
  createGroupAddBody, parseGroupAddBody, GroupState } from '../src/index.js';
const vectors = JSON.parse(readFileSync(new URL('../../specs/test-vectors/ed25519-verification.json', import.meta.url), 'utf8')).cases;
describe('shared Ed25519 verification profile', () => {
  it.each(vectors)('$name', (v: any) => {
    const key = Buffer.from(v.public_key_hex, 'hex'), message = Buffer.from(v.message_hex, 'hex'), signature = Buffer.from(v.signature_hex, 'hex');
    expect(new QSP1Suite().verify(key, message, signature)).toBe(v.valid);
    expect(isValidEd25519PublicKey(key)).toBe(v.key_valid);
    expect(verifyEd25519Signature(key, message, signature)).toBe(v.valid);
    if (v.key_valid) {
      expect(() => validateCharterPublicKey(key)).not.toThrow();
      expect(verifyCharterSignature(key, message, signature)).toBe(v.valid);
    } else expect(() => validateCharterPublicKey(key)).toThrow();
  });
  it.each(vectors.filter((v: any) => !v.key_valid))('rejects $name at invite and gateway admission', (v: any) => {
    const key = Buffer.from(v.public_key_hex, 'hex');
    const invite = createInvite(generateIdentity(), 'group');
    expect(() => validateInvite({ ...invite, inviter_ik_pk: key })).toThrow();
    expect(validateGatewayIdentity(base64UrlEncode(key), base64UrlEncode(keyIDFromPublicKey(key)))).toBe(false);
  });
  it('rejects an authenticated ciphertext containing an identity-key signature forgery', () => {
    const issuer = generateIdentity(), invite = createInvite(issuer, 'group');
    const conversation = createConversation(invite, deriveConversationKeys(invite));
    const suite = new QSP1Suite(), envelope = createMessage(issuer, conversation, 'text', new TextEncoder().encode('forged sender'));
    const { ciphertext, aad_hash, ...header } = envelope;
    const aad = marshalCanonical(header), nonce = suite.deriveNonce(conversation.keys.nonceKey, envelope.msg_id);
    const inner = unmarshalCanonical<Record<string, unknown>>(suite.decrypt(conversation.keys.aeadKey, nonce, ciphertext, aad));
    const identity = new Uint8Array([1, ...new Uint8Array(31)]);
    inner.sender_ik_pk = identity; inner.sender_kid = keyIDFromPublicKey(identity);
    inner.signature = new Uint8Array([...identity, ...new Uint8Array(32)]);
    envelope.ciphertext = suite.encrypt(conversation.keys.aeadKey, nonce, marshalCanonical(inner), aad);
    expect(() => decryptMessage(envelope, conversation)).toThrow(/signature/i);
  });
  it('rejects an invalid member before partially applying a group roster', () => {
    const issuer = generateIdentity(), member = generateIdentity(), identity = new Uint8Array([1, ...new Uint8Array(31)]);
    expect(() => createGroupAddBody(issuer, [member.publicKey, identity])).toThrow(/public key/);
    const body = parseGroupAddBody(createGroupAddBody(issuer, [member.publicKey, issuer.publicKey]));
    body.new_members[1].public_key = identity; body.new_members[1].key_id = keyIDFromPublicKey(identity);
    expect(() => parseGroupAddBody(marshalCanonical(body))).toThrow(/public key/);
    const state = new GroupState();
    expect(() => state.applyAdd(body)).toThrow(/public key/);
    expect(state.memberCount()).toBe(0);
  });
});
