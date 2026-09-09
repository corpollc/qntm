import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { createMessage, serializeEnvelope, createGroupRekeyBody, createGroupRemoveBody, generateIdentity, base64UrlEncode, serializeIdentity } from '@corpollc/qntm';
import { createConfig, createConversationFixture, createIdentityFixture } from './helpers.js';
import { resolveQntmAccount } from '../src/accounts.js';
import { loadQntmIdentityFromString, parseStoredConversationRecord, toHex } from '../src/qntm.js';
import { QntmCheckpointStore } from '../src/checkpoint.js';
import { receiveQntmEnvelope } from '../src/receive.js';
import { writeConversationCursor, resolveConversationCursorPath } from '../src/state.js';

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function fixture(options: ConstructorParameters<typeof QntmCheckpointStore>[1] = {}) {
  const stateDir = mkdtempSync(join(tmpdir(), 'qntm-checkpoint-')); directories.push(stateDir);
  const identity = createIdentityFixture();
  const group = createConversationFixture('group');
  const account = resolveQntmAccount({ cfg: createConfig({ identity: identity.serialized, conversations: { group: { invite: group.token } } }) });
  const binding = account.bindings[0];
  const store = new QntmCheckpointStore(account, { stateDir, ...options });
  const envelope = (text: string) => serializeEnvelope(createMessage(group.inviter, store.load(binding).conversation, 'text', new TextEncoder().encode(text)));
  return { stateDir, identity: identity.identity, group, account, binding, store, envelope };
}

describe('qntm authenticated checkpoints', () => {
  test('commits pending dispatch, verified state and cursor atomically in a private file', () => {
    const f = fixture();
    expect(receiveQntmEnvelope(f.store, f.binding, 4, f.envelope('hello'))).toBe('accepted');
    const resumed = new QntmCheckpointStore(f.account, { stateDir: f.stateDir }).load(f.binding);
    expect(resumed.cursor).toBe(4);
    expect(resumed.outbox[0].text).toBe('hello');
    expect(Object.keys(resumed.session.seen)).toHaveLength(1);
    expect(statSync(f.store.path(f.binding)).mode & 0o777).toBe(0o600);
    expect(statSync(join(f.stateDir, 'plugins/qntm/accounts/default/conversations')).mode & 0o777).toBe(0o700);
  });
  test('failed persistence does not consume a message', () => {
    const f = fixture({ write: () => { throw new Error('disk full'); } });
    expect(() => receiveQntmEnvelope(f.store, f.binding, 1, f.envelope('retain me'))).toThrow('disk full');
    expect(f.store.load(f.binding).cursor).toBe(0);
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
  });
  test('rekeys even when mention filtering suppresses dispatch; exact old replay needs no old key', () => {
    const f = fixture();
    f.binding.trigger = 'mention'; f.binding.triggerNames = ['wake'];
    const root = new Uint8Array(32).fill(42);
    const body = createGroupRekeyBody(root, 1, [f.identity, f.group.inviter].map(identity => ({ kid: identity.keyID, publicKey: identity.publicKey })), f.group.conversation.id);
    const rekey = serializeEnvelope(createMessage(f.group.inviter, f.group.conversation, 'group_rekey', body));
    expect(receiveQntmEnvelope(f.store, f.binding, 1, rekey)).toBe('accepted');
    expect(f.store.load(f.binding).conversation.currentEpoch).toBe(1);
    expect(f.store.load(f.binding).conversation.keys.root).toEqual(root);
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
    expect(receiveQntmEnvelope(f.store, f.binding, 2, rekey)).toBe('duplicate');
    expect(receiveQntmEnvelope(f.store, f.binding, 3, f.envelope('wake after rotation'))).toBe('accepted');
    expect(f.store.load(f.binding).outbox.map(message => message.text)).toEqual(['wake after rotation']);
  });
  test('legacy cursors suppress old wakeups while available history establishes state', () => {
    const f = fixture();
    writeConversationCursor({ stateDir: f.stateDir, accountId: 'default', conversationId: f.binding.conversationId, sequence: 9 });
    expect(f.store.load(f.binding).cursor).toBe(0);
    receiveQntmEnvelope(f.store, f.binding, 1, f.envelope('previously handled'));
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
    receiveQntmEnvelope(f.store, f.binding, 10, f.envelope('new message'));
    expect(f.store.load(f.binding).outbox.map(message => message.text)).toEqual(['new message']);
  });
  test('malformed checkpoints and legacy cursors fail closed without exposing their contents', () => {
    const f = fixture();
    f.store.commit(f.binding, f.store.load(f.binding));
    writeFileSync(f.store.path(f.binding), '{"secret":"never-echo-this",');
    expect(() => f.store.load(f.binding)).toThrow(/^Invalid qntm checkpoint;/);
    expect(readFileSync(f.store.path(f.binding), 'utf8')).toContain('never-echo-this');
    const other = fixture();
    writeConversationCursor({ stateDir: other.stateDir, accountId: 'default', conversationId: other.binding.conversationId, sequence: 1 });
    writeFileSync(resolveConversationCursorPath({ stateDir: other.stateDir, accountId: 'default', conversationId: other.binding.conversationId }), '{"seq":1.5}');
    expect(() => other.store.load(other.binding)).toThrow('legacy cursor');
    expect(() => other.store.path({ ...other.binding, conversationId: '../escape' })).toThrow();
  });
  test('rejects wrong-epoch/tampered input and preserves removal across restart', () => {
    const f = fixture();
    const tampered = f.envelope('forged'); tampered[tampered.length - 1] ^= 1;
    expect(receiveQntmEnvelope(f.store, f.binding, 1, tampered)).toBe('invalid');
    expect(f.store.load(f.binding).cursor).toBe(1);
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
    const remove = serializeEnvelope(createMessage(f.group.inviter, f.group.conversation, 'group_remove', createGroupRemoveBody([f.identity.keyID])));
    receiveQntmEnvelope(f.store, f.binding, 2, remove);
    expect(new QntmCheckpointStore(f.account, { stateDir: f.stateDir }).load(f.binding).session.removed).toBe(true);
    receiveQntmEnvelope(f.store, f.binding, 3, f.envelope('cannot wake removed agent'));
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
  });
  test('pins identity and initial conversation configuration', () => {
    const f = fixture(); f.store.commit(f.binding, f.store.load(f.binding));
    const replacement = { ...f.account, identity: generateIdentity() };
    expect(() => new QntmCheckpointStore(replacement, { stateDir: f.stateDir }).load(f.binding)).toThrow('Invalid qntm checkpoint');
    f.binding.conversation.keys.root = new Uint8Array(32);
    expect(() => f.store.load(f.binding)).toThrow('Invalid qntm checkpoint');
  });
  test('bounds pending dispatches before advancing the cursor', () => {
    const f = fixture();
    for (let i = 1; i <= 64; i++) receiveQntmEnvelope(f.store, f.binding, i, f.envelope(`message ${i}`));
    expect(() => receiveQntmEnvelope(f.store, f.binding, 65, f.envelope('overflow'))).toThrow('queue is full');
    expect(f.store.load(f.binding).cursor).toBe(64);
  });
  test('oversized plaintext on a custom relay cannot pin the subscription cursor', () => {
    const f = fixture();
    expect(receiveQntmEnvelope(f.store, f.binding, 1, f.envelope('a'.repeat(65537)))).toBe('invalid');
    expect(f.store.load(f.binding).cursor).toBe(1);
    expect(f.store.load(f.binding).outbox).toHaveLength(0);
    expect(receiveQntmEnvelope(f.store, f.binding, 2, f.envelope('next message'))).toBe('accepted');
    expect(f.store.load(f.binding).outbox[0].text).toBe('next message');
  });
});

describe('local identity and conversation parsing', () => {
  test('requires matching private/public keys and key IDs in JSON and CBOR', () => {
    const identity = generateIdentity(), other = generateIdentity();
    for (const bad of [{ ...identity, keyID: other.keyID }, { ...identity, privateKey: other.privateKey }]) {
      const json = JSON.stringify({ private_key: toHex(bad.privateKey), public_key: toHex(bad.publicKey), key_id: toHex(bad.keyID) });
      expect(() => loadQntmIdentityFromString(json)).toThrow();
      expect(() => loadQntmIdentityFromString(base64UrlEncode(serializeIdentity(bad)))).toThrow();
    }
    expect(() => loadQntmIdentityFromString('{"private_key":"do-not-echo",')).toThrow('invalid qntm identity JSON');
    expect(() => loadQntmIdentityFromString(JSON.stringify({ private_key: [-1, 1.5, 256], public_key: [], key_id: [] }))).toThrow();
  });
  test.each([-1, 1.5, '1', '2broken', Number.MAX_SAFE_INTEGER])('rejects malformed conversation epoch %s', currentEpoch => {
    expect(() => parseStoredConversationRecord({ id: 'aa'.repeat(16), keys: { root: 'bb'.repeat(32), aeadKey: 'cc'.repeat(32), nonceKey: 'dd'.repeat(32) }, currentEpoch })).toThrow('epoch');
  });
});
