import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  QSP1Suite, GroupState, generateIdentity, createInvite, createConversation,
  deriveConversationKeys, createGroupGenesisBody, parseGroupGenesisBody, applyRekey,
  createMessage, decryptMessage, marshalCanonical, deserializeEnvelope,
  prepareGroupAddition, openGroupWelcome, createGroupLink, parseGroupLink,
  createGroupSession, restoreGroupSession, receiveGroupEvent, createGroupControlMessage,
  createGroupRemoveBody, createRekey,
} from '../src/index.js';
import type { Identity } from '../src/index.js';

const suite = new QSP1Suite();
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'hex'));
const identity = (value: Record<string, string>): Identity => ({
  privateKey: bytes(value.privateKey), publicKey: bytes(value.publicKey), keyID: bytes(value.keyID),
});
function python(request: Record<string, unknown>): any {
  return JSON.parse(execFileSync(process.env.QNTM_TEST_PYTHON ?? 'python3', [
    fileURLToPath(new URL('../../python-dist/tests/group_welcome_peer.py', import.meta.url)),
  ], {
    input: JSON.stringify(request), encoding: 'utf8', timeout: 15000,
    env: { ...process.env, PYTHONPATH: fileURLToPath(new URL('../../python-dist/src', import.meta.url)) },
  }));
}

describe('fresh Python / TypeScript contact addition interoperability', () => {
  it('exchanges private checkpoints between Python and TypeScript through addition and removal', () => {
    const owner = generateIdentity(), peer = generateIdentity(), late = generateIdentity();
    const invite = createInvite(owner, 'group');
    const conversation = createConversation(invite, deriveConversationKeys(invite));
    const group = new GroupState();
    group.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Checkpoint team', '', owner, [peer.publicKey])));
    conversation.participants = group.listMembers();
    const operation = prepareGroupAddition(peer, conversation, group, [late.publicKey]);
    const pyIdentity = Object.fromEntries(Object.entries(peer).map(([k, v]) => [k, hex(v)]));
    const receivedAdd = python({ action: 'session_receive', identity: pyIdentity,
      state: createGroupSession(peer, conversation, group), envelopes: [hex(marshalCanonical(operation.addition))] });
    const added = receiveGroupEvent(peer, operation.rekey, restoreGroupSession(peer, receivedAdd.state));
    expect(added.conversation.keys).toEqual(operation.conversation.keys);
    const removal = createGroupControlMessage(owner, added.conversation, 'group_remove', createGroupRemoveBody([peer.keyID]));
    const receivedRemoval = python({ action: 'session_receive', identity: pyIdentity, state: added.state, envelopes: [hex(marshalCanonical(removal))] });
    expect(receivedRemoval.state.removed).toBe(true);
    const remaining = new GroupState(); remaining.applyGenesis(added.group.snapshot());
    remaining.applyRemove({ removed_at: Math.floor(Date.now() / 1000), removed_members: [peer.keyID], reason: '' });
    const rekey = createGroupControlMessage(owner, added.conversation, 'group_rekey', createRekey(owner, added.conversation, remaining).bodyBytes);
    const excluded = receiveGroupEvent(peer, rekey, restoreGroupSession(peer, receivedRemoval.state));
    expect(excluded.state.removed).toBe(true);
    expect(excluded.state.root).toBe(added.state.root);
    expect(python({ action: 'session_receive', identity: pyIdentity, state: excluded.state,
      envelopes: [hex(marshalCanonical(rekey))] }).events).toEqual([{ duplicate: true, rewound: false }]);
  });

  it('Python resumes a TypeScript rekey checkpoint and selects the lower competing rekey', () => {
    const owner = generateIdentity(), peer = generateIdentity();
    const invite = createInvite(owner, 'group');
    const conversation = createConversation(invite, deriveConversationKeys(invite));
    const group = new GroupState();
    group.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Rekey team', '', owner, [peer.publicKey])));
    conversation.participants = group.listMembers();
    const [low, high] = [owner, peer].map(sender => createGroupControlMessage(sender, conversation, 'group_rekey', createRekey(sender, conversation, group).bodyBytes))
      .sort((a, b) => hex(a.msg_id).localeCompare(hex(b.msg_id)));
    const initial = createGroupSession(peer, conversation, group);
    const higher = receiveGroupEvent(peer, high, initial);
    const expected = receiveGroupEvent(peer, low, initial);
    const result = python({ action: 'session_receive', identity: Object.fromEntries(Object.entries(peer).map(([k, v]) => [k, hex(v)])),
      state: higher.state, envelopes: [hex(marshalCanonical(low))] });
    const resumed = restoreGroupSession(peer, result.state);
    expect(result.events).toEqual([{ duplicate: false, rewound: true }]);
    expect(resumed.root).toBe(expected.state.root);
    expect(resumed.snapshot).toBe(expected.state.snapshot);
    expect(resumed.rekeys[0].messageId).toBe(hex(low.msg_id));
  });

  for (const epoch of [0, 7]) {
    it(`Python opens a TypeScript welcome after epoch ${epoch} and replies without old keys`, () => {
      const owner = generateIdentity(), late = generateIdentity();
      const invite = createInvite(owner, 'group');
      const source = createConversation(invite, deriveConversationKeys(invite));
      const state = new GroupState();
      state.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Interop colleagues', 'Ω private roster', owner, [])));
      source.participants = state.listMembers();
      if (epoch) applyRekey(source, suite.generateGroupKey(), epoch);
      const before = createMessage(owner, source, 'text', new TextEncoder().encode('before addition'));
      const added = prepareGroupAddition(owner, source, state, [late.publicKey]);
      const after = createMessage(owner, added.conversation, 'text', new TextEncoder().encode('after addition'));
      const result = python({ action: 'open', identity: Object.fromEntries(Object.entries(late).map(([k, v]) => [k, hex(v)])),
        link: createGroupLink({ conversationId: source.id, inviterPublicKey: owner.publicKey, relayUrl: 'https://inbox.qntm.corpo.llc' }),
        welcome: hex(marshalCanonical(added.welcomes[0])), conversation_id: hex(source.id), inviter_public_key: hex(owner.publicKey),
        before: hex(marshalCanonical(before)), after: hex(marshalCanonical(after)) });
      expect(result).toMatchObject({ old_decrypts: false, epoch: epoch + 1, after: 'after addition' });
      const reply = decryptMessage(deserializeEnvelope(bytes(result.reply)), added.conversation);
      expect(new TextDecoder().decode(reply.inner.body)).toBe('Python recipient reply');
      expect(reply.inner.sender_ik_pk).toEqual(late.publicKey);
    });

    it(`TypeScript opens a Python welcome after epoch ${epoch} without earlier history`, () => {
      const result = python({ action: 'prepare', epoch });
      const late = identity(result.late);
      const locator = parseGroupLink(result.link);
      expect(locator.conversationId).toEqual(bytes(result.conversation_id));
      expect(locator.inviterPublicKey).toEqual(bytes(result.owner.publicKey));
      const joined = openGroupWelcome(late, bytes(result.welcome), locator);
      expect(joined.conversation.currentEpoch).toBe(epoch + 1);
      expect(hex(joined.conversation.keys.root)).toBe(result.root);
      expect(hex(joined.additionId)).toBe(result.addition_id);
      expect(hex(joined.rekeyId)).toBe(result.rekey_id);
      expect(() => decryptMessage(deserializeEnvelope(bytes(result.before)), joined.conversation)).toThrow();
      const after = decryptMessage(deserializeEnvelope(bytes(result.after)), joined.conversation);
      expect(new TextDecoder().decode(after.inner.body)).toBe('after addition');
    });
  }
});
