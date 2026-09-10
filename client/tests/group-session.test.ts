import { describe, expect, it, vi } from 'vitest';
import {
  generateIdentity, createInvite, deriveConversationKeys, createConversation, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupAddBody, createGroupRemoveBody,
  createRekey, applyRekey, createMessage, marshalCanonical, unmarshalCanonical,
  createGroupSession, restoreGroupSession, receiveGroupEvent, groupSessionConversation,
  assertGroupCanSend, createGroupControlMessage, prepareGroupAddition, openGroupWelcome,
  prepareGroupSessionAddition, assertGroupAdditionAccepted,
  QSP1Suite, GROUP_REKEY_GRACE_SECONDS,
} from '../src/index.js';
import type { Identity, Conversation, OuterEnvelope, GroupSessionState } from '../src/index.js';

const hex = (v: Uint8Array) => Buffer.from(v).toString('hex');
function setup() {
  const owner = generateIdentity(), member = generateIdentity(), late = generateIdentity();
  const invite = createInvite(owner, 'group');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const group = new GroupState();
  group.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Team', '', owner, [member.publicKey])));
  conversation.participants = group.listMembers();
  return { owner, member, late, conversation, group, state: createGroupSession(member, conversation, group) };
}
function rotate(sender: Identity, conversation: Conversation, group: GroupState) {
  const { bodyBytes, newGroupKey } = createRekey(sender, conversation, group);
  const envelope = createGroupControlMessage(sender, conversation, 'group_rekey', bodyBytes);
  const next = structuredClone(conversation);
  next.participants = group.listMembers();
  applyRekey(next, newGroupKey, conversation.currentEpoch + 1);
  return { envelope, conversation: next };
}
const text = (sender: Identity, conversation: Conversation, value = 'hello') => createMessage(sender, conversation, 'text', new TextEncoder().encode(value));
const restart = (identity: Identity, state: GroupSessionState) => restoreGroupSession(identity, JSON.parse(JSON.stringify(state)));

describe('ordinary group receive checkpoints', () => {
  it('applies a member-initiated add and rekey across restart, matching the welcome recipient', () => {
    const f = setup(), original = JSON.stringify(f.state);
    const operation = prepareGroupAddition(f.member, f.conversation, f.group, [f.late.publicKey]);
    let received = receiveGroupEvent(f.member, operation.addition, f.state);
    expect(received.group.isMember(f.late.keyID)).toBe(true);
    expect(() => assertGroupCanSend(f.member, received.state)).toThrow('key rotation');
    expect(() => receiveGroupEvent(f.member, text(f.owner, f.conversation), received.state)).toThrow('key rotation');
    received = receiveGroupEvent(f.member, operation.rekey, restart(f.member, received.state));
    expect(received.conversation.keys).toEqual(operation.conversation.keys);
    expect(() => assertGroupCanSend(f.member, received.state)).not.toThrow();
    expect(JSON.stringify(f.state)).toBe(original);
    const welcome = openGroupWelcome(f.late, marshalCanonical(operation.welcomes[0]), {
      conversationId: f.conversation.id, inviterPublicKey: f.member.publicKey,
    });
    const newcomer = createGroupSession(f.late, welcome.conversation, welcome.state);
    expect(newcomer.rekeys).toEqual([]);
    const reply = text(f.late, groupSessionConversation(newcomer));
    expect(receiveGroupEvent(f.member, reply, received.state).duplicate).toBe(false);
    expect(receiveGroupEvent(f.member, operation.rekey, restart(f.member, received.state)).duplicate).toBe(true);
  });

  it('releases a welcome only for the exact verified addition and rekey', () => {
    const f = setup();
    const operation = prepareGroupSessionAddition(f.member, f.state, [f.late.publicKey]);
    expect(() => assertGroupAdditionAccepted(f.member, f.state, operation)).toThrow();
    const pending = receiveGroupEvent(f.member, operation.addition, f.state);
    expect(() => assertGroupAdditionAccepted(f.member, pending.state, operation)).toThrow();
    expect(() => prepareGroupSessionAddition(f.member, pending.state, [generateIdentity().publicKey])).toThrow('key rotation');
    const accepted = receiveGroupEvent(f.member, operation.rekey, pending.state);
    expect(() => assertGroupAdditionAccepted(f.member, accepted.state, operation)).not.toThrow();
    const missingEvidence = structuredClone(accepted.state);
    delete missingEvidence.seen[hex(operation.addition.msg_id)];
    expect(() => assertGroupAdditionAccepted(f.member, missingEvidence, operation)).toThrow('not both');
    const advanced = receiveGroupEvent(f.member, rotate(f.owner, accepted.conversation, accepted.group).envelope, accepted.state);
    expect(() => assertGroupAdditionAccepted(f.member, advanced.state, operation)).toThrow('differs');
  });

  it('keeps removal sticky across restart and refuses old-key readmission by replay', () => {
    const f = setup();
    const remove = createGroupControlMessage(f.owner, f.conversation, 'group_remove', createGroupRemoveBody([f.member.keyID]));
    let current = receiveGroupEvent(f.member, remove, f.state);
    expect(current.state.removed).toBe(true);
    const remaining = current.group;
    const rotation = rotate(f.owner, f.conversation, remaining);
    current = receiveGroupEvent(f.member, rotation.envelope, restart(f.member, current.state));
    expect(current.state.root).toBe(f.state.root);
    expect(current.state.rekeys).toEqual([]);
    expect(() => assertGroupCanSend(f.member, current.state)).toThrow('removed');
    expect(() => receiveGroupEvent(f.member, text(f.owner, rotation.conversation), current.state)).toThrow();
    // A new control encrypted with the old shared key cannot re-enable the
    // removed receiver, even if its snapshot again includes the local identity.
    const add = createGroupControlMessage(f.owner, f.conversation, 'group_add', createGroupAddBody(f.owner, [f.member.publicKey]));
    current = receiveGroupEvent(f.member, add, current.state);
    const oldKeyRotation = rotate(f.owner, f.conversation, current.group);
    current = receiveGroupEvent(f.member, oldKeyRotation.envelope, current.state);
    expect(current.state.removed).toBe(true);
    expect(current.state.root).toBe(f.state.root);
  });

  it('rejects a removed sender, outsiders, creator removal and malformed controls without mutation', () => {
    const f = setup(), outsider = generateIdentity();
    const original = JSON.stringify(f.state);
    const cases = [
      createGroupControlMessage(outsider, f.conversation, 'group_add', createGroupAddBody(outsider, [f.late.publicKey])),
      createGroupControlMessage(f.owner, f.conversation, 'group_remove', createGroupRemoveBody([f.owner.keyID])),
      createGroupControlMessage(f.owner, f.conversation, 'group_add', createGroupAddBody(f.owner, [f.late.publicKey, f.late.publicKey])),
      createGroupControlMessage(f.owner, f.conversation, 'group_add', createGroupAddBody(f.member, [f.late.publicKey])),
      text(outsider, f.conversation),
    ];
    for (const envelope of cases) expect(() => receiveGroupEvent(f.member, envelope, f.state)).toThrow();
    expect(JSON.stringify(f.state)).toBe(original);
    const removed = receiveGroupEvent(f.member,
      createGroupControlMessage(f.owner, f.conversation, 'group_remove', createGroupRemoveBody([f.member.keyID])), f.state);
    expect(() => receiveGroupEvent(f.member, text(f.member, f.conversation), removed.state)).toThrow('current member');
  });

  it('requires signed source epochs while allowing explicit migration of legacy checkpoints', () => {
    const f = setup();
    const body = createGroupAddBody(f.owner, [f.late.publicKey]);
    const legacy = createMessage(f.owner, f.conversation, 'group_add', body);
    expect(() => receiveGroupEvent(f.member, legacy, f.state)).toThrow('signed for this epoch');
    const migrated = createGroupSession(f.member, f.conversation, f.group, { signedEpoch: false });
    expect(receiveGroupEvent(f.member, legacy, migrated).state.needsRekey).toBe(true);
    const wrongEpoch = createMessage(f.owner, f.conversation, 'group_add', marshalCanonical({ ...unmarshalCanonical<any>(body), group_epoch: 1 }));
    expect(() => receiveGroupEvent(f.member, wrongEpoch, migrated)).toThrow('signed for this epoch');
  });

  it('requires rekey recipients to equal the complete current roster', () => {
    const f = setup(), rotation = rotate(f.owner, f.conversation, f.group);
    const suite = new QSP1Suite();
    const body = unmarshalCanonical<any>(createRekey(f.owner, f.conversation, f.group).bodyBytes);
    delete body.wrapped_keys[Object.keys(body.wrapped_keys)[0]];
    const missing = createGroupControlMessage(f.owner, f.conversation, 'group_rekey', marshalCanonical(body));
    expect(() => receiveGroupEvent(f.member, missing, f.state)).toThrow('recipients');
    const invalid = { ...f.state, root: hex(suite.generateGroupKey()) };
    expect(() => receiveGroupEvent(f.member, rotation.envelope, invalid)).toThrow();
  });

  it('selects a delayed lower rekey, rewinds descendants, and resumes the winning branch', () => {
    const f = setup();
    const [low, high] = [rotate(f.owner, f.conversation, f.group), rotate(f.member, f.conversation, f.group)]
      .sort((a, b) => hex(a.envelope.msg_id).localeCompare(hex(b.envelope.msg_id)));
    let current = receiveGroupEvent(f.member, high.envelope, f.state);
    const losingChild = rotate(f.owner, high.conversation, f.group);
    current = receiveGroupEvent(f.member, losingChild.envelope, current.state);
    expect(current.state.epoch).toBe(2);
    const winningChild = rotate(f.owner, low.conversation, f.group);
    expect(() => receiveGroupEvent(f.member, winningChild.envelope, current.state)).toThrow();
    current = receiveGroupEvent(f.member, low.envelope, restart(f.member, current.state));
    expect(current.rewound).toBe(true);
    expect(current.state.epoch).toBe(1);
    expect(current.conversation.keys).toEqual(low.conversation.keys);
    expect(current.state.rekeys).toHaveLength(1);
    expect(current.state.seen[hex(losingChild.envelope.msg_id)]).toBeUndefined();
    expect(() => receiveGroupEvent(f.member, text(f.owner, high.conversation), current.state)).toThrow();
    current = receiveGroupEvent(f.member, winningChild.envelope, current.state);
    expect(current.conversation.keys).toEqual(winningChild.conversation.keys);
    expect(receiveGroupEvent(f.member, text(f.owner, winningChild.conversation), current.state).duplicate).toBe(false);
  });

  it('never uses archived roots for old application or membership events and bounds their lifetime', () => {
    const f = setup();
    const candidates = Array.from({ length: 8 }, () => rotate(f.owner, f.conversation, f.group))
      .sort((a, b) => hex(a.envelope.msg_id).localeCompare(hex(b.envelope.msg_id)));
    const high = candidates.at(-1)!;
    const current = receiveGroupEvent(f.member, high.envelope, f.state);
    expect(() => receiveGroupEvent(f.member, text(f.owner, f.conversation), current.state)).toThrow();
    const saved = restart(f.member, current.state);
    vi.useFakeTimers();
    try {
      vi.setSystemTime((Math.floor(Date.now() / 1000) + GROUP_REKEY_GRACE_SECONDS + 1) * 1000);
      expect(() => receiveGroupEvent(f.member, candidates[0].envelope, saved)).toThrow('epoch');
    } finally { vi.useRealTimers(); }
  });

  it('rejects another identity, malformed checkpoint fields, and conflicting message IDs', () => {
    const f = setup();
    expect(() => restoreGroupSession(f.owner, f.state)).toThrow();
    for (const change of [{ epoch: -1 }, { epoch: true }, { root: '00' }, { extra: true }, { removed: 'false' }, { snapshot: f.state.snapshot + '=' }]) {
      expect(() => restoreGroupSession(f.member, { ...f.state, ...change })).toThrow();
    }
    const envelope = text(f.owner, f.conversation);
    const current = receiveGroupEvent(f.member, envelope, f.state);
    const forged: OuterEnvelope = structuredClone(envelope); forged.ciphertext[0] ^= 1;
    expect(() => receiveGroupEvent(f.member, forged, current.state)).toThrow('Conflicting');
  });
});
