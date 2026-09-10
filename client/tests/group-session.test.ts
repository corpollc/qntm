import { describe, expect, it, vi } from 'vitest';
import {
  generateIdentity, createInvite, deriveConversationKeys, createConversation, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupAddBody, createGroupRemoveBody,
  createRekey, applyRekey, createMessage, marshalCanonical, unmarshalCanonical,
  createGroupSession, restoreGroupSession, receiveGroupEvent, groupSessionConversation,
  assertGroupCanSend, createGroupControlMessage, prepareGroupAddition, openGroupWelcome,
  prepareGroupSessionAddition, assertGroupAdditionAccepted,
  groupSessionFromWelcome, prepareGroupWelcomeRefresh, prepareGroupAdmissionRenewal,
  assertGroupAdmissionRenewalCurrent, prepareGroupSessionRekey, requireGroupRecovery,
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

describe('authenticated admission renewal', () => {
  const expected = (state: GroupSessionState, kid: Uint8Array) => {
    const { addId, addDigest } = state.admissions[hex(kid)];
    return { addId, addDigest };
  };
  function admitted() {
    const f = setup();
    const addition = prepareGroupSessionAddition(f.member, f.state, [f.late.publicKey]);
    const pending = receiveGroupEvent(f.member, addition.addition, f.state).state;
    const state = receiveGroupEvent(f.member, addition.rekey, pending).state;
    const pin = { conversationId: f.conversation.id, inviterPublicKey: f.member.publicKey };
    const welcome = openGroupWelcome(f.late, marshalCanonical(addition.welcomes[0]), pin);
    return { ...f, addition, pending, state, pin, welcome, peerState: groupSessionFromWelcome(f.late, welcome, 3) };
  }
  function nextEpoch(identity: Identity, state: GroupSessionState) {
    return receiveGroupEvent(identity, prepareGroupSessionRekey(identity, state).rekey, state).state;
  }

  it('persists incomplete and canonical completion evidence independently of seen eviction', () => {
    const f = admitted(), kid = hex(f.late.keyID), suite = new QSP1Suite();
    expect(restart(f.member, f.pending).admissions[kid]).toEqual({
      addId: hex(f.addition.addition.msg_id), addDigest: hex(suite.hash(marshalCanonical(f.addition.addition))),
      sourceEpoch: 0, completion: null,
    });
    expect(f.state.rekeys[0].admissions[kid].completion).toBeNull();
    expect(f.state.admissions[kid].completion).toEqual({ rekeyId: hex(f.addition.rekey.msg_id),
      rekeyDigest: hex(suite.hash(marshalCanonical(f.addition.rekey))) });
    let state = restart(f.member, f.state);
    for (let index = 0; Object.keys(state.seen).length < 8192; index++) {
      state.seen[index.toString(16).padStart(32, '0')] = { digest: '00'.repeat(32), epoch: state.epoch };
    }
    for (let index = 0; index < 2; index++) state = receiveGroupEvent(f.member, text(f.owner, groupSessionConversation(state)), state).state;
    expect(state.seen[hex(f.addition.addition.msg_id)]).toBeUndefined();
    expect(state.seen[hex(f.addition.rekey.msg_id)]).toBeUndefined();
    state = nextEpoch(f.member, nextEpoch(f.member, restart(f.member, state)));
    const renewal = prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey, expected(f.state, f.late.keyID), undefined, undefined, 9000);
    expect(renewal.admission).toEqual(f.state.admissions[kid]);
    expect(() => assertGroupAdmissionRenewalCurrent(f.member, state, renewal)).not.toThrow();
    expect(() => prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey,
      { ...expected(state, f.late.keyID), addDigest: '01'.repeat(32) })).toThrow('provenance');
    const substituted = structuredClone(state);
    substituted.admissions[kid].completion!.rekeyDigest = '02'.repeat(32);
    expect(() => assertGroupAdmissionRenewalCurrent(f.member, substituted, renewal)).toThrow('provenance');
  });

  it('restores admission evidence with a canonical rewind and replaces its completing rekey proof', () => {
    const f = setup(), other = generateIdentity();
    const operation = prepareGroupSessionAddition(f.member, f.state, [f.late.publicKey]);
    const pending = receiveGroupEvent(f.member, operation.addition, f.state).state;
    const [low, high] = [operation.rekey, prepareGroupSessionRekey(f.member, pending).rekey]
      .sort((a, b) => hex(a.msg_id).localeCompare(hex(b.msg_id)));
    let state = receiveGroupEvent(f.member, high, pending).state;
    const renewal = prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey, expected(state, f.late.keyID));
    const descendant = prepareGroupSessionAddition(f.member, state, [other.publicKey]);
    state = receiveGroupEvent(f.member, descendant.addition, state).state;
    state = receiveGroupEvent(f.member, descendant.rekey, state).state;
    const removal = createGroupControlMessage(f.owner, groupSessionConversation(state), 'group_remove', createGroupRemoveBody([f.member.keyID]));
    const removed = receiveGroupEvent(f.member, removal, state).state;
    const removedRewind = receiveGroupEvent(f.member, low, removed).state;
    expect(restart(f.member, removedRewind).removedAtEpoch).toBe(2);
    expect(removedRewind.removed).toBe(true);
    const winner = receiveGroupEvent(f.member, low, restart(f.member, state));
    expect(winner.rewound).toBe(true);
    expect(winner.state.admissions[hex(other.keyID)]).toBeUndefined();
    expect(winner.state.admissions[hex(f.late.keyID)].completion).toEqual({ rekeyId: hex(low.msg_id),
      rekeyDigest: hex(new QSP1Suite().hash(marshalCanonical(low))) });
    expect(winner.state.rekeys[0].admissions[hex(f.late.keyID)].completion).toBeNull();
    expect(() => assertGroupAdmissionRenewalCurrent(f.member, winner.state, renewal)).toThrow();
  });

  it('renews a later readmission without a new challenge and never revives its old incarnation', () => {
    const f = admitted();
    const remove = createGroupControlMessage(f.member, groupSessionConversation(f.state), 'group_remove', createGroupRemoveBody([f.late.keyID]));
    const removed = receiveGroupEvent(f.late, remove, f.peerState).state;
    expect(removed.removedAtEpoch).toBe(1);
    expect(removed.admissions[hex(f.late.keyID)]).toBeUndefined();
    let state = receiveGroupEvent(f.member, remove, f.state).state;
    state = nextEpoch(f.member, state);
    const readmit = prepareGroupSessionAddition(f.member, state, [f.late.publicKey]);
    state = receiveGroupEvent(f.member, readmit.addition, state).state;
    state = receiveGroupEvent(f.member, readmit.rekey, state).state;
    const secondEpoch = state;
    state = nextEpoch(f.member, nextEpoch(f.member, state));
    expect(state.epoch).toBe(5);
    expect(() => prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey, expected(f.state, f.late.keyID))).toThrow('provenance');
    const renewal = prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey, expected(state, f.late.keyID), undefined, undefined, 20);
    const opened = openGroupWelcome(f.late, marshalCanonical(renewal.welcomes[0]), f.pin);
    expect(opened.purpose).toBe('renewal');
    const renewed = groupSessionFromWelcome(f.late, opened, 21, restart(f.late, removed));
    expect(renewed.removed).toBe(false);
    expect(renewed.removedAtEpoch).toBe(1);
    expect(renewed.epoch).toBe(5);
    expect(renewed.rekeys).toEqual([]);
    // The very same proof at current epoch 5 cannot undo a later source-epoch 3 removal.
    const readmitted = groupSessionFromWelcome(f.late, openGroupWelcome(f.late, marshalCanonical(readmit.welcomes[0]), f.pin), 10, removed);
    const laterRemove = createGroupControlMessage(f.member, groupSessionConversation(secondEpoch), 'group_remove', createGroupRemoveBody([f.late.keyID]));
    const removedAgain = receiveGroupEvent(f.late, laterRemove, readmitted).state;
    expect(removedAgain.removedAtEpoch).toBe(3);
    expect(() => groupSessionFromWelcome(f.late, opened, 21, removedAgain)).toThrow('saved removal');
    const refresh = prepareGroupWelcomeRefresh(f.member, state, [f.late.publicKey], undefined, undefined, 20);
    expect(() => groupSessionFromWelcome(f.late, openGroupWelcome(f.late, marshalCanonical(refresh.welcomes[0]), f.pin), 21, removed)).toThrow('refresh');
    const blocked = requireGroupRecovery(removed, 18, 'missing_history');
    expect(() => groupSessionFromWelcome(f.late, opened, 21, blocked)).toThrow('challenge');
    const challenged = prepareGroupAdmissionRenewal(f.member, state, f.late.publicKey, expected(state, f.late.keyID), undefined,
      new Uint8Array(Buffer.from(blocked.recovery!.challenge, 'hex')), 20);
    expect(groupSessionFromWelcome(f.late, openGroupWelcome(f.late, marshalCanonical(challenged.welcomes[0]), f.pin), 21, blocked).removed).toBe(false);
    expect(() => groupSessionFromWelcome(f.late, opened, 21, { ...removed, removedAtEpoch: null })).toThrow('saved removal');
  });

  it('imports signed provenance for later member-issued renewals and enriches only unknown same-epoch evidence', () => {
    const f = admitted(), newcomer = generateIdentity();
    const addition = prepareGroupSessionAddition(f.member, f.state, [newcomer.publicKey]);
    let state = receiveGroupEvent(f.member, addition.addition, f.state).state;
    state = receiveGroupEvent(f.member, addition.rekey, state).state;
    const opened = openGroupWelcome(newcomer, marshalCanonical(addition.welcomes[0]), f.pin);
    const joined = groupSessionFromWelcome(newcomer, opened, 6);
    expect(joined.admissions).toEqual(state.admissions);
    const renewal = prepareGroupAdmissionRenewal(newcomer, joined, f.late.publicKey, expected(joined, f.late.keyID));
    expect(openGroupWelcome(f.late, marshalCanonical(renewal.welcomes[0]), { ...f.pin, inviterPublicKey: newcomer.publicKey }).admissions).toEqual(state.admissions);
    const legacy: any = structuredClone(joined);
    delete legacy.admissions; delete legacy.removedAtEpoch;
    const unknown = restoreGroupSession(newcomer, legacy);
    expect(unknown.admissions).toEqual({});
    expect(() => prepareGroupAdmissionRenewal(newcomer, unknown, f.late.publicKey, expected(state, f.late.keyID))).toThrow('unknown');
    expect(groupSessionFromWelcome(newcomer, opened, 7, unknown).admissions).toEqual(state.admissions);
    const conflict = structuredClone(joined);
    conflict.admissions[hex(f.late.keyID)].addDigest = '00'.repeat(32);
    expect(() => groupSessionFromWelcome(newcomer, opened, 7, conflict)).toThrow('conflicts');
  });

  it('validates bounded private provenance and keeps unknown draft archives unknown', () => {
    const f = admitted(), kid = hex(f.late.keyID);
    for (const admissions of [null, [], { outsider: f.state.admissions[kid] },
      { [kid]: { ...f.state.admissions[kid], sourceEpoch: 1 } },
      { [kid]: { ...f.state.admissions[kid], completion: null } }]) {
      expect(() => restoreGroupSession(f.member, { ...f.state, admissions })).toThrow();
    }
    expect(() => restoreGroupSession(f.member, { ...f.pending, needsRekey: false })).toThrow('rotation');
    expect(() => restoreGroupSession(f.member, { ...f.state, removedAtEpoch: -1 })).toThrow('removal');
    const legacy: any = structuredClone(f.state);
    delete legacy.admissions; delete legacy.removedAtEpoch;
    for (const frame of legacy.rekeys) delete frame.admissions;
    const restored = restoreGroupSession(f.member, legacy);
    expect(restored.admissions).toEqual({});
    expect(restored.rekeys[0].admissions).toEqual({});
    expect(restored.removedAtEpoch).toBeNull();
  });

  it('does not invent epoch-bound provenance from legacy unsigned-epoch controls', () => {
    const f = setup();
    const legacy = { ...f.state, signedEpoch: false };
    const addition = createMessage(f.member, f.conversation, 'group_add', createGroupAddBody(f.member, [f.late.publicKey]));
    let current = receiveGroupEvent(f.member, addition, legacy);
    const rekey = rotate(f.member, current.conversation, current.group);
    current = receiveGroupEvent(f.member, rekey.envelope, current.state);
    expect(current.state.admissions).toEqual({});
    const removal = createMessage(f.owner, current.conversation, 'group_remove', createGroupRemoveBody([f.member.keyID]));
    const removed = receiveGroupEvent(f.member, removal, current.state).state;
    expect(removed.removed).toBe(true);
    expect(removed.removedAtEpoch).toBeNull();
    const signedAddition = prepareGroupSessionAddition(f.member, legacy, [f.late.publicKey]);
    const pending = receiveGroupEvent(f.member, signedAddition.addition, legacy);
    const unsignedRekey = createMessage(f.member, pending.conversation, 'group_rekey', createRekey(f.member, pending.conversation, pending.group).bodyBytes);
    const unknown = receiveGroupEvent(f.member, unsignedRekey, pending.state).state;
    expect(restart(f.member, unknown).admissions).toEqual({});
  });
});
