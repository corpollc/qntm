import { describe, expect, it, vi } from 'vitest';
import {
  generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, prepareGroupSessionAddition,
  receiveGroupEvent, prepareGroupWelcomeRefresh, openGroupWelcome, marshalCanonical,
  checkGroupReplayCoverage, restoreGroupSession, groupSessionFromWelcome, assertGroupCanSend,
  prepareGroupSessionRekey, createGroupControlMessage, createGroupRemoveBody, createMessage,
  checkExpiredGroupControl, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch, groupSessionConversation,
} from '../src/index.js';

function setup() {
  const owner = generateIdentity(), peer = generateIdentity();
  const invite = createInvite(owner, 'group');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const group = new GroupState();
  group.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Recovery team', '', owner, [])));
  conversation.participants = group.listMembers();
  const initial = createGroupSession(owner, conversation, group);
  const addition = prepareGroupSessionAddition(owner, initial, [peer.publicKey]);
  let state = receiveGroupEvent(owner, addition.addition, initial).state;
  state = receiveGroupEvent(owner, addition.rekey, state).state;
  const pin = { conversationId: conversation.id, inviterPublicKey: owner.publicKey };
  const welcome = openGroupWelcome(peer, marshalCanonical(addition.welcomes[0]), pin);
  return { owner, peer, state, welcome, pin, initial, addition, conversation, peerState: groupSessionFromWelcome(peer, welcome, 3) };
}

describe('group recovery after missing history', () => {
  it('pauses unknown older-source ciphertext before dispatch, exempting only exact signed controls', () => {
    const f = setup();
    const rows = [f.addition.addition, f.addition.rekey, f.addition.welcomes[0]].map((envelope, i) => ({ seq: i + 1, envelope: marshalCanonical(envelope) }));
    expect(checkGroupWelcomeReplay(f.peerState, f.welcome, 3, rows).recovery).toBeNull();
    const oldText = createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('racing old traffic'), undefined, 1);
    const extra = { seq: 4, envelope: marshalCanonical(oldText) };
    const blocked = checkGroupWelcomeReplay(f.peerState, f.welcome, 4, [...rows, extra]);
    expect(blocked.recovery?.afterSequence).toBe(4);
    expect(() => assertGroupCanSend(f.peer, blocked)).toThrow('incomplete');
    const clock = vi.spyOn(Date, 'now').mockReturnValue((oldText.expiry_ts + 2) * 1000);
    try { expect(checkGroupWelcomeReplay(f.peerState, f.welcome, 4, [...rows, extra]).recovery).not.toBeNull(); }
    finally { clock.mockRestore(); }
    const substituted = { ...f.addition.rekey, ciphertext: new Uint8Array(f.addition.rekey.ciphertext.length) };
    expect(checkGroupWelcomeReplay(f.peerState, f.welcome, 3, [rows[0], { seq: 2, envelope: marshalCanonical(substituted) }, rows[2]]).recovery).not.toBeNull();
    expect(checkGroupWelcomeReplay(f.peerState, { ...f.welcome, replayFromSequence: 4 }, 4, [...rows, extra]).recovery).toBeNull();
    expect(checkGroupUnverifiableEpoch(f.peerState, oldText, 4).recovery?.afterSequence).toBe(4);
    expect(checkGroupUnverifiableEpoch(f.state, oldText, 4).recovery).toBeNull(); // Has the source-key archive.
    expect(checkGroupUnverifiableEpoch({ ...f.state, rekeys: [] }, f.addition.rekey, 4).recovery).toBeNull(); // Exact verified duplicate.
  });

  it('recovers a different root at the same epoch only with the persisted challenge', () => {
    const f = setup();
    const source = { ...f.initial, snapshot: f.state.snapshot };
    const winning = prepareGroupSessionRekey(f.owner, source);
    const winningState = createGroupSession(f.owner, winning.conversation, winning.state);
    expect(winningState.epoch).toBe(f.peerState.epoch);
    expect(winningState.root).not.toBe(f.peerState.root);
    const blocked = checkGroupReplayCoverage(f.peerState, 3, 4, []);
    const plain = prepareGroupWelcomeRefresh(f.owner, winningState, [f.peer.publicKey], undefined, undefined, 4);
    expect(() => groupSessionFromWelcome(f.peer, openGroupWelcome(f.peer, marshalCanonical(plain.welcomes[0]), f.pin), 5, blocked)).toThrow('challenge');
    const challenge = new Uint8Array(Buffer.from(blocked.recovery!.challenge, 'hex'));
    const fresh = prepareGroupWelcomeRefresh(f.owner, winningState, [f.peer.publicKey], undefined, challenge, 4);
    const opened = openGroupWelcome(f.peer, marshalCanonical(fresh.welcomes[0]), f.pin);
    expect(() => groupSessionFromWelcome(f.peer, opened, 5, f.peerState)).toThrow('epoch');
    expect(() => groupSessionFromWelcome(f.peer, opened, 5, { ...blocked, removed: true })).toThrow('removal');
    const recovered = checkGroupWelcomeReplay(groupSessionFromWelcome(f.peer, opened, 5, blocked), opened, 5,
      [{ seq: 5, envelope: marshalCanonical(fresh.welcomes[0]) }]);
    expect(recovered.root).toBe(winningState.root);
    expect(recovered.rekeys).toEqual([]);
    expect(recovered.seen).toEqual({});
    assertGroupCanSend(f.peer, recovered);
    const reply = createMessage(f.peer, groupSessionConversation(recovered), 'text', new TextEncoder().encode('winning branch'));
    expect(receiveGroupEvent(f.owner, reply, winningState).message.inner.body_type).toBe('text');
  });

  it('detects leading, interior and trailing omissions and never clears them on later replay', () => {
    const f = setup();
    for (const [sequences, boundary] of [[[5, 6], 4], [[4, 6], 5], [[4, 5], 6], [[], 6]] as const) {
      const blocked = checkGroupReplayCoverage(f.peerState, 3, 6, [...sequences]);
      expect(blocked.recovery).toEqual({ afterSequence: boundary, reason: 'missing_history', challenge: expect.stringMatching(/^[0-9a-f]{64}$/) });
      expect(restoreGroupSession(f.peer, JSON.parse(JSON.stringify(blocked))).recovery).toEqual(blocked.recovery);
      expect(checkGroupReplayCoverage(blocked, 6, 7, [7]).recovery).toEqual(blocked.recovery);
    }
    expect(checkGroupReplayCoverage(f.peerState, 3, 6, [2, 6, 4, 5, 5]).recovery).toBeNull();
    expect(f.peerState.recovery).toBeNull();
    for (const [from, head, seqs] of [[3, 2, []], [3, 4, [5]], [0, 1, [0]]] as const) {
      expect(() => checkGroupReplayCoverage(f.peerState, from, head, [...seqs])).toThrow('coverage');
    }
  });

  it('blocks every producer and new group event until a later welcome restores state', () => {
    const f = setup(), blocked = checkGroupReplayCoverage(f.peerState, 3, 5, [5]);
    expect(() => assertGroupCanSend(f.peer, blocked)).toThrow('incomplete');
    expect(() => prepareGroupSessionAddition(f.peer, blocked, [generateIdentity().publicKey])).toThrow('incomplete');
    expect(() => prepareGroupSessionRekey(f.peer, blocked)).toThrow('incomplete');
    expect(() => prepareGroupWelcomeRefresh(f.peer, blocked, [f.owner.publicKey])).toThrow('incomplete');
    const message = createMessage(f.owner, f.welcome.conversation, 'text', new TextEncoder().encode('after gap'));
    expect(() => receiveGroupEvent(f.peer, message, blocked)).toThrow('incomplete');
    expect(() => groupSessionFromWelcome(f.peer, f.welcome, 3, blocked)).toThrow('predates');
    // An attacker can repost valid ciphertext at a later relay sequence.
    expect(() => groupSessionFromWelcome(f.peer, f.welcome, 6, blocked)).toThrow('challenge');
    const challenge = new Uint8Array(Buffer.from(blocked.recovery!.challenge, 'hex'));
    const wrong = prepareGroupWelcomeRefresh(f.owner, f.state, [f.peer.publicKey], undefined, new Uint8Array(32));
    expect(() => groupSessionFromWelcome(f.peer, openGroupWelcome(f.peer, marshalCanonical(wrong.welcomes[0]), f.pin), 6, blocked)).toThrow('challenge');
    const refresh = prepareGroupWelcomeRefresh(f.owner, f.state, [f.peer.publicKey], undefined, challenge);
    const opened = openGroupWelcome(f.peer, marshalCanonical(refresh.welcomes[0]), f.pin);
    const recovered = groupSessionFromWelcome(f.peer, opened, 6, blocked);
    assertGroupCanSend(f.peer, recovered);
    expect(recovered.root).toBe(f.peerState.root);
    expect(recovered.rekeys).toEqual([]);
    expect(recovered.recovery).toBeNull();
    expect(checkGroupReplayCoverage(recovered, 6, 8, [8]).recovery?.afterSequence).toBe(7);
    const laterGap = checkGroupReplayCoverage(blocked, 5, 7, [7]);
    expect(laterGap.recovery!.challenge).not.toBe(blocked.recovery!.challenge);
    expect(() => groupSessionFromWelcome(f.peer, opened, 8, laterGap)).toThrow('challenge');
  });

  it('requires recovery for an expired authenticated control, without applying its authority', () => {
    const f = setup();
    const removal = createGroupControlMessage(f.owner, f.welcome.conversation, 'group_remove', createGroupRemoveBody([f.peer.keyID]), 1);
    const expiredText = createMessage(f.owner, f.welcome.conversation, 'text', new TextEncoder().encode('old'), undefined, 1);
    const forged = createGroupControlMessage(generateIdentity(), f.welcome.conversation, 'group_remove', createGroupRemoveBody([f.peer.keyID]), 1);
    const clock = vi.spyOn(Date, 'now').mockReturnValue((removal.expiry_ts + 2) * 1000);
    try {
      const blocked = checkExpiredGroupControl(f.peer, f.peerState, removal, 4);
      expect(blocked.recovery).toEqual({ afterSequence: 4, reason: 'expired_control', challenge: expect.stringMatching(/^[0-9a-f]{64}$/) });
      expect(blocked.removed).toBe(false);
      expect(blocked.snapshot).toBe(f.peerState.snapshot);
      expect(checkExpiredGroupControl(f.peer, f.peerState, expiredText, 4).recovery).toBeNull();
      expect(checkExpiredGroupControl(f.peer, f.peerState, forged, 4).recovery).toBeNull();
    } finally { clock.mockRestore(); }
  });

  it('does not let recovery bypass removal, rotation or same-epoch roster checks', () => {
    const f = setup();
    const refresh = prepareGroupWelcomeRefresh(f.owner, f.state, [f.peer.publicKey]);
    const opened = openGroupWelcome(f.peer, marshalCanonical(refresh.welcomes[0]), f.pin);
    expect(() => groupSessionFromWelcome(f.peer, opened, 6, { ...f.peerState, removed: true })).toThrow('removal');
    expect(() => groupSessionFromWelcome(f.peer, opened, 6, { ...f.peerState, needsRekey: true })).toThrow('epoch');
    const conflicting = { ...opened, state: new GroupState() };
    conflicting.state.applyGenesis(opened.state.snapshot());
    conflicting.state.groupName = 'Conflicting metadata';
    expect(() => groupSessionFromWelcome(f.peer, conflicting, 6, f.peerState)).toThrow('roster');
    expect(() => restoreGroupSession(f.peer, { ...f.peerState, recovery: { afterSequence: true, reason: 'missing_history' } })).toThrow('recovery');
    for (const challenge of [new Uint8Array(31), new Uint8Array(33)]) {
      expect(() => prepareGroupWelcomeRefresh(f.owner, f.state, [f.peer.publicKey], undefined, challenge)).toThrow('challenge');
      expect(() => prepareGroupSessionAddition(f.owner, f.state, [generateIdentity().publicKey], undefined, challenge)).toThrow('challenge');
    }
    expect(() => prepareGroupWelcomeRefresh(f.owner, f.state, [f.peer.publicKey, f.owner.publicKey], undefined, new Uint8Array(32))).toThrow('challenge');
  });
});
