import { describe, expect, it, vi } from 'vitest';
import {
  generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, receiveGroupEvent,
  prepareGroupSessionAddition, prepareGroupWelcomeRefresh, assertGroupWelcomeRefreshCurrent,
  openGroupWelcome, marshalCanonical, createMessage, decryptMessage, GROUP_WELCOME_TTL,
  createGroupControlMessage, createGroupRemoveBody, createRekey, prepareGroupSessionRekey, assertGroupCanSend,
} from '../src/index.js';

function setup() {
  const owner = generateIdentity(), contact = generateIdentity();
  const invite = createInvite(owner, 'group');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const group = new GroupState();
  group.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Refresh team', '', owner, [])));
  conversation.participants = group.listMembers();
  const initial = createGroupSession(owner, conversation, group);
  const operation = prepareGroupSessionAddition(owner, initial, [contact.publicKey]);
  const added = receiveGroupEvent(owner, operation.addition, initial);
  const accepted = receiveGroupEvent(owner, operation.rekey, added.state);
  return { owner, contact, initial, operation, accepted,
    pin: { conversationId: conversation.id, inviterPublicKey: owner.publicKey } };
}

describe('current-member welcome refresh', () => {
  it('recovers an expired welcome without changing membership, epoch or keys', () => {
    const f = setup(), before = structuredClone(f.accepted.state);
    const clock = vi.spyOn(Date, 'now').mockReturnValue((f.operation.welcomes[0].expiry_ts + 1) * 1000);
    try {
      expect(() => openGroupWelcome(f.contact, marshalCanonical(f.operation.welcomes[0]), f.pin)).toThrow('expired');
      const refresh = prepareGroupWelcomeRefresh(f.owner, f.accepted.state, [f.contact.publicKey]);
      assertGroupWelcomeRefreshCurrent(f.owner, f.accepted.state, refresh);
      const opened = openGroupWelcome(f.contact, marshalCanonical(refresh.welcomes[0]), f.pin);
      expect(opened.purpose).toBe('refresh');
      expect(opened).not.toHaveProperty('additionId');
      expect(opened).not.toHaveProperty('rekeyId');
      expect(opened.conversation.keys).toEqual(f.accepted.conversation.keys);
      expect(opened.conversation.currentEpoch).toBe(1);
      expect(opened.conversation).not.toHaveProperty('inviteToken');
      expect(opened.conversation).not.toHaveProperty('epochKeys');
      expect(opened.state.snapshot()).toEqual(f.accepted.group.snapshot());
      const message = createMessage(f.contact, opened.conversation, 'text', new TextEncoder().encode('recovered'));
      expect(decryptMessage(message, f.accepted.conversation).inner.body).toEqual(new TextEncoder().encode('recovered'));
      expect(f.accepted.state).toEqual(before);
    } finally { clock.mockRestore(); }
  });

  it('rejects a removed recipient and never releases a stale prepared refresh', () => {
    const f = setup();
    const refresh = prepareGroupWelcomeRefresh(f.owner, f.accepted.state, [f.contact.publicKey]);
    const removal = createGroupControlMessage(f.owner, f.accepted.conversation, 'group_remove', createGroupRemoveBody([f.contact.keyID]));
    const removed = receiveGroupEvent(f.owner, removal, f.accepted.state);
    expect(() => assertGroupWelcomeRefreshCurrent(f.owner, removed.state, refresh)).toThrow('rotation');
    const rekey = createGroupControlMessage(f.owner, removed.conversation, 'group_rekey', createRekey(f.owner, removed.conversation, removed.group).bodyBytes);
    const rotated = receiveGroupEvent(f.owner, rekey, removed.state);
    expect(() => prepareGroupWelcomeRefresh(f.owner, rotated.state, [f.contact.publicKey])).toThrow('current member');
    expect(() => assertGroupWelcomeRefreshCurrent(f.owner, rotated.state, refresh)).toThrow('differs');
    expect(() => prepareGroupWelcomeRefresh(f.owner, { ...f.accepted.state, removed: true }, [f.contact.publicKey])).toThrow('removed');
  });

  it('validates all recipients, identity and lifetime before producing a refresh', () => {
    const f = setup();
    for (const recipients of [[], [generateIdentity().publicKey], [f.contact.publicKey, f.contact.publicKey], [new Uint8Array(32)]]) {
      expect(() => prepareGroupWelcomeRefresh(f.owner, f.accepted.state, recipients)).toThrow();
    }
    expect(() => prepareGroupWelcomeRefresh(f.contact, f.accepted.state, [f.owner.publicKey])).toThrow();
    for (const ttl of [0, -1, 1.5, GROUP_WELCOME_TTL + 1]) {
      expect(() => prepareGroupWelcomeRefresh(f.owner, f.accepted.state, [f.contact.publicKey], ttl)).toThrow('lifetime');
    }
    const refresh = prepareGroupWelcomeRefresh(f.owner, f.accepted.state, [f.contact.publicKey], 1);
    const clock = vi.spyOn(Date, 'now').mockReturnValue((refresh.welcomes[0].expiry_ts + 1) * 1000);
    try { expect(() => assertGroupWelcomeRefreshCurrent(f.owner, f.accepted.state, refresh)).toThrow('expired'); }
    finally { clock.mockRestore(); }
  });

  it('supports an existing member at epoch zero without claiming a new admission', () => {
    const f = setup();
    const refresh = prepareGroupWelcomeRefresh(f.owner, f.initial, [f.owner.publicKey]);
    const opened = openGroupWelcome(f.owner, marshalCanonical(refresh.welcomes[0]), f.pin);
    expect(opened.purpose).toBe('refresh');
    expect(opened.conversation.currentEpoch).toBe(0);
  });

  it('lets a remaining noncreator finish another member’s interrupted rotation', () => {
    const f = setup(), newcomer = generateIdentity();
    const memberState = createGroupSession(f.contact, f.accepted.conversation, f.accepted.group);
    const addition = prepareGroupSessionAddition(f.owner, f.accepted.state, [newcomer.publicKey]);
    const pending = receiveGroupEvent(f.contact, addition.addition, memberState);
    expect(() => assertGroupCanSend(f.contact, pending.state)).toThrow('rotation');
    const before = structuredClone(pending.state);
    const rotation = prepareGroupSessionRekey(f.contact, pending.state);
    expect(pending.state).toEqual(before);
    const received = receiveGroupEvent(f.contact, rotation.rekey, pending.state);
    assertGroupCanSend(f.contact, received.state);
    expect(received.state.epoch).toBe(2);
    const refresh = prepareGroupWelcomeRefresh(f.contact, received.state, [newcomer.publicKey]);
    const opened = openGroupWelcome(newcomer, marshalCanonical(refresh.welcomes[0]),
      { conversationId: f.pin.conversationId, inviterPublicKey: f.contact.publicKey });
    expect(opened.conversation.keys).toEqual(rotation.conversation.keys);
    expect(opened.state.snapshot().founding_members[0].key_id).toEqual(f.owner.keyID);
    expect(() => prepareGroupSessionRekey(f.contact, { ...pending.state, removed: true })).toThrow('removed');
  });
});
