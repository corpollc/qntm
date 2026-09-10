import { describe, expect, it, vi } from 'vitest';
import {
  QSP1Suite, generateIdentity, createInvite, createConversation, deriveConversationKeys,
  createMessage, decryptMessage, marshalCanonical, unmarshalCanonical,
  GroupState, createGroupGenesisBody, parseGroupGenesisBody, parseGroupRekeyBody,
  applyRekey, createRekey, base64UrlEncode, prepareGroupAddition, openGroupWelcome,
  isGroupWelcomeEnvelope, GROUP_WELCOME_TTL, MAX_GROUP_WELCOME_BYTES,
  groupSessionFromWelcome, checkGroupReplayCoverage, assertGroupCanSend,
  createGroupSession, prepareGroupSessionAddition, receiveGroupEvent, prepareGroupAdmissionRenewal,
  assertGroupAdmissionRenewalCurrent, prepareGroupSessionRekey,
} from '../src/index.js';
import { openSecret, sealSecret } from '../src/crypto/naclbox.js';

const suite = new QSP1Suite();
function setup(epoch = 0) {
  const owner = generateIdentity(), peer = generateIdentity(), late = generateIdentity();
  const invite = createInvite(owner, 'group');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const state = new GroupState();
  state.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Colleagues', 'private roster', owner, [peer.publicKey])));
  conversation.participants = state.listMembers();
  if (epoch) applyRekey(conversation, suite.generateGroupKey(), epoch);
  return { owner, peer, late, conversation, state };
}
const pin = (f: ReturnType<typeof setup>) => ({ conversationId: f.conversation.id, inviterPublicKey: f.owner.publicKey });

describe('Contact group welcomes', () => {
  it('signs exact admission provenance, rejects malformed records, and keeps old drafts unknown', () => {
    const f = setup();
    const operation = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    const envelope = operation.welcomes[0], kid = Buffer.from(f.late.keyID).toString('hex');
    const decoded = unmarshalCanonical<any>(openSecret(f.late.privateKey, f.owner.publicKey, envelope.ciphertext));
    expect(Object.keys(decoded.payload.admissions[kid]).sort()).toEqual(['add_hash', 'add_id', 'rekey_hash', 'rekey_id', 'source_epoch']);
    expect(decoded.payload.admissions[kid].source_epoch).toBe(0);
    const resign = (payload: any) => marshalCanonical({ ...envelope, ciphertext: sealSecret(f.owner.privateKey, f.late.publicKey,
      marshalCanonical({ payload, signature: suite.sign(f.owner.privateKey, marshalCanonical(payload)) })) });
    const changed = structuredClone(decoded);
    changed.payload.admissions[kid].add_hash[0] ^= 1;
    expect(() => openGroupWelcome(f.late, marshalCanonical({ ...envelope,
      ciphertext: sealSecret(f.late.privateKey, f.owner.publicKey, marshalCanonical(changed)) }), pin(f))).toThrow('signature');
    for (const change of [
      (payload: any) => { payload.admissions = null; },
      (payload: any) => { payload.admissions[kid].source_epoch = 1; },
      (payload: any) => { payload.admissions[kid].rekey_hash = new Uint8Array(31); },
      (payload: any) => { payload.admissions[kid].add_id = new Uint8Array(16); },
      (payload: any) => { payload.admissions['00'.repeat(16)] = payload.admissions[kid]; },
      (payload: any) => { payload.admissions = Object.fromEntries([['__proto__', payload.admissions[kid]]]); },
      (payload: any) => { payload.admissions[kid].extra = true; },
    ]) {
      const payload = structuredClone(decoded.payload); change(payload);
      expect(() => openGroupWelcome(f.late, resign(payload), pin(f))).toThrow();
    }
    const legacy = structuredClone(decoded.payload); delete legacy.admissions;
    expect(openGroupWelcome(f.late, resign(legacy), pin(f)).admissions).toEqual({});
  });

  it('renews expired delivery with a separate purpose, current keys and no historical-key archive', () => {
    const f = setup();
    let state = createGroupSession(f.owner, f.conversation, f.state);
    const operation = prepareGroupSessionAddition(f.owner, state, [f.late.publicKey], 1);
    state = receiveGroupEvent(f.owner, operation.addition, state).state;
    state = receiveGroupEvent(f.owner, operation.rekey, state).state;
    const admission = state.admissions[Buffer.from(f.late.keyID).toString('hex')];
    const expected = { addId: admission.addId, addDigest: admission.addDigest };
    const historical = createMessage(f.owner, operation.conversation, 'text', new TextEncoder().encode('older generation'));
    state = receiveGroupEvent(f.owner, prepareGroupSessionRekey(f.owner, state).rekey, state).state;
    vi.useFakeTimers();
    try {
      vi.setSystemTime((operation.welcomes[0].expiry_ts + 2) * 1000);
      expect(() => openGroupWelcome(f.late, marshalCanonical(operation.welcomes[0]), pin(f))).toThrow('expired');
      const renewal = prepareGroupAdmissionRenewal(f.owner, state, f.late.publicKey, expected, 1, undefined, 10);
      assertGroupAdmissionRenewalCurrent(f.owner, state, renewal);
      const payload = unmarshalCanonical<any>(openSecret(f.late.privateKey, f.owner.publicKey, renewal.welcomes[0].ciphertext)).payload;
      expect(payload.proto).toBe('qntm/group-renewal/v1');
      expect(payload.addition_id).toBeUndefined();
      expect(payload.rekey_id).toBeUndefined();
      expect(Object.keys(payload).sort()).toEqual(['admissions', 'envelope', 'group_key', 'group_state',
        'inviter_ik_pk', 'proto', 'recipient_ik_pk', 'replay_from_seq']);
      const opened = openGroupWelcome(f.late, marshalCanonical(renewal.welcomes[0]), pin(f));
      expect(opened.purpose).toBe('renewal');
      expect(opened.conversation.currentEpoch).toBe(2);
      expect(() => decryptMessage(historical, opened.conversation)).toThrow();
      expect(groupSessionFromWelcome(f.late, opened, 11).rekeys).toEqual([]);
      for (const admissions of [undefined, {}]) {
        const changed = structuredClone(payload);
        if (admissions === undefined) delete changed.admissions;
        else changed.admissions = admissions;
        const wire = marshalCanonical({ ...renewal.welcomes[0], ciphertext: sealSecret(f.owner.privateKey, f.late.publicKey,
          marshalCanonical({ payload: changed, signature: suite.sign(f.owner.privateKey, marshalCanonical(changed)) })) });
        expect(() => openGroupWelcome(f.late, wire, pin(f))).toThrow();
      }
      vi.setSystemTime((renewal.welcomes[0].expiry_ts + 1) * 1000);
      expect(() => assertGroupAdmissionRenewalCurrent(f.owner, state, renewal)).toThrow('expired');
    } finally { vi.useRealTimers(); }
  });

  it('fits authenticated provenance for a maximum-size ordinary group within the welcome bound', () => {
    const f = setup(), recipients = Array.from({ length: 126 }, () => generateIdentity());
    const operation = prepareGroupAddition(f.owner, f.conversation, f.state, recipients.map(identity => identity.publicKey));
    const wire = marshalCanonical(operation.welcomes[0]);
    expect(wire.length).toBeLessThanOrEqual(MAX_GROUP_WELCOME_BYTES);
    const opened = openGroupWelcome(recipients[0], wire, pin(f));
    expect(opened.state.memberCount()).toBe(128);
    expect(Object.keys(opened.admissions)).toHaveLength(126);
  });

  it('binds the replay interval before welcome delivery and rejects a changed anchor', () => {
    const f = setup();
    const envelope = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey], undefined, undefined, 12).welcomes[0];
    const joined = openGroupWelcome(f.late, marshalCanonical(envelope), pin(f));
    expect(joined.replayFromSequence).toBe(12);
    const state = groupSessionFromWelcome(f.late, joined, 16);
    const blocked = checkGroupReplayCoverage(state, joined.replayFromSequence, 16, [13, 14, 16]);
    expect(blocked.recovery?.afterSequence).toBe(15);
    expect(() => assertGroupCanSend(f.late, blocked)).toThrow('incomplete');
    expect(checkGroupReplayCoverage(state, joined.replayFromSequence, 16, [13, 14, 15, 16]).recovery).toBeNull();
    expect(() => groupSessionFromWelcome(f.late, joined, 12)).toThrow('anchor');
    const opened = unmarshalCanonical<any>(openSecret(f.late.privateKey, f.owner.publicKey, envelope.ciphertext));
    opened.payload.replay_from_seq = 15;
    const forged = { ...envelope, ciphertext: sealSecret(f.late.privateKey, f.owner.publicKey, marshalCanonical(opened)) };
    expect(() => openGroupWelcome(f.late, marshalCanonical(forged), pin(f))).toThrow('signature');
    for (const anchor of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey], undefined, undefined, anchor)).toThrow('anchor');
    }
    delete opened.payload.replay_from_seq;
    opened.signature = suite.sign(f.owner.privateKey, marshalCanonical(opened.payload));
    const legacy = { ...envelope, ciphertext: sealSecret(f.owner.privateKey, f.late.publicKey, marshalCanonical(opened)) };
    expect(openGroupWelcome(f.late, marshalCanonical(legacy), pin(f)).replayFromSequence).toBe(0);
  });

  for (const epoch of [0, 7]) it(`adds a contact after epoch ${epoch} without exposing earlier history`, () => {
    const f = setup(epoch);
    const before = structuredClone(f.conversation), roster = f.state.snapshot();
    const earlier = createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('before addition'));
    const added = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    expect(f.conversation).toEqual(before);
    expect(f.state.snapshot()).toEqual(roster);
    expect(added.conversation.currentEpoch).toBe(epoch + 1);
    expect(added.conversation.keys.root).not.toEqual(before.keys.root);
    const add = decryptMessage(added.addition, before);
    expect(unmarshalCanonical<any>(add.inner.body).group_epoch).toBe(epoch);
    const rekey = parseGroupRekeyBody(decryptMessage(added.rekey, before).inner.body);
    const peerKey = suite.unwrapKeyForRecipient(rekey.wrapped_keys[base64UrlEncode(f.peer.keyID)],
      f.peer.privateKey, f.peer.keyID, before.id);
    expect(peerKey).toEqual(added.conversation.keys.root);
    const joined = openGroupWelcome(f.late, marshalCanonical(added.welcomes[0]), pin(f));
    expect(joined.rekeyId).toEqual(added.rekey.msg_id);
    expect(joined.additionId).toEqual(added.addition.msg_id);
    expect(joined.conversation.keys).toEqual(added.conversation.keys);
    expect(joined.conversation.inviteToken).toBeUndefined();
    expect(joined.conversation.epochKeys).toBeUndefined();
    expect(() => decryptMessage(earlier, joined.conversation)).toThrow();
    const after = createMessage(f.late, joined.conversation, 'text', new TextEncoder().encode('hello group'));
    expect(new TextDecoder().decode(decryptMessage(after, added.conversation).inner.body)).toBe('hello group');
    expect(() => decryptMessage(after, before)).toThrow();
    const outer = added.welcomes[0];
    expect(isGroupWelcomeEnvelope(outer)).toBe(true);
    expect(Object.keys(outer).sort()).toEqual('v,suite,kind,conv_id,msg_id,conv_epoch,created_ts,expiry_ts,ciphertext'.split(',').sort());
    expect(() => decryptMessage(outer, before)).toThrow();
  });

  it('preserves member-initiated addition and encrypts each welcome to its recipient', () => {
    const f = setup(), second = generateIdentity();
    const snapshot = f.state.snapshot();
    const state = new GroupState(); state.applyGenesis(snapshot);
    const added = prepareGroupAddition(f.peer, f.conversation, state, [f.late.publicKey, second.publicKey]);
    const expected = { conversationId: f.conversation.id, inviterPublicKey: f.peer.publicKey };
    const first = openGroupWelcome(f.late, marshalCanonical(added.welcomes[0]), expected);
    const next = openGroupWelcome(second, marshalCanonical(added.welcomes[1]), expected);
    expect(first.state.snapshot().founding_members[0].key_id).toEqual(f.owner.keyID);
    expect(first.conversation.keys).toEqual(next.conversation.keys);
    expect(() => openGroupWelcome(second, marshalCanonical(added.welcomes[0]), expected)).toThrow();
    expect(() => openGroupWelcome(f.late, marshalCanonical(added.welcomes[0]), pin(f))).toThrow();
  });

  it('rejects outsiders, duplicate contacts, stale rosters and malformed keys without mutation', () => {
    const f = setup(), before = f.state.snapshot();
    expect(() => prepareGroupAddition(generateIdentity(), f.conversation, f.state, [f.late.publicKey])).toThrow('current group member');
    for (const recipients of [[f.owner.publicKey], [f.late.publicKey, f.late.publicKey], [new Uint8Array(32)], []]) {
      expect(() => prepareGroupAddition(f.owner, f.conversation, f.state, recipients)).toThrow();
    }
    expect(() => prepareGroupAddition(f.owner, { ...f.conversation, participants: [] }, f.state, [f.late.publicKey])).toThrow('roster');
    expect(() => prepareGroupAddition(f.owner, { ...f.conversation, currentEpoch: 0xffffffff }, f.state, [f.late.publicKey])).toThrow();
    for (const ttl of [0, -1, 1.5, GROUP_WELCOME_TTL + 1]) {
      expect(() => prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey], ttl)).toThrow('lifetime');
    }
    expect(f.state.snapshot()).toEqual(before);
  });

  it('binds all outer context, refuses expired or oversized welcomes and needs the right group', () => {
    const f = setup(), added = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    const envelope = added.welcomes[0], wire = marshalCanonical(envelope);
    for (const [field, replacement] of Object.entries({ v: 2, suite: 'other', kind: 'text',
      conv_id: new Uint8Array(16), msg_id: new Uint8Array(16), conv_epoch: 2,
      created_ts: envelope.created_ts - 1, expiry_ts: envelope.expiry_ts - 1, ciphertext: new Uint8Array(40) })) {
      expect(() => openGroupWelcome(f.late, marshalCanonical({ ...envelope, [field]: replacement }), pin(f))).toThrow();
    }
    expect(() => openGroupWelcome(f.late, wire, { ...pin(f), conversationId: new Uint8Array(16) })).toThrow('different group');
    expect(() => openGroupWelcome(f.late, wire, pin(f), envelope.expiry_ts + 1)).toThrow('expired');
    expect(() => openGroupWelcome(f.late, wire, pin(f), envelope.created_ts - 601)).toThrow();
    expect(openGroupWelcome(f.late, wire, pin(f), envelope.expiry_ts).conversation.currentEpoch).toBe(1);
    expect(() => openGroupWelcome(f.late, new Uint8Array(MAX_GROUP_WELCOME_BYTES + 1), pin(f))).toThrow('size');
    expect(() => openGroupWelcome(f.late, marshalCanonical({ ...envelope, extra: true }), pin(f))).toThrow();
  });

  it('checks signatures even though the recipient can construct an authenticated box', () => {
    const f = setup(), added = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    const envelope = added.welcomes[0];
    const opened = unmarshalCanonical<any>(openSecret(f.late.privateKey, f.owner.publicKey, envelope.ciphertext));
    opened.payload.group_key = suite.generateGroupKey();
    const forged = { ...envelope, ciphertext: sealSecret(f.late.privateKey, f.owner.publicKey, marshalCanonical(opened)) };
    expect(() => openGroupWelcome(f.late, marshalCanonical(forged), pin(f))).toThrow('signature');
  });

  it('validates the full signed roster and admission before returning group state', () => {
    const f = setup(), added = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    const envelope = added.welcomes[0];
    const clear = openSecret(f.late.privateKey, f.owner.publicKey, envelope.ciphertext);
    const mutations = [
      (p: any) => { p.group_state.founding_members = p.group_state.founding_members.filter((m: any) => !m.key_id.every((b: number, i: number) => b === f.late.keyID[i])); },
      (p: any) => { p.group_state.founding_members.push(p.group_state.founding_members[0]); },
      (p: any) => { p.group_state.founding_members[0].role = 'member'; },
      (p: any) => { p.recipient_ik_pk = f.peer.publicKey; },
      (p: any) => { p.group_state.founding_members[1].public_key = new Uint8Array(32); },
      (p: any) => { p.group_state.description = 'x'.repeat(4097); },
    ];
    for (const change of mutations) {
      const { payload } = unmarshalCanonical<any>(clear);
      change(payload);
      const signature = suite.sign(f.owner.privateKey, marshalCanonical(payload));
      const ciphertext = sealSecret(f.owner.privateKey, f.late.publicKey, marshalCanonical({ payload, signature }));
      expect(() => openGroupWelcome(f.late, marshalCanonical({ ...envelope, ciphertext }), pin(f))).toThrow();
    }
  });

  it('returns a detached group snapshot', () => {
    const f = setup(), snapshot = f.state.snapshot();
    snapshot.founding_members[0].key_id.fill(0);
    expect(f.state.isAdmin(f.owner.keyID)).toBe(true);
    expect(f.state.snapshot().founding_members[0].key_id).toEqual(f.owner.keyID);
  });

  it('excludes a removed contact from later keys and gives a readmitted contact only fresh keys', () => {
    const f = setup();
    const added = prepareGroupAddition(f.owner, f.conversation, f.state, [f.late.publicKey]);
    const originalWelcome = marshalCanonical(added.welcomes[0]);
    const joined = openGroupWelcome(f.late, originalWelcome, pin(f));
    const remaining = new GroupState(); remaining.applyGenesis(added.state.snapshot());
    remaining.applyRemove({ removed_at: Math.floor(Date.now() / 1000), removed_members: [f.late.keyID], reason: 'left' });
    const rotation = createRekey(f.owner, added.conversation, remaining);
    const body = parseGroupRekeyBody(rotation.bodyBytes);
    expect(body.wrapped_keys[base64UrlEncode(f.late.keyID)]).toBeUndefined();
    const afterRemoval = { ...added.conversation, keys: { ...added.conversation.keys }, participants: remaining.listMembers() };
    applyRekey(afterRemoval, rotation.newGroupKey, 2);
    const privateMessage = createMessage(f.owner, afterRemoval, 'text', new TextEncoder().encode('after removal'));
    expect(() => decryptMessage(privateMessage, joined.conversation)).toThrow();
    expect(() => decryptMessage(privateMessage, openGroupWelcome(f.late, originalWelcome, pin(f)).conversation)).toThrow();
    const readmitted = prepareGroupAddition(f.owner, afterRemoval, remaining, [f.late.publicKey]);
    const rejoined = openGroupWelcome(f.late, marshalCanonical(readmitted.welcomes[0]), pin(f));
    expect(rejoined.conversation.currentEpoch).toBe(3);
    expect(() => decryptMessage(privateMessage, rejoined.conversation)).toThrow();
    const latest = createMessage(f.owner, readmitted.conversation, 'text', new TextEncoder().encode('welcome back'));
    expect(new TextDecoder().decode(decryptMessage(latest, rejoined.conversation).inner.body)).toBe('welcome back');
  });
});
