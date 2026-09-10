import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, base64UrlEncode, base64UrlDecode, serializeEnvelope, deserializeEnvelope,
  openGroupWelcome, groupSessionFromWelcome, createMessage, groupSessionConversation, prepareGroupWelcomeRefresh,
  receiveGroupEvent, createGroupControlMessage, createGroupRemoveBody, prepareGroupSessionRekey, restoreGroupSession,
  prepareGroupAdmissionRenewal, prepareGroupSessionAddition,
  type Identity, type OuterEnvelope,
} from '@corpollc/qntm';
import { QntmGroupStore, groupDispatchDisposition, type GroupTransport } from '../src/group-store.js';
import { QntmGroupActions } from '../src/group-tool.js';
import * as identityGeneration from '../../client/src/identity/index.js';
import { toHex } from '../src/qntm.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding } from '../src/types.js';
const roots: string[] = [];
afterEach(() => { vi.useRealTimers(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'qntm-group-adapter-')); roots.push(root);
  const owner = generateIdentity(), member = generateIdentity(), late = generateIdentity();
  const invite = createInvite(owner, 'group'), conversation = createConversation(invite, deriveConversationKeys(invite));
  const roster = new GroupState(); roster.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Team', '', owner, [member.publicKey])));
  conversation.participants = roster.listMembers();
  let head = 0, failAfterPost = false;
  const rows: Array<{ seq: number; envelope: Uint8Array }> = [];
  const client: GroupTransport = {
    async postMessage(_id, envelope) { const seq = ++head; rows.push({ seq, envelope }); if (failAfterPost) { failAfterPost = false; throw new Error('ambiguous POST'); } return seq; },
    async receiveMessages(_id, cursor = 0) { const entries = rows.filter(row => row.seq > cursor); return { entries, messages: entries.map(row => row.envelope), sequence: head }; },
  };
  const contacts = { Owner: base64UrlEncode(owner.publicKey), Member: base64UrlEncode(member.publicKey), Late: base64UrlEncode(late.publicKey) };
  function store(identity: Identity, accountId = toHex(identity.keyID), link?: string) {
    const binding: ResolvedQntmBinding = { key: 'team', target: 'team', label: 'Team', enabled: true, conversationId: toHex(conversation.id),
      conversation, chatType: 'group', trigger: 'all', triggerNames: [], ordinaryGroup: true,
      groupActions: ['add', 'remove', 'refresh', 'rekey', 'retry', 'open', 'send'], groupLink: link,
      groupSeed: link ? undefined : { session: createGroupSession(identity, conversation, roster), cursor: 0 } };
    const account: ResolvedQntmAccount = { accountId, enabled: true, configured: true, relayUrl: 'https://relay.test', identity, identitySource: 'config',
      bindings: [binding], configErrors: [], config: { contacts } };
    return new QntmGroupStore(account, binding, { stateDir: root, client });
  }
  return { root, owner, member, late, conversation, roster, client, rows, store, ambiguous: () => { failAfterPost = true; } };
}
async function run(store: QntmGroupStore, action: Parameters<QntmGroupStore['prepare']>[0], options: Parameters<QntmGroupStore['prepare']>[1] = {}) {
  await store.exclusive(async () => { await store.sync(); store.saveOperation(store.prepare(action, options)); await store.resume(); });
}
describe('OpenClaw durable ordinary groups', () => {
  it('reviews admission renewal through refresh without exposing keys or sending before commit', async () => {
    const f = fixture(), store = f.store(f.member);
    await run(store, 'add', { contact: 'Late' });
    const before = store.load(), service = new QntmGroupActions(), scope = { key: 'native-renewal-review', store };
    const challenge = '42'.repeat(32), count = f.rows.length;
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'refresh', options: { contact: 'Late', challenge } }) as any;
    expect(reviewed.review.welcomePurpose).toBe('renewal');
    expect(reviewed.review.effect).toContain('proof of this existing admission');
    expect(reviewed.review.recoveryChallenge).toBe(challenge);
    expect(reviewed.review.recipientPublicKey).toBe(base64UrlEncode(f.late.publicKey));
    expect(JSON.stringify(reviewed)).not.toContain(before.session!.root);
    expect(f.rows).toHaveLength(count); expect(store.load().operation).toBeNull();
    await service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash });
    const opened = openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('renewal'); expect(opened.recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
    expect(opened.replayFromSequence).toBe(count);
    expect(opened.admissions).toEqual(before.session!.admissions);
    expect(f.rows).toHaveLength(count + 1); expect(store.load().session!.epoch).toBe(before.session!.epoch);
    expect(store.load().session!.root).toBe(before.session!.root);
  });
  it('retains the exact reviewed renewal and its challenge through a lost ACK and restart', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const before = member.load(), count = f.rows.length, challenge = '71'.repeat(32); f.ambiguous();
    await expect(run(member, 'refresh', { contact: 'Late', challenge })).rejects.toThrow('ambiguous POST');
    const pending = member.load().operation!;
    expect(pending.welcomePurpose).toBe('renewal'); expect(pending.controls).toEqual([]); expect(pending.sentWelcomes).toBe(0);
    expect(restoreGroupSession(f.member, pending.expected).admissions).toEqual(before.session!.admissions);
    const restarted = f.store(f.member), service = new QntmGroupActions(), scope = { key: 'native-retry-renewal', store: restarted };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(reviewed.review.welcomePurpose).toBe('renewal'); expect(reviewed.review.recoveryChallenge).toBe(challenge);
    await service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash });
    expect(f.rows.slice(count).map(row => row.envelope)).toEqual([base64UrlDecode(pending.welcomes[0]), base64UrlDecode(pending.welcomes[0])]);
    expect(restarted.load().operation).toBeNull(); expect(restarted.load().session!.root).toBe(before.session!.root);
    const opened = openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
  });
  it('preserves founding-member generic refresh and unfinished older journals', async () => {
    const f = fixture(), member = f.store(f.member), challenge = '35'.repeat(32);
    const prepared = member.prepare('refresh', { contact: 'Owner', challenge });
    expect(prepared.welcomePurpose).toBe('refresh');
    delete prepared.welcomePurpose; delete prepared.recoveryChallenge; // Earlier native journal format.
    member.saveOperation(prepared);
    const restarted = f.store(f.member); await restarted.exclusive(() => restarted.resume());
    expect(f.rows).toHaveLength(1); expect(f.rows[0].envelope).toEqual(base64UrlDecode(prepared.welcomes[0]));
    const opened = openGroupWelcome(f.owner, f.rows[0].envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('refresh'); expect(opened.recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
    expect(restarted.load().session!.epoch).toBe(0);
  });
  it('invalidates a reviewed renewal when admission provenance changes without changing root or roster', async () => {
    const f = fixture(), store = f.store(f.member);
    await run(store, 'add', { contact: 'Late' });
    const service = new QntmGroupActions(), scope = { key: 'provenance-review', store };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'refresh', options: { contact: 'Late' } }) as any;
    const state = store.load(); state.session!.admissions = {}; store.save(state);
    const count = f.rows.length;
    await expect(service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash })).rejects.toThrow('configuration changed');
    expect(store.load().operation).toBeNull(); expect(f.rows).toHaveLength(count);
  });
  it.each(['provenance', 'contact'] as const)('retains a pending renewal without POST when its %s changes', async changed => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const pending = member.prepare('refresh', { contact: 'Late' }); member.saveOperation(pending);
    if (changed === 'provenance') {
      const state = member.load(); state.session!.admissions[toHex(f.late.keyID)].completion!.rekeyDigest = '12'.repeat(32); member.save(state);
    } else member.account.config.contacts!.Late = base64UrlEncode(generateIdentity().publicKey);
    const count = f.rows.length, restarted = f.store(f.member);
    await expect(restarted.exclusive(() => restarted.resume())).rejects.toThrow(changed === 'provenance' ? 'current provenance' : 'contact pin changed');
    expect(restarted.load().operation).toEqual(pending); expect(f.rows).toHaveLength(count);
  });
  it.each([false, true])('prefers a current renewal over a later replayed addition welcome (rotated=%s)', async rotated => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const oldWelcome = f.rows.at(-1)!.envelope;
    if (rotated) await run(member, 'rekey');
    const state = member.load(), admission = state.session!.admissions[toHex(f.late.keyID)];
    const renewal = prepareGroupAdmissionRenewal(f.member, state.session!, f.late.publicKey,
      { addId: admission.addId, addDigest: admission.addDigest }, undefined, undefined, state.cursor);
    const opened = openGroupWelcome(f.late, serializeEnvelope(renewal.welcomes[0]),
      { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('renewal'); expect(opened).not.toHaveProperty('rekeyId');
    await f.client.postMessage(f.conversation.id, serializeEnvelope(renewal.welcomes[0]));
    await f.client.postMessage(f.conversation.id, oldWelcome);
    const late = f.store(f.late, undefined, member.link());
    await late.exclusive(() => late.open());
    expect(late.load().session!.epoch).toBe(rotated ? 2 : 1);
    expect(late.load().session!.rekeys).toEqual([]);
    expect(late.load().bootstrap).toBe(state.cursor);
    expect(late.load().session!.admissions[toHex(f.late.keyID)]).toEqual(admission);
    await late.send('native renewal uses current keys');
    await member.exclusive(() => member.sync());
    expect(member.load().outbox.at(-1)!.text).toBe('native renewal uses current keys');
  });
  it('keeps saved removal against old renewals, then accepts renewed delivery of a later expired readmission', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const late = f.store(f.late, undefined, member.link());
    await late.exclusive(() => late.open());
    const oldRenewal = member.prepare('refresh', { contact: 'Late' });
    expect(oldRenewal.welcomePurpose).toBe('renewal');
    await run(member, 'remove', { contact: 'Late' });
    await late.exclusive(() => late.sync());
    expect(late.load().session!.removedAtEpoch).toBe(1);
    await f.client.postMessage(f.conversation.id, base64UrlDecode(oldRenewal.welcomes[0]));
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    expect(late.load().session!.removed).toBe(true);

    await member.exclusive(() => member.sync());
    const current = member.load(), readmission = prepareGroupSessionAddition(f.member, current.session!, [f.late.publicKey], 1,
      undefined, current.cursor);
    for (const envelope of [readmission.addition, readmission.rekey, readmission.welcomes[0]]) {
      await f.client.postMessage(f.conversation.id, serializeEnvelope(envelope));
    }
    await member.exclusive(() => member.sync());
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((readmission.welcomes[0].expiry_ts + 1) * 1000);
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    expect(late.load().session!.removed).toBe(true);
    const admitted = member.load();
    const refreshed = prepareGroupWelcomeRefresh(f.member, admitted.session!, [f.late.publicKey], undefined, undefined, admitted.cursor);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    await run(member, 'refresh', { contact: 'Late' });
    expect(openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id }).purpose).toBe('renewal');
    // A later generic refresh is ineligible for saved removal; candidate
    // fallback must still reach the valid renewal of the later admission.
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await late.exclusive(() => late.open());
    expect(late.load().session!.removed).toBe(false);
    expect(late.load().session!.epoch).toBe(3);
    expect(late.load().session!.rekeys).toEqual([]);
    expect(late.load().session!.admissions[toHex(f.late.keyID)].sourceEpoch).toBe(2);
    await late.send('native readmission renewal reply');
    await member.exclusive(() => member.sync());
    expect(member.load().outbox.at(-1)!.text).toBe('native readmission renewal reply');
  });
  it('allows a noncreator member to add, opens a key-free contact link, and exchanges encrypted replies', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    expect(member.load().session?.epoch).toBe(1); expect(member.load().operation).toBeNull();
    const late = f.store(f.late, undefined, member.link());
    await late.exclusive(() => late.open());
    expect(late.load().session?.epoch).toBe(1);
    expect(late.load().session?.rekeys).toEqual([]);
    await late.send('hello from the new contact');
    await member.exclusive(() => member.sync());
    expect(member.load().outbox.map(row => row.text)).toEqual(['hello from the new contact']);
    expect(statSync(member.filename).mode & 0o777).toBe(0o600);
    const disk = JSON.parse(readFileSync(member.filename, 'utf8'));
    expect(disk.cursor).toBe(f.rows.at(-1)!.seq); expect(disk.session.root).toBe(late.load().session?.root);
    await run(member, 'rekey');
    await late.exclusive(() => late.open()); // Existing keys catch up even though its original welcome is older.
    expect(late.load().session!.epoch).toBe(2);
  });
  it('retains exact ciphertext after an ambiguous POST and releases the welcome only after replay acceptance', async () => {
    const f = fixture(), member = f.store(f.member); f.ambiguous();
    await expect(run(member, 'add', { contact: 'Late' })).rejects.toThrow('ambiguous POST');
    const pending = member.load().operation!; expect(pending.sentControls).toBe(0); expect(pending.sentWelcomes).toBe(0);
    expect(f.rows).toHaveLength(1);
    const restarted = f.store(f.member); await restarted.exclusive(() => restarted.resume());
    expect(f.rows[0].envelope).toEqual(new Uint8Array(Buffer.from(pending.controls[0], "base64url")));
    expect(restarted.load().operation).toBeNull(); expect(restarted.load().session?.epoch).toBe(1);
    expect(f.rows).toHaveLength(3);
    const opened = openGroupWelcome(f.late, f.rows[2].envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.conversation.currentEpoch).toBe(1);
  });
  it('recognizes an exact verified control after a lost ACK, expiry and restart without reposting', async () => {
    const f = fixture(), member = f.store(f.member); f.ambiguous();
    await expect(run(member, 'rekey')).rejects.toThrow('ambiguous POST');
    const pending = member.load().operation!, control = deserializeEnvelope(base64UrlDecode(pending.controls[0]));
    expect(pending.sentControls).toBe(0);
    await member.exclusive(() => member.sync());
    expect(member.load().session!.seen[toHex(control.msg_id)]).toBeDefined();
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((control.expiry_ts + 1) * 1000);
    const restarted = f.store(f.member); await restarted.exclusive(() => restarted.resume());
    expect(restarted.load().operation).toBeNull(); expect(restarted.load().session!.epoch).toBe(1);
    expect(f.rows).toHaveLength(1); expect(f.rows[0].envelope).toEqual(base64UrlDecode(pending.controls[0]));
  });
  it('retains an expired control with no authenticated acceptance evidence', async () => {
    const f = fixture(), member = f.store(f.member), pending = member.prepare('rekey', {});
    member.saveOperation(pending);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(pending.controls[0])).expiry_ts + 1) * 1000);
    await expect(member.exclusive(() => member.resume())).rejects.toThrow('Saved group operation expired');
    expect(member.load().operation).toEqual(pending); expect(f.rows).toHaveLength(0);
  });
  it('completes an exact accepted text after a lost ACK and later rekey without sending a duplicate', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner); f.ambiguous();
    await expect(member.send('one accepted text')).rejects.toThrow('ambiguous POST');
    const pending = member.load().operation!;
    await member.exclusive(() => member.sync());
    await run(owner, 'rekey');
    const restarted = f.store(f.member); await restarted.exclusive(() => restarted.resume());
    expect(restarted.load().operation).toBeNull(); expect(restarted.load().session!.epoch).toBe(1);
    expect(f.rows).toHaveLength(2); expect(f.rows[0].envelope).toEqual(base64UrlDecode(pending.controls[0]));
  });
  it('persists missing-history recovery, rejects a replayed welcome, then accepts its challenge-bound refresh', async () => {
    const f = fixture(), member = f.store(f.member); await run(member, 'add', { contact: 'Late' });
    const late = f.store(f.late, undefined, member.link()); await late.exclusive(() => late.open());
    const oldWelcome = f.rows.at(-1)!.envelope;
    await member.send('missed retained row'); f.rows.splice(f.rows.length - 1, 1);
    await late.exclusive(() => late.sync());
    const challenge = late.load().session!.recovery!.challenge;
    await expect(late.send('unsafe old-key reply')).rejects.toThrow();
    await f.client.postMessage(f.conversation.id, oldWelcome);
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    expect(late.load().session!.recovery!.challenge).toBe(challenge);
    await run(member, 'refresh', { contact: 'Late', challenge });
    await late.exclusive(() => late.open()); expect(late.load().session!.recovery).toBeNull();
    await late.send('safe recovered reply');
    expect(late.load().session!.epoch).toBe(1);
  });
  it('keeps removal across restart and disallows old admission replay or current-member refresh', async () => {
    const f = fixture(), member = f.store(f.member); await run(member, 'add', { contact: 'Late' });
    const late = f.store(f.late, undefined, member.link()); await late.exclusive(() => late.open());
    await run(member, 'remove', { contact: 'Late' }); await late.exclusive(() => late.sync());
    expect(late.load().session?.removed).toBe(true);
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    await expect(run(member, 'refresh', { contact: 'Late' })).rejects.toThrow('not a current member');
    await expect(late.send('removed')).rejects.toThrow();
    await run(member, 'add', { contact: 'Late' }); await late.exclusive(() => late.open());
    expect(late.load().session?.removed).toBe(false); expect(late.load().session?.epoch).toBe(3);
  });
  it('requires concrete matching review and invalidates it when a pinned contact changes', async () => {
    const f = fixture(), store = f.store(f.member), service = new QntmGroupActions(), scope = { key: 'native-session-a', store };
    const review = await service.execute(scope, { operation: 'prepare', action: 'add', options: { contact: 'Late' } }) as any;
    expect(review.review.recipientPublicKey).toBe(base64UrlEncode(f.late.publicKey)); expect(f.rows).toHaveLength(0);
    await expect(service.execute({ ...scope, key: 'other-session' }, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('mismatched');
    store.account.config.contacts!.Late = base64UrlEncode(generateIdentity().publicKey);
    await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(0);
  });
  it('quarantines a competing rekey branch and never dispatches its queued plaintext after recovery', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    const source = owner.load().session!;
    const [low, high] = [prepareGroupSessionRekey(f.owner, source), prepareGroupSessionRekey(f.owner, source)]
      .sort((a, b) => toHex(a.rekey.msg_id).localeCompare(toHex(b.rekey.msg_id)));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(high.rekey));
    const losing = createMessage(f.owner, high.conversation, 'text', new TextEncoder().encode('losing branch agent trigger'));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(losing));
    await member.exclusive(() => member.sync());
    const queued = member.load().outbox[0]; expect(queued.text).toBe('losing branch agent trigger');
    await f.client.postMessage(f.conversation.id, serializeEnvelope(low.rekey));
    await member.exclusive(() => member.sync());
    expect(member.load().outbox).toEqual([]); expect(member.load().session!.recovery).not.toBeNull();
    expect(groupDispatchDisposition(member.load(), queued)).toBe('discard');
    const accepted = receiveGroupEvent(f.owner, low.rekey, source).state;
    const refreshed = prepareGroupWelcomeRefresh(f.owner, accepted, [f.member.publicKey], undefined,
      new Uint8Array(Buffer.from(member.load().session!.recovery!.challenge, 'hex')), f.rows.at(-1)!.seq);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await member.exclusive(() => member.open(owner.link()));
    expect(member.load().session!.recovery).toBeNull();
    expect(groupDispatchDisposition(member.load(), queued)).toBe('discard');
    expect(member.load().outbox).toEqual([]);
    // A newly authenticated ciphertext may reuse an ID pruned by the rewind.
    // It must not grant the old queued plaintext fresh delivery authority.
    const ids = vi.spyOn(identityGeneration, 'generateMessageID').mockReturnValueOnce(losing.msg_id);
    const canonical = createMessage(f.owner, groupSessionConversation(accepted), 'text', new TextEncoder().encode('canonical same-ID message'));
    ids.mockRestore();
    expect(canonical.msg_id).toEqual(losing.msg_id);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(canonical));
    await member.exclusive(() => member.sync());
    const fresh = member.load().outbox[0];
    expect(fresh.messageId).toBe(queued.messageId); expect(fresh.groupDispatch).not.toEqual(queued.groupDispatch);
    expect(groupDispatchDisposition(member.load(), queued)).toBe('discard');
    expect(groupDispatchDisposition(member.load(), fresh)).toBe('dispatch');
  });
  it('keeps a verified queued delivery eligible after dedup-cache eviction and restart', async () => {
    const f = fixture(), member = f.store(f.member);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('pending slow host'))));
    await member.exclusive(() => member.sync());
    const queued = member.load().outbox[0], checkpoint = member.load();
    // Model the exact bounded-cache result of unrelated later traffic without
    // performing thousands of expensive crypto operations in this regression.
    checkpoint.session!.seen = {};
    member.save(checkpoint);
    const restarted = f.store(f.member);
    expect(groupDispatchDisposition(restarted.load(), queued)).toBe('dispatch');
    await run(restarted, 'rekey');
    expect(groupDispatchDisposition(restarted.load(), queued)).toBe('dispatch');
    expect(restarted.load().dispatchGeneration).toBe(queued.groupDispatch!.generation);
  });
  it('quarantines legacy ordinary queued drafts without granting a new binding', async () => {
    const f = fixture(), member = f.store(f.member);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('old unbound draft'))));
    await member.exclusive(() => member.sync());
    const queued = member.load().outbox[0]; delete queued.groupDispatch;
    expect(groupDispatchDisposition(member.load(), queued)).toBe('discard');
  });
  it('replays a current-epoch rekey posted before a delayed welcome instead of treating the welcome sequence as authority', async () => {
    const f = fixture(), member = f.store(f.member);
    const operation = member.prepare('add', { contact: 'Late' });
    for (const wire of operation.controls) await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(wire, 'base64url')));
    await member.exclusive(() => member.sync());
    const rotation = prepareGroupSessionRekey(f.member, member.load().session!);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(rotation.rekey));
    await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(operation.welcomes[0], 'base64url')));
    const late = f.store(f.late, undefined, member.link()); await late.exclusive(() => late.open());
    expect(late.load().session!.epoch).toBe(2);
    expect(late.load().session!.root).toBe(toHex(rotation.conversation.keys.root));
  });
  it('detects an omitted rekey between the signed replay anchor and delayed welcome', async () => {
    const f = fixture(), member = f.store(f.member), operation = member.prepare('add', { contact: 'Late' });
    for (const wire of operation.controls) await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(wire, 'base64url')));
    await member.exclusive(() => member.sync());
    const rotation = prepareGroupSessionRekey(f.member, member.load().session!);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(rotation.rekey));
    await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(operation.welcomes[0], 'base64url')));
    f.rows.splice(2, 1); // The relay omits the transition posted before welcome delivery.
    const late = f.store(f.late, undefined, member.link()); await late.exclusive(() => late.open());
    expect(late.load().session!.recovery).toMatchObject({ reason: 'missing_history', afterSequence: 3 });
    await expect(late.send('unsafe stale key send')).rejects.toThrow();
  });
  it.each([[false, false], [true, false], [false, true], [true, true]])('quarantines an old-source competing rekey and recovers at the same epoch (expired=%s, afterBootstrap=%s)', async (expired, afterBootstrap) => {
    const f = fixture(), member = f.store(f.member), source = member.load().session!;
    let operation = member.prepare('add', { contact: 'Late' });
    while (deserializeEnvelope(base64UrlDecode(operation.controls[1])).msg_id[0] < 128) operation = member.prepare('add', { contact: 'Late' });
    for (const wire of operation.controls) await f.client.postMessage(f.conversation.id, base64UrlDecode(wire));
    const admitted = receiveGroupEvent(f.member, deserializeEnvelope(base64UrlDecode(operation.controls[0])), source).state;
    let winner = prepareGroupSessionRekey(f.member, admitted, 1);
    while (winner.rekey.msg_id[0] >= 128) winner = prepareGroupSessionRekey(f.member, admitted, 1);
    const losingText = createMessage(f.member, groupSessionConversation(restoreGroupSession(f.member, operation.expected)), 'text', new TextEncoder().encode('must never trigger the agent'));
    let late = f.store(f.late, undefined, member.link());
    if (afterBootstrap) {
      await f.client.postMessage(f.conversation.id, base64UrlDecode(operation.welcomes[0]));
      await late.exclusive(() => late.open()); expect(late.load().session!.recovery).toBeNull();
    }
    await f.client.postMessage(f.conversation.id, serializeEnvelope(losingText));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(winner.rekey));
    if (!afterBootstrap) await f.client.postMessage(f.conversation.id, base64UrlDecode(operation.welcomes[0]));
    const accepted = receiveGroupEvent(f.member, winner.rekey, admitted).state;
    if (expired) { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((winner.rekey.expiry_ts + 1) * 1000); }
    await late.exclusive(() => afterBootstrap ? late.sync() : late.open());
    expect(late.load().session!.epoch).toBe(1);
    expect(late.load().session!.recovery).not.toBeNull(); expect(late.load().outbox).toEqual([]);
    const challenge = late.load().session!.recovery!.challenge;
    const before = f.rows.length;
    await expect(late.send('unsafe stale key send')).rejects.toThrow(); expect(f.rows).toHaveLength(before);
    late = f.store(f.late, undefined, member.link());
    await expect(late.exclusive(() => late.open())).rejects.toThrow('No current welcome');
    expect(late.load().session!.recovery!.challenge).toBe(challenge);
    const refresh = prepareGroupWelcomeRefresh(f.member, accepted, [f.late.publicKey], undefined,
      new Uint8Array(Buffer.from(challenge, 'hex')), f.rows.at(-1)!.seq);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refresh.welcomes[0]));
    await late.exclusive(() => late.open());
    expect(late.load().session!.epoch).toBe(1); expect(late.load().session!.root).toBe(accepted.root);
    expect(late.load().session!.recovery).toBeNull(); expect(late.load().session!.rekeys).toEqual([]);
    expect(late.load().outbox).toEqual([]);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createMessage(f.member, groupSessionConversation(accepted), 'text', new TextEncoder().encode('winning branch message'))));
    await late.exclusive(() => late.sync());
    expect(late.load().outbox.map(row => row.text)).toEqual(['winning branch message']);
    await late.send('safe same-epoch recovery reply');
  });
  it('blocks an expired authenticated removal posted before welcome delivery', async () => {
    const f = fixture(), member = f.store(f.member), operation = member.prepare('add', { contact: 'Late' });
    for (const wire of operation.controls) await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(wire, 'base64url')));
    await member.exclusive(() => member.sync());
    const removal = createGroupControlMessage(f.member, groupSessionConversation(member.load().session!), 'group_remove', createGroupRemoveBody([f.late.keyID]), 1);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(removal));
    await f.client.postMessage(f.conversation.id, new Uint8Array(Buffer.from(operation.welcomes[0], 'base64url')));
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((removal.expiry_ts + 1) * 1000);
    const late = f.store(f.late, undefined, member.link()); await late.exclusive(() => late.open());
    expect(late.load().session!.recovery?.reason).toBe('expired_control');
    await expect(late.send('must not send')).rejects.toThrow();
  });
  it('preflights a stale saved addition before publishing any control', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    member.saveOperation(member.prepare('add', { contact: 'Late' }));
    const rotation = prepareGroupSessionRekey(f.owner, owner.load().session!);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(rotation.rekey));
    await expect(member.exclusive(() => member.resume())).rejects.toThrow();
    expect(f.rows).toHaveLength(1); expect(member.load().operation?.sentControls).toBe(0);
  });
  it('reports the exact send receipt rather than a later captured relay head', async () => {
    const f = fixture(), member = f.store(f.member), post = f.client.postMessage.bind(f.client);
    f.client.postMessage = async (id, bytes) => {
      const receipt = await post(id, bytes);
      await post(id, serializeEnvelope(createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('concurrent reply'))));
      return receipt;
    };
    expect((await member.send('outgoing')).sequence).toBe(1);
    expect(member.load().cursor).toBe(2);
  });
  it('serializes simultaneous local writers and refuses stale checkpoint commits', async () => {
    const f = fixture(), one = f.store(f.member), two = f.store(f.member), stale = two.load();
    await Promise.all([one.send('one'), two.send('two')]);
    expect(f.rows).toHaveLength(2); expect(one.load().cursor).toBe(2); expect(one.load().operation).toBeNull();
    expect(() => two.save(stale)).toThrow('Concurrent group writer');
  });
});
