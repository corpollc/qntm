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
async function completedPending(f: ReturnType<typeof fixture>, store: QntmGroupStore, options: { ttl?: number; challenge?: string; competing?: boolean; partial?: boolean } = {}) {
  await store.sync();
  const before = store.load(), value = prepareGroupSessionAddition(f.member, before.session!, [f.late.publicKey], options.ttl,
    options.challenge ? new Uint8Array(Buffer.from(options.challenge, 'hex')) : undefined, before.cursor);
  const operation = store.prepare('add', { contact: 'Late', challenge: options.challenge });
  operation.controls = [value.addition, value.rekey].map(wire => base64UrlEncode(serializeEnvelope(wire)));
  operation.welcomes = value.welcomes.map(wire => base64UrlEncode(serializeEnvelope(wire)));
  operation.expected = createGroupSession(f.member, value.conversation, value.state);
  store.saveOperation(operation);
  await f.client.postMessage(f.conversation.id, serializeEnvelope(value.addition));
  let rekey = value.rekey;
  if (options.competing) {
    const admitted = receiveGroupEvent(f.owner, value.addition, f.store(f.owner).load().session!).state;
    do { rekey = prepareGroupSessionRekey(f.owner, admitted).rekey; } while (toHex(rekey.msg_id) >= toHex(value.rekey.msg_id));
  }
  if (!options.partial) await f.client.postMessage(f.conversation.id, serializeEnvelope(rekey));
  await store.sync();
  const state = store.load(); state.session!.seen = {}; store.save(state);
  return operation;
}
describe('OpenClaw durable ordinary groups', () => {
  it('requires separate concrete rotation and welcome reviews after partial-add expiry and restart', async () => {
    const f = fixture(), member = f.store(f.member), challenge = '86'.repeat(32);
    const original = await completedPending(f, member, { partial: true, ttl: 1, challenge });
    expect(member.load().session!.needsRekey).toBe(true);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    const service = new QntmGroupActions(), scope = { key: 'repair-two-reviews', store: f.store(f.member) };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.recoveryPhase).toBe('addition_rekey'); expect(review.review.effect).toContain('does not deliver contact keys');
    expect(scope.store.load().operation).toEqual(original); expect(f.rows).toHaveLength(1);
    const rotated = await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }) as any;
    expect(rotated.status).toBe('rotation_verified'); expect(rotated.welcomePending).toBe(true);
    const repair = scope.store.load().operation!; expect(repair.welcomes).toEqual([]); expect(repair.controls).toHaveLength(1);
    expect(repair.origin!.controls).toEqual(original.controls); expect(repair.expected).not.toEqual(original.expected); expect(f.rows).toHaveLength(2);
    const anchor = scope.store.load().cursor;
    const renewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(renewed.review.welcomePurpose).toBe('renewal'); expect(scope.store.load().operation).toEqual(repair); expect(f.rows).toHaveLength(2);
    await service.execute(scope, { operation: 'commit', reviewToken: renewed.reviewToken, reviewHash: renewed.reviewHash });
    const opened = openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.replayFromSequence).toBe(anchor); expect(opened.recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
    expect(scope.store.load().operation).toBeNull(); expect(f.rows).toHaveLength(3);
  });
  it('reports rotation verification only for the retry that checked it, not an unrelated open', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true, ttl: 1 });
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    member.saveRetry(member.prepareRetry()); await member.resume();
    const service = new QntmGroupActions(), scope = { key: 'open-pending-repair', store: member };
    const review = await service.execute(scope, { operation: 'prepare', action: 'open', options: { link: member.link() } }) as any;
    const result = await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }) as any;
    expect(result.status).toBe('submitted'); expect(result).not.toHaveProperty('welcomePending');
    expect(member.load().operation!.phase).toBe('addition_rekey'); expect(f.rows).toHaveLength(2);
  });
  it.each([false, true])('keeps a valid repair exact after unknown POST and restart (accepted=%s)', async accepted => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true, ttl: 1 });
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    const repair = member.prepareRetry(); member.saveRetry(repair);
    const post = f.client.postMessage.bind(f.client);
    const failure = vi.spyOn(f.client, 'postMessage').mockImplementationOnce(async (...args) => {
      if (accepted) await post(...args); throw new Error('repair delivery unknown');
    });
    await expect(member.resume()).rejects.toThrow('delivery unknown'); failure.mockRestore();
    expect(member.load().operation).toEqual(repair);
    const restarted = f.store(f.member); await restarted.sync();
    const planned = restarted.prepareRetry();
    if (accepted) { expect(planned.welcomePurpose).toBe('renewal'); expect(f.rows).toHaveLength(2); }
    else { expect(planned).toEqual(repair); await restarted.exclusive(() => restarted.resume()); expect(f.rows).toHaveLength(2); }
    expect(f.rows[1].envelope).toEqual(base64UrlDecode(repair.controls[0]));
  });
  it('retains exact repair evidence across repeated expiry without sending another addition', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true, ttl: 1 });
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    const first = member.prepareRetry(); member.saveRetry(first);
    vi.setSystemTime((deserializeEnvelope(base64UrlDecode(first.controls[0])).expiry_ts + 1) * 1000);
    const second = member.prepareRetry();
    expect(second.controls).not.toEqual(first.controls); expect(second.origin).toEqual(first.origin);
    expect(second.superseded![0].controls).toEqual(first.controls); expect(second.superseded![0]).not.toHaveProperty('expected');
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toEqual(first);
    member.saveRetry(second); await member.resume();
    expect(f.rows).toHaveLength(2); expect(member.load().session!.needsRekey).toBe(false);
  });
  it('blocks a target removal after a partial admission even after seen eviction', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true });
    const owner = f.store(f.owner); await owner.sync();
    // A target removal must block repair, even when the bounded seen cache is empty.
    const targetRemoval = createGroupControlMessage(f.owner, groupSessionConversation(owner.load().session!), 'group_remove', createGroupRemoveBody([f.late.keyID]));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(targetRemoval)); await member.sync();
    const state = member.load(); state.session!.seen = {}; member.save(state);
    expect(() => member.prepareRetry()).toThrow('no longer the current admission');
    await expect(member.resume()).rejects.toThrow(); expect(member.load().operation).toEqual(original);
    expect(f.rows).toHaveLength(2);
  });
  it('replaces a stale partial rotation using the current roster while preserving the same target admission', async () => {
    const f = fixture(), member = f.store(f.member), extra = generateIdentity();
    member.account.config.contacts!.Extra = base64UrlEncode(extra.publicKey);
    await run(member, 'add', { contact: 'Extra' });
    const original = await completedPending(f, member, { partial: true });
    const owner = f.store(f.owner); await owner.sync();
    const removal = createGroupControlMessage(f.owner, groupSessionConversation(owner.load().session!), 'group_remove', createGroupRemoveBody([extra.keyID]));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(removal)); await member.sync();
    const before = member.load(), repair = member.prepareRetry();
    expect(repair.phase).toBe('addition_rekey'); expect(repair.controls[0]).not.toBe(original.controls[1]);
    member.saveRetry(repair); await member.resume();
    expect(member.load().session!.admissions[toHex(f.late.keyID)].addId).toBe(before.session!.admissions[toHex(f.late.keyID)].addId);
    expect(member.load().session!.admissions[toHex(extra.keyID)]).toBeUndefined();
    expect(groupSessionConversation(member.load().session!).participants.map(toHex)).not.toContain(toHex(extra.keyID));
  });
  it('uses a competing canonical completion for the second review without releasing a predicted welcome', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true, ttl: 1 });
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    const repair = member.prepareRetry(); member.saveRetry(repair);
    // Owner authenticated the ADD before expiry; use the same pending verified roster.
    const source = restoreGroupSession(f.owner, { ...member.load().session!, identityKid: toHex(f.owner.keyID) });
    let winner;
    do { winner = prepareGroupSessionRekey(f.owner, source); } while (toHex(winner.rekey.msg_id) >= toHex(deserializeEnvelope(base64UrlDecode(repair.controls[0])).msg_id));
    const post = f.client.postMessage.bind(f.client);
    const competing = vi.spyOn(f.client, 'postMessage').mockImplementationOnce(async (...args) => {
      await post(f.conversation.id, serializeEnvelope(winner.rekey)); return post(...args);
    });
    await member.resume(); competing.mockRestore();
    expect(member.load().operation!.welcomes).toEqual([]); expect(member.load().session!.root).toBe(toHex(winner.conversation.keys.root));
    const renewal = member.prepareRetry(); expect(renewal.welcomePurpose).toBe('renewal');
    expect(renewal.superseded![0].controls).toEqual(repair.controls);
    member.saveRetry(renewal); await member.resume();
    const late = f.store(f.late, undefined, member.link()); await late.open();
    expect(late.load().session!.root).toBe(toHex(winner.conversation.keys.root)); expect(late.load().session!.recovery).toBeNull();
    expect(f.rows).toHaveLength(4);
  });
  it('does not treat a repair ACK as replay coverage or release a welcome', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member, { partial: true, ttl: 1 });
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.controls[1])).expiry_ts + 1) * 1000);
    const repair = member.prepareRetry(); member.saveRetry(repair);
    const post = f.client.postMessage.bind(f.client);
    const missing = vi.spyOn(f.client, 'postMessage').mockImplementationOnce(async (...args) => {
      const receipt = await post(...args); f.rows.pop(); return receipt;
    });
    await expect(member.resume()).rejects.toThrow('not verified'); missing.mockRestore();
    expect(member.load().session!.recovery).not.toBeNull(); expect(member.load().session!.epoch).toBe(0);
    expect(member.load().receipts).toEqual([]); expect(member.load().operation!.controls).toEqual(repair.controls);
    expect(member.load().operation!.welcomes).toEqual([]);
  });
  it('reviews replacement of a stale explicit refresh renewal with current proof and flat ciphertext evidence', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const original = member.prepare('refresh', { contact: 'Late', challenge: '72'.repeat(32) }); member.saveOperation(original);
    await run(f.store(f.owner), 'rekey'); await member.sync();
    const service = new QntmGroupActions(), scope = { key: 'refresh-renewal-revision', store: member };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('replacement_renewal'); expect(review.review.effect).toContain('same verified completed admission');
    expect(member.load().operation).toEqual(original);
    f.ambiguous(); await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('ambiguous POST');
    const revised = member.load().operation!; expect(revised.origin).toBeUndefined();
    expect(revised.superseded![0].welcomes).toEqual(original.welcomes); expect(revised.expected).not.toEqual(original.expected);
    const retry = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(retry.review.retryMode).toBe('exact_renewal'); expect(member.load().operation).toEqual(revised);
    await service.execute(scope, { operation: 'commit', reviewToken: retry.reviewToken, reviewHash: retry.reviewHash });
    expect(member.load().operation).toBeNull();
  });
  it('preserves the journal when flat recovery evidence reaches either bound', async () => {
    const f = fixture(), member = f.store(f.member); await completedPending(f, member, { competing: true });
    const renewal = member.prepareRetry(); member.saveRetry(renewal);
    const entry = { phase: 'renewal' as const, controls: [], welcomes: renewal.welcomes, sentControls: 0, sentWelcomes: 0, delivery: 'unknown' as const };
    const state = member.load(); state.operation!.superseded = Array.from({ length: 256 }, () => ({ ...entry, welcomes: [] })); member.save(state);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(renewal.welcomes[0])).expiry_ts + 1) * 1000);
    expect(() => member.prepareRetry()).toThrow('evidence reached its limit');
    expect(member.load().operation!.superseded).toHaveLength(256);
    const oversized = member.load(); oversized.operation!.superseded = Array.from({ length: 40 }, () => ({ ...entry, welcomes: ['A'.repeat(128 * 1024)] }));
    expect(() => member.save(oversized)).toThrow('evidence reached its limit');
    expect(member.load().operation!.superseded).toHaveLength(256); expect(f.rows).toHaveLength(2);
  });
  it('reviews the exact completed original welcome after lost control ACKs, seen eviction and restart', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member);
    const restarted = f.store(f.member), service = new QntmGroupActions(), scope = { key: 'completed-exact', store: restarted };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(reviewed.review.effect).toContain('exact saved'); expect(reviewed.review.welcomePurpose).toBeUndefined();
    expect(restarted.load().operation).toEqual(original); expect(f.rows).toHaveLength(2);
    await service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash });
    expect(f.rows).toHaveLength(3); expect(f.rows[2].envelope).toEqual(base64UrlDecode(original.welcomes[0]));
    expect(restarted.load().operation).toBeNull();
  });
  it.each(['expired', 'later rotation', 'competing completion'] as const)('reviews a current renewal for %s without replacing original intent before commit', async reason => {
    const f = fixture(), member = f.store(f.member), challenge = '81'.repeat(32);
    const original = await completedPending(f, member, { challenge, competing: reason === 'competing completion' });
    // Draft compatibility: authenticate the original signed ciphertext to recover its challenge.
    delete original.recoveryChallenge; const saved = member.load(); saved.operation = original; member.save(saved);
    if (reason === 'later rotation') { await run(f.store(f.owner), 'rekey'); await member.sync(); }
    if (reason === 'expired') { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.welcomes[0])).expiry_ts + 1) * 1000); }
    const before = member.load(), count = f.rows.length, service = new QntmGroupActions(), scope = { key: 'completed-renewal', store: f.store(f.member) };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(reviewed.review.welcomePurpose).toBe('renewal'); expect(reviewed.review.effect).toContain('same verified completed admission');
    expect(reviewed.review.recoveryChallenge).toBe(challenge); expect(JSON.stringify(reviewed)).not.toContain(before.session!.root);
    expect(member.load().operation).toEqual(original); expect(f.rows).toHaveLength(count);
    f.ambiguous();
    await expect(service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash })).rejects.toThrow('ambiguous POST');
    const staged = member.load().operation!;
    expect(staged.origin).toMatchObject({ controls: original.controls, welcomes: original.welcomes, sentControls: 0, sentWelcomes: 0, delivery: 'unknown' });
    expect(staged.origin).not.toHaveProperty('expected'); expect(staged.controls).toEqual([]); expect(staged.sentWelcomes).toBe(0);
    expect(staged.welcomes).not.toEqual(original.welcomes);
    const opened = openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('renewal'); expect(opened.conversation.currentEpoch).toBe(before.session!.epoch);
    expect(opened.replayFromSequence).toBe(before.cursor); expect(opened.recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
    const restarted = f.store(f.member); expect(restarted.prepareRetry()).toEqual(staged);
    await restarted.exclusive(() => restarted.resume());
    expect(f.rows.slice(count).map(row => base64UrlEncode(row.envelope))).toEqual([staged.welcomes[0], staged.welcomes[0]]);
    expect(restarted.load().operation).toBeNull();
  });
  it('reviews another expired renewal while preserving every superseded exact ciphertext', async () => {
    const f = fixture(), member = f.store(f.member); await completedPending(f, member, { competing: true });
    const renewal = member.prepareRetry(); member.saveRetry(renewal); f.ambiguous();
    await expect(member.resume()).rejects.toThrow('ambiguous POST');
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(renewal.welcomes[0])).expiry_ts + 1) * 1000);
    const restarted = f.store(f.member), count = f.rows.length;
    const next = restarted.prepareRetry();
    expect(next.welcomes).not.toEqual(renewal.welcomes); expect(next.origin).toEqual(renewal.origin);
    expect(next.superseded).toEqual([{ phase: 'renewal', controls: [], welcomes: renewal.welcomes, sentControls: 0, sentWelcomes: 0, delivery: 'unknown' }]);
    expect(restarted.load().operation).toEqual(renewal); expect(f.rows).toHaveLength(count);
    await restarted.exclusive(async () => { restarted.saveRetry(next); await restarted.resume(); });
    expect(f.rows).toHaveLength(count + 1); expect(restarted.load().operation).toBeNull();
  });
  it.each(['removal', 'readmission', 'recovery', 'journal'] as const)('invalidates reviewed recovery after %s changes', async changed => {
    const f = fixture(), member = f.store(f.member); await completedPending(f, member, { competing: true });
    const original = member.load().operation!, service = new QntmGroupActions(), scope = { key: 'recovery-cas', store: member };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    if (changed === 'removal' || changed === 'readmission') {
      const owner = f.store(f.owner); await run(owner, 'remove', { contact: 'Late' });
      if (changed === 'readmission') await run(owner, 'add', { contact: 'Late' });
    } else {
      const state = member.load();
      if (changed === 'journal') state.operation!.welcomes[0] = member.prepareRetry().welcomes[0];
      else state.session!.recovery = { afterSequence: state.cursor, reason: 'missing_history', challenge: '63'.repeat(32) };
      member.save(state);
    }
    const count = f.rows.length;
    await expect(service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(count); expect(member.load().operation!.id).toBe(original.id);
    if (changed === 'removal' || changed === 'readmission') {
      expect(() => member.prepareRetry()).toThrow('no longer the current admission');
      await expect(member.exclusive(() => member.resume())).rejects.toThrow('no longer safe');
      expect(f.rows).toHaveLength(count);
    }
  });
  it('preserves the original intent and posts nothing when reviewed renewal staging fails', async () => {
    const f = fixture(), member = f.store(f.member); await completedPending(f, member, { competing: true });
    const original = member.load().operation!, service = new QntmGroupActions(), scope = { key: 'staging-failure', store: member };
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    const originalSave = member.save.bind(member), count = f.rows.length;
    const save = vi.spyOn(member, 'save').mockImplementation(state => {
      if (state.operation?.origin) throw new Error('simulated disk full');
      originalSave(state);
    });
    await expect(service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash })).rejects.toThrow('disk full');
    save.mockRestore(); expect(member.load().operation).toEqual(original); expect(f.rows).toHaveLength(count);
  });
  it('clears fully acknowledged welcome journals after removal and changed pins without a POST', async () => {
    const f = fixture(), member = f.store(f.member), original = await completedPending(f, member);
    await f.client.postMessage(f.conversation.id, base64UrlDecode(original.welcomes[0]));
    const state = member.load(); state.operation!.sentControls = 2; state.operation!.sentWelcomes = 1; member.save(state);
    await run(f.store(f.owner), 'remove', { contact: 'Member' });
    member.account.config.contacts!.Late = base64UrlEncode(generateIdentity().publicKey);
    const service = new QntmGroupActions(), scope = { key: 'acknowledged-cleanup', store: member }, count = f.rows.length;
    const reviewed = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(reviewed.review.effect).toContain('already acknowledged');
    await service.execute(scope, { operation: 'commit', reviewToken: reviewed.reviewToken, reviewHash: reviewed.reviewHash });
    expect(member.load().operation).toBeNull(); expect(member.load().session!.removed).toBe(true); expect(f.rows).toHaveLength(count);
  });
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
  it('refuses a newly obsolete standalone rekey even when the receiver would accept it as a competing winner', async () => {
    const f = fixture(), member = f.store(f.member), source = member.load().session!;
    const pending = member.prepare('rekey', {});
    const old = deserializeEnvelope(base64UrlDecode(pending.controls[0]));
    let published;
    do { published = prepareGroupSessionRekey(f.owner, f.store(f.owner).load().session!); } while (toHex(published.rekey.msg_id) <= toHex(old.msg_id));
    member.saveOperation(pending);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(published.rekey)); await member.sync();
    expect(member.load().session!.epoch).toBe(source.epoch + 1);
    expect(receiveGroupEvent(f.member, old, member.load().session!).rewound).toBe(true);
    await expect(member.exclusive(() => member.resume())).rejects.toThrow('obsolete epoch');
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toEqual(pending);
    expect(member.load().session!.root).toBe(toHex(published.conversation.keys.root));
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
