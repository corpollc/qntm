import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, base64UrlEncode, base64UrlDecode, serializeEnvelope, deserializeEnvelope,
  openGroupWelcome, groupSessionFromWelcome, createMessage, groupSessionConversation, prepareGroupWelcomeRefresh,
  receiveGroupEvent, createGroupControlMessage, createGroupRemoveBody, prepareGroupSessionRekey, restoreGroupSession,
  prepareGroupAdmissionRenewal, prepareGroupSessionAddition, openSecret, sealSecret, marshalCanonical, unmarshalCanonical, QSP1Suite,
  createGroupAddBody, keyIDFromPublicKey,
  type Identity, type OuterEnvelope,
} from '@corpollc/qntm';
import { QntmGroupStore, groupDispatchDisposition, removalTarget, type GroupOperation, type GroupTransport } from '../src/group-store.js';
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
function genericPending(store: QntmGroupStore, contact = 'Owner', ttl = 604800, challenge?: string) {
  const state = store.load(), operation = store.prepare('refresh', { contact, challenge });
  const prepared = prepareGroupWelcomeRefresh(store.account.identity!, state.session!, [base64UrlDecode(operation.publicKey!)], ttl,
    challenge ? new Uint8Array(Buffer.from(challenge, 'hex')) : undefined, state.cursor);
  operation.welcomes = prepared.welcomes.map(wire => base64UrlEncode(serializeEnvelope(wire)));
  operation.expected = createGroupSession(store.account.identity!, prepared.conversation, prepared.state,
    { signedEpoch: state.session!.signedEpoch, admissions: state.session!.admissions });
  operation.welcomePurpose = 'refresh'; store.saveOperation(operation); return operation;
}
/** Shared reducer replay bound (client/src/group/session.ts MAX_SEEN); it is not exported. */
const MAX_SEEN = 8192;
/** The relay accepts the numbered POST, but its acknowledgement never returns. */
function loseAckAt(f: ReturnType<typeof fixture>, call: number) {
  const post = f.client.postMessage.bind(f.client); let count = 0;
  f.client.postMessage = async (id, bytes) => {
    const receipt = await post(id, bytes);
    if (++count === call) { f.client.postMessage = post; throw new Error('ambiguous POST'); }
    return receipt;
  };
}
async function acceptedPending(f: ReturnType<typeof fixture>, store: QntmGroupStore, action: 'rekey' | 'remove' | 'send', options: { contact?: string } = {}) {
  const last = action === 'remove' ? 2 : 1;
  loseAckAt(f, last);
  await expect(action === 'send' ? store.send('accepted text') : run(store, action, options)).rejects.toThrow('ambiguous POST');
  const operation = store.load().operation!;
  expect(operation.sentControls).toBe(last - 1);
  await store.exclusive(() => store.sync());
  return operation;
}
/** Fill the bounded cache to its legal limit, then let real authenticated
 * traffic run the production eviction over the oldest markers. */
async function evictWithAuthenticatedTraffic(f: ReturnType<typeof fixture>, store: QntmGroupStore, sender: Identity, messages = 6) {
  const state = store.load(), seen = state.session!.seen;
  let entries = Object.keys(seen).length;
  while (entries < MAX_SEEN) {
    const id = randomBytes(16).toString('hex');
    if (id in seen) continue;
    seen[id] = { digest: randomBytes(32).toString('hex'), epoch: 0 };
    entries++;
  }
  store.save(state);
  const peer = f.store(sender); await peer.exclusive(() => peer.sync());
  for (let index = 0; index < messages; index++) {
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createMessage(sender, groupSessionConversation(peer.load().session!), 'text', new TextEncoder().encode(`cache pressure ${index}`))));
  }
  await store.exclusive(() => store.sync());
}
/** The relay never sees the numbered POST; the caller observes an ambiguous failure. */
function dropPostAt(f: ReturnType<typeof fixture>, call: number) {
  const post = f.client.postMessage.bind(f.client); let count = 0;
  f.client.postMessage = async (id, bytes) => {
    if (++count === call) { f.client.postMessage = post; throw new Error('ambiguous POST'); }
    return post(id, bytes);
  };
}
const wireOf = (encoded: string) => deserializeEnvelope(base64UrlDecode(encoded));
function expireControl(encoded: string) { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((wireOf(encoded).expiry_ts + 1) * 1000); }
/** A real removal whose completing rotation has a short signed lifetime. Only the
 * crash window is chosen here; journal, target pin, controls and receive are production code. */
async function stagedRemoval(f: ReturnType<typeof fixture>, store: QntmGroupStore, contact: string,
  options: { ttl?: number; delivery?: 'unposted' | 'lost_ack' | 'none' } = {}) {
  await store.exclusive(() => store.sync());
  const state = store.load(), identity = store.account.identity!, operation = store.prepare('remove', { contact });
  const remove = wireOf(operation.controls[0]), removed = receiveGroupEvent(identity, remove, state.session!).state;
  const rotation = prepareGroupSessionRekey(identity, removed, options.ttl ?? 1).rekey;
  operation.controls[1] = base64UrlEncode(serializeEnvelope(rotation)); operation.expected = receiveGroupEvent(identity, rotation, removed).state;
  store.saveOperation(operation);
  const delivery = options.delivery ?? 'unposted';
  if (delivery !== 'none') await f.client.postMessage(f.conversation.id, base64UrlDecode(operation.controls[0]));
  if (delivery === 'lost_ack') await f.client.postMessage(f.conversation.id, base64UrlDecode(operation.controls[1]));
  await store.exclusive(() => store.sync());
  const saved = store.load().operation!;
  if (delivery !== 'none') { expect(store.controlAccepted(store.load(), saved.controls[0])).toBe(true); expect(store.load().session!.needsRekey).toBe(delivery !== 'lost_ack'); }
  return saved;
}
async function helperJoined(f: ReturnType<typeof fixture>, owner: QntmGroupStore) {
  await run(owner, 'add', { contact: 'Late' });
  const late = f.store(f.late, undefined, owner.link()); await late.exclusive(() => late.open()); return late;
}
const members = (store: QntmGroupStore) => groupSessionConversation(store.load().session!).participants.map(toHex);
/** An unposted production removal journal with short signed lifetimes (crash before any POST). */
async function unpostedRemoval(f: ReturnType<typeof fixture>, store: QntmGroupStore, contact: string, ttl = 1) {
  await store.exclusive(() => store.sync());
  const state = store.load(), identity = store.account.identity!, operation = store.prepare('remove', { contact });
  const kid = keyIDFromPublicKey(base64UrlDecode(operation.publicKey!));
  const removal = createGroupControlMessage(identity, groupSessionConversation(state.session!), 'group_remove', createGroupRemoveBody([kid]), ttl);
  const removed = receiveGroupEvent(identity, removal, state.session!).state, rotation = prepareGroupSessionRekey(identity, removed, ttl).rekey;
  operation.controls = [removal, rotation].map(value => base64UrlEncode(serializeEnvelope(value)));
  operation.expected = receiveGroupEvent(identity, rotation, removed).state;
  store.saveOperation(operation); return store.load().operation!;
}
async function releaseThroughTool(store: QntmGroupStore, key: string) {
  const service = new QntmGroupActions(), scope = { key, store };
  const review = await service.execute(scope, { operation: 'prepare', action: 'release_unproven' }) as any;
  const result = await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }) as any;
  return { review, result };
}
describe('OpenClaw explicit release of stale unproven removals', () => {
  it.each(['pinned', 'legacy'] as const)('releases an expired unposted removal into the archive without posting and restores sending (%s journal)', async journal => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner);
    let original = await unpostedRemoval(f, owner, 'Member');
    if (journal === 'legacy') { const state = owner.load(); delete state.operation!.target; owner.save(state); original = owner.load().operation!; }
    expireControl(original.controls[0]);
    const count = f.rows.length;
    expect(() => owner.prepareRetry()).toThrow('expired before its acceptance was verified');
    const beforePlan = owner.load();
    const planned = owner.prepareRelease();
    expect(planned.reason).toBe('expired');
    expect(owner.load().operation).toEqual(beforePlan.operation);
    expect(owner.load().releasedOperations).toEqual([]);
    const { review, result } = await releaseThroughTool(owner, 'release-expired');
    expect(review.review.action).toBe('release_unproven'); expect(review.review.releaseReason).toBe('expired');
    expect(review.review.effect).toContain('No message will be posted'); expect(review.review.effect).not.toMatch(/cancel/i);
    expect(review.review.target).toEqual(journal === 'pinned' ? { keyId: toHex(f.member.keyID), publicKey: base64UrlEncode(f.member.publicKey), admissionSourceEpoch: null, stillMember: true } : null);
    expect(review.review.evidence).toMatchObject({ controls: 2, sentControls: 0, welcomes: 0, originControls: 0, retainedRevisions: 0, archivedOperations: 0, archivedAfterRelease: 1 });
    expect(review.review.currentStatus).toMatchObject({ status: 'ready', needsRekey: false, removed: false, members: 3 });
    expect(result.status).toBe('released'); expect(result.reason).toBe('expired'); expect(result.releasedOperations).toBe(1); expect(result.pendingOperation).toBeNull();
    expect(f.rows).toHaveLength(count);
    const after = owner.load();
    expect(after.operation).toBeNull(); expect(after.controlReceipts).toEqual([]);
    expect(after.releasedOperations).toEqual([{ action: 'remove', controls: original.controls, welcomes: [], sentControls: 0, sentWelcomes: 0,
      ...(journal === 'pinned' ? { target: original.target } : {}), delivery: 'unknown', releasedReason: 'expired', releasedAt: after.releasedOperations[0].releasedAt }]);
    expect(JSON.stringify(after.releasedOperations)).not.toContain('"expected"');
    expect(members(owner)).toContain(toHex(f.member.keyID)); expect(after.session!.needsRekey).toBe(false);
    // Nothing was excluded: the target still reads and replies on the same keys.
    await owner.send('after release');
    const member = f.store(f.member); await member.exclusive(() => member.sync()); expect(member.load().outbox.at(-1)!.text).toBe('after release');
    await member.send('member still present'); await owner.exclusive(() => owner.sync()); expect(owner.load().outbox.at(-1)!.text).toBe('member still present');
    // A later explicit removal is a fresh current-epoch decision with its own pin.
    await run(owner, 'remove', { contact: 'Member' });
    await member.exclusive(() => member.sync()); expect(member.load().session!.removed).toBe(true);
    expect(owner.load().releasedOperations).toEqual(after.releasedOperations);
    await late.exclusive(() => late.sync()); expect(late.load().session!.root).toBe(owner.load().session!.root);
  });
  it('refuses to release a verified removal and leaves plain retry in charge', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await stagedRemoval(f, owner, 'Member');
    expireControl(original.controls[1]);
    const count = f.rows.length;
    expect(() => owner.prepareRelease()).toThrow('verified in current history; use retry');
    await expect(releaseThroughTool(owner, 'release-verified')).rejects.toThrow('verified in current history');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toEqual(original); expect(owner.load().releasedOperations).toEqual([]);
    owner.saveRetry(owner.prepareRetry()); await owner.exclusive(() => owner.resume()); expect(owner.load().operation).toBeNull();
  });
  it('refuses to release a removal whose exact bytes still apply, whatever journal shape carries them', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await unpostedRemoval(f, owner, 'Member', 3600);
    const count = f.rows.length;
    expect(() => owner.prepareRelease()).toThrow('still exact-retryable; use retry');
    // The same still-applying unproven bytes carried as a repair origin are refused too, with no acceptance claim.
    const state = owner.load();
    state.operation = { ...original, phase: 'removal_rekey', controls: [original.controls[1]], target: undefined,
      origin: { kind: 'remove', controls: original.controls, welcomes: [], sentControls: 0, sentWelcomes: 0, target: original.target, delivery: 'unknown' } };
    owner.save(state);
    expect(() => owner.prepareRelease()).toThrow('still exact-retryable; use retry');
    expect(f.rows).toHaveLength(count); expect(owner.load().releasedOperations).toEqual([]);
    const restored = owner.load(); restored.operation = original; owner.save(restored);
    owner.saveRetry(owner.prepareRetry()); await owner.exclusive(() => owner.resume());
    expect(f.rows.slice(count).map(row => base64UrlEncode(row.envelope))).toEqual(original.controls); expect(owner.load().operation).toBeNull();
  });
  it.each(['add', 'rekey', 'refresh', 'send'] as const)('refuses to release a pending %s journal', async action => {
    const f = fixture(), owner = f.store(f.owner);
    dropPostAt(f, 1);
    await expect(action === 'send' ? owner.send('pending text') : run(owner, action, action === 'add' ? { contact: 'Late' } : action === 'refresh' ? { contact: 'Member' } : {})).rejects.toThrow('ambiguous POST');
    const pending = owner.load().operation!, count = f.rows.length;
    expect(() => owner.prepareRelease()).toThrow('not an unproven removal; use retry');
    await expect(releaseThroughTool(owner, `release-${action}`)).rejects.toThrow('not an unproven removal');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toEqual(pending);
  });
  it('refuses without a pending journal or behind an incomplete-history barrier', async () => {
    const f = fixture(), owner = f.store(f.owner);
    expect(() => owner.prepareRelease()).toThrow('No saved group operation to release');
    const original = await unpostedRemoval(f, owner, 'Member'); expireControl(original.controls[0]);
    const state = owner.load(); state.session!.recovery = { afterSequence: Math.max(1, state.cursor), reason: 'missing_history', challenge: '47'.repeat(32) }; owner.save(state);
    expect(() => owner.prepareRelease()).toThrow('incomplete');
    await expect(releaseThroughTool(owner, 'release-recovery')).rejects.toThrow();
    expect(owner.load().operation).toEqual(original); expect(owner.load().releasedOperations).toEqual([]);
  });
  it.each(['superseded', 'wrong_branch'] as const)('releases a %s removal without excluding anyone', async stale => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await unpostedRemoval(f, owner, 'Member', 3600);
    await late.exclusive(() => late.sync());
    if (stale === 'superseded') { await run(late, 'rekey'); await owner.exclusive(() => owner.sync()); }
    else {
      // A lower-ID competing child of the previous epoch installs a different root at
      // the removal's epoch. Native receive() also pauses for missing descendant
      // history on that rewind, so the production reducer is applied here the way
      // Python's receive_batch does (no extra recovery barrier) and nothing is
      // posted. Decrypt of the original same-epoch removal then fails.
      const current = owner.load(), session = current.session!, frame = session.rekeys.at(-1)!;
      expect(frame).toBeTruthy();
      const branch = { ...session, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot,
        rekeys: [] as typeof session.rekeys, seen: {}, admissions: structuredClone(frame.admissions), needsRekey: true, recovery: null };
      let competitor; do { competitor = prepareGroupSessionRekey(f.owner, branch); } while (toHex(competitor.rekey.msg_id) >= frame.messageId);
      const applied = receiveGroupEvent(f.owner, competitor.rekey, session).state;
      expect(applied.epoch).toBe(session.epoch); expect(applied.root).not.toBe(session.root); expect(applied.recovery).toBeNull();
      current.session = applied; owner.save(current);
    }
    const count = f.rows.length, before = owner.load();
    const { review, result } = await releaseThroughTool(owner, `release-${stale}`);
    expect(review.review.releaseReason).toBe(stale);
    expect(result.status).toBe('released'); expect(f.rows).toHaveLength(count);
    expect(owner.load().operation).toBeNull(); expect(owner.load().releasedOperations).toHaveLength(1);
    expect(members(owner)).toContain(toHex(f.member.keyID)); expect(owner.load().session!.epoch).toBe(before.session!.epoch);
  });
  it.each(['pinned', 'legacy'] as const)('releases after a same-epoch readmission changed the target and never re-removes it (%s journal)', async journal => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner);
    let original = await unpostedRemoval(f, owner, 'Member', 3600);
    if (journal === 'legacy') { const state = owner.load(); delete state.operation!.target; owner.save(state); original = owner.load().operation!; }
    await late.exclusive(() => late.sync()); const lateState = late.load().session!;
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_remove', createGroupRemoveBody([f.member.keyID]))));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_add', createGroupAddBody(f.late, [f.member.publicKey]))));
    await owner.exclusive(() => owner.sync()); expect(members(owner)).toContain(toHex(f.member.keyID));
    const count = f.rows.length;
    expect(() => owner.prepareRetry()).toThrow(journal === 'legacy' ? 'later admission' : 'original admission');
    const { review, result } = await releaseThroughTool(owner, `release-readmitted-${journal}`);
    expect(review.review.releaseReason).toBe(journal === 'legacy' ? 'legacy_same_epoch_admission' : 'incarnation_changed');
    expect(result.status).toBe('released'); expect(f.rows).toHaveLength(count);
    expect(owner.load().operation).toBeNull(); expect(members(owner)).toContain(toHex(f.member.keyID)); expect(owner.load().session!.needsRekey).toBe(true);
    expect(owner.load().releasedOperations[0]).toMatchObject({ controls: original.controls, releasedReason: journal === 'legacy' ? 'legacy_same_epoch_admission' : 'incarnation_changed' });
  });
  it('releases when the target is already absent without claiming anything', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await unpostedRemoval(f, owner, 'Member', 3600);
    await late.exclusive(() => late.sync()); const lateState = late.load().session!;
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_remove', createGroupRemoveBody([f.member.keyID]))));
    await owner.exclusive(() => owner.sync()); expect(members(owner)).not.toContain(toHex(f.member.keyID)); expect(owner.load().session!.needsRekey).toBe(true);
    expect(owner.controlAccepted(owner.load(), original.controls[0])).toBe(false);
    const count = f.rows.length, { review, result } = await releaseThroughTool(owner, 'release-absent');
    expect(review.review.releaseReason).toBe('target_absent'); expect(review.review.target.stillMember).toBe(false);
    expect(result.status).toBe('released'); expect(f.rows).toHaveLength(count);
    expect(owner.controlAccepted(owner.load(), original.controls[0])).toBe(false); expect(owner.load().session!.needsRekey).toBe(true);
    expect(owner.load().releasedOperations[0].controls).toEqual(original.controls);
  });
  it('releases a removal repair whose unproven origin no longer applies on the current branch', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    await late.exclusive(() => late.sync()); const lateState = late.load().session!, removeId = toHex(wireOf(original.controls[0]).msg_id);
    expireControl(original.controls[1]);
    const repair = owner.prepareRetry(); owner.saveRetry(repair); loseAckAt(f, 1);
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('ambiguous POST');
    let competitor; do { competitor = prepareGroupSessionRekey(f.late, lateState); } while (toHex(competitor.rekey.msg_id) >= toHex(wireOf(repair.controls[0]).msg_id));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(competitor.rekey));
    await owner.exclusive(() => owner.sync()); const rewound = owner.load();
    const accepted = receiveGroupEvent(f.late, competitor.rekey, lateState).state;
    const refreshed = prepareGroupWelcomeRefresh(f.late, accepted, [f.owner.publicKey], undefined, new Uint8Array(Buffer.from(rewound.session!.recovery!.challenge, 'hex')), f.rows.at(-1)!.seq);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await owner.exclusive(() => owner.open(late.link()));
    expect(owner.controlAccepted(owner.load(), original.controls[0])).toBe(false); expect(() => owner.prepareRetry()).toThrow('no longer verified in current history');
    const count = f.rows.length, { review, result } = await releaseThroughTool(owner, 'release-repair');
    expect(review.review.releaseReason).toBe('superseded'); expect(review.review.savedOperation.recovery).toBe('removal_rekey');
    expect(review.review.evidence).toMatchObject({ controls: 1, originControls: 2 });
    expect(result.status).toBe('released'); expect(f.rows).toHaveLength(count);
    expect(owner.load().operation).toBeNull(); expect(owner.load().controlReceipts).toEqual([]);
    expect(owner.load().releasedOperations[0]).toMatchObject({ phase: 'removal_rekey', controls: repair.controls, origin: repair.origin, releasedReason: 'superseded' });
    expect(owner.load().releasedOperations[0].origin!.controls[0]).toBe(original.controls[0]); void removeId;
  });
  it.each(['removed', 'needsRekey'] as const)('keeps received barriers after release (%s)', async barrier => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), member = f.store(f.member);
    await member.exclusive(() => member.sync());
    const original = await unpostedRemoval(f, member, 'Late', 3600);
    if (barrier === 'removed') {
      // The creator cannot be removed. A current non-creator who holds the journal
      // is fully excluded (remove + completing rotation) and may still release.
      await run(owner, 'remove', { contact: 'Member' });
      await member.exclusive(() => member.sync());
    } else {
      expireControl(original.controls[0]);
      await late.exclusive(() => late.sync());
      await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(late.load().session!),
        'group_add', createGroupAddBody(f.late, [generateIdentity().publicKey]))));
      await member.exclusive(() => member.sync());
    }
    expect(member.load().session!.removed).toBe(barrier === 'removed');
    expect(member.load().session!.needsRekey).toBe(barrier === 'needsRekey');
    const count = f.rows.length, { result } = await releaseThroughTool(member, `release-${barrier}`);
    expect(result.status).toBe('released'); expect(result.removed).toBe(barrier === 'removed'); expect(result.needsRekey).toBe(barrier === 'needsRekey');
    expect(f.rows).toHaveLength(count); expect(member.load().operation).toBeNull();
    expect(member.load().session!.removed).toBe(barrier === 'removed'); expect(member.load().session!.needsRekey).toBe(barrier === 'needsRekey');
    expect(member.binding.groupActions).toContain('remove');
    await expect(member.send('still blocked')).rejects.toThrow();
    await expect(member.exclusive(async () => { member.prepare('remove', { contact: 'Late' }); })).rejects.toThrow();
    expect(f.rows).toHaveLength(count); expect(member.load().releasedOperations[0].controls).toEqual(original.controls);
  });
  it('requires a new review when the journal, proof or archive changes between prepare and commit', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await unpostedRemoval(f, owner, 'Member');
    expireControl(original.controls[0]);
    const service = new QntmGroupActions(), scope = { key: 'release-race', store: owner };
    const review = await service.execute(scope, { operation: 'prepare', action: 'release_unproven' }) as any;
    const state = owner.load(); state.operation!.sentControls = 1; owner.save(state);
    const count = f.rows.length;
    await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).not.toBeNull(); expect(owner.load().releasedOperations).toEqual([]);
    // Direct release also rejects a journal that no longer matches the reviewed one.
    expect(() => owner.release(original, 'expired')).toThrow('changed before release');
    expect(() => owner.release(owner.load().operation!, 'superseded')).toThrow('reason changed');
    expect(owner.load().operation).not.toBeNull();
  });
  it.each(['revisions', 'bytes', 'malformed'] as const)('refuses unchanged when the archive cannot retain the evidence (%s)', async bound => {
    const f = fixture(), owner = f.store(f.owner), original = await unpostedRemoval(f, owner, 'Member');
    expireControl(original.controls[0]);
    const disk = JSON.parse(readFileSync(owner.filename, 'utf8'));
    const row = { action: 'remove', controls: [], welcomes: [], sentControls: 0, sentWelcomes: 0, delivery: 'unknown', releasedReason: 'expired', releasedAt: 1 };
    if (bound === 'revisions') disk.releasedOperations = Array.from({ length: 256 }, () => row);
    else if (bound === 'bytes') disk.releasedOperations = Array.from({ length: 40 }, () => ({ ...row, controls: ['A'.repeat(128 * 1024)] }));
    else disk.releasedOperations = [{ ...row, expected: {} }];
    writeFileSync(owner.filename, JSON.stringify(disk));
    const count = f.rows.length;
    if (bound === 'malformed') { expect(() => owner.load()).toThrow(); await expect(releaseThroughTool(owner, 'release-malformed')).rejects.toThrow(); }
    else if (bound === 'bytes') { expect(() => owner.load()).toThrow('archive reached its limit'); }
    else {
      expect(() => owner.prepareRelease()).toThrow('archive reached its limit');
      await expect(releaseThroughTool(owner, 'release-full')).rejects.toThrow('archive reached its limit');
      expect(owner.load().operation).toEqual(original); expect(owner.load().releasedOperations).toHaveLength(256);
    }
    expect(f.rows).toHaveLength(count); expect(JSON.parse(readFileSync(owner.filename, 'utf8')).operation).toEqual(original);
  });
  it('preserves the archive across receive, restart and a challenged welcome replacement', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await unpostedRemoval(f, owner, 'Member');
    expireControl(original.controls[0]);
    const { result } = await releaseThroughTool(owner, 'release-persist'); expect(result.status).toBe('released');
    const archive = owner.load().releasedOperations;
    await late.send('later traffic'); await owner.exclusive(() => owner.sync());
    const restarted = f.store(f.owner); expect(restarted.load().releasedOperations).toEqual(archive);
    await late.send('missed retained row'); f.rows.splice(f.rows.length - 1, 1);
    await restarted.exclusive(() => restarted.sync()); const paused = restarted.load(); expect(paused.session!.recovery).not.toBeNull();
    expect(paused.releasedOperations).toEqual(archive);
    // A current member posts a fresh challenged welcome; open installs it from
    // that new row so the earlier gap is behind the welcome's replay cursor.
    await run(late, 'refresh', { contact: 'Owner', challenge: paused.session!.recovery!.challenge });
    await restarted.exclusive(() => restarted.open(late.link()));
    expect(restarted.load().session!.recovery).toBeNull(); expect(restarted.load().releasedOperations).toEqual(archive);
    expect(restarted.status().releasedOperations).toBe(1);
  });
  it('handles a late authenticated arrival of released expired ciphertext through ordinary receive', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await unpostedRemoval(f, owner, 'Member');
    expireControl(original.controls[0]);
    await releaseThroughTool(owner, 'release-late');
    await f.client.postMessage(f.conversation.id, base64UrlDecode(original.controls[0]));
    await owner.exclusive(() => owner.sync());
    expect(owner.load().session!.recovery?.reason).toBe('expired_control'); expect(owner.load().releasedOperations).toHaveLength(1);
    expect(members(owner)).toContain(toHex(f.member.keyID));
  });
  it('permits release exactly by the original remove action and never by an unknown or missing action', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await unpostedRemoval(f, owner, 'Member');
    expireControl(original.controls[0]);
    const service = new QntmGroupActions(), permitted = owner.binding.groupActions!;
    owner.binding.groupActions = permitted.filter(action => action !== 'remove');
    await expect(service.execute({ key: 'release-denied', store: owner }, { operation: 'prepare', action: 'release_unproven' })).rejects.toThrow('not permitted');
    owner.binding.groupActions = permitted;
    const review = await service.execute({ key: 'release-revoked', store: owner }, { operation: 'prepare', action: 'release_unproven' }) as any;
    owner.binding.groupActions = permitted.filter(action => action !== 'remove');
    await expect(service.execute({ key: 'release-revoked', store: owner }, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('no longer locally permitted');
    await expect(service.execute({ key: 'release-unknown', store: owner }, { operation: 'prepare', action: 'release' })).rejects.toThrow();
    expect(owner.load().operation).toEqual(original); expect(owner.load().releasedOperations).toEqual([]);
  });
});
describe('OpenClaw removal and rotation recovery', () => {
  it.each(['sole survivor', 'helper present'] as const)('finishes an accepted removal whose rotation expired with a reviewed rotation for the current roster (%s)', async roster => {
    const f = fixture(), owner = f.store(f.owner), late = roster === 'helper present' ? await helperJoined(f, owner) : undefined;
    const original = await stagedRemoval(f, owner, 'Member');
    expect(original.target).toMatchObject({ keyId: toHex(f.member.keyID), publicKey: base64UrlEncode(f.member.publicKey), admission: null });
    expect(original.target!.record).toBe(base64UrlEncode(marshalCanonical(f.roster.snapshot().founding_members.find(row => toHex(row.key_id) === toHex(f.member.keyID))!)));
    const source = wireOf(original.controls[0]).conv_epoch;
    expect(members(owner)).not.toContain(toHex(f.member.keyID));
    expireControl(original.controls[1]);
    const count = f.rows.length, service = new QntmGroupActions(), scope = { key: `removal-${roster}`, store: f.store(f.owner) };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.recoveryPhase).toBe('removal_rekey'); expect(review.review.retryMode).toBe('replacement_rotation');
    expect(review.review.effect).toContain('never reposted'); expect(review.review.savedOperation.recovery).toBe('removal_rekey');
    expect(scope.store.load().operation).toEqual(original); expect(f.rows).toHaveLength(count);
    const result = await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }) as any;
    expect(result.status).toBe('submitted'); expect(f.rows).toHaveLength(count + 1);
    const posted = deserializeEnvelope(f.rows.at(-1)!.envelope);
    expect(posted.conv_epoch).toBe(source); expect(base64UrlEncode(f.rows.at(-1)!.envelope)).not.toBe(original.controls[1]);
    expect(f.rows.map(row => base64UrlEncode(row.envelope))).not.toContain(original.controls[1]);
    const after = scope.store.load();
    expect(after.operation).toBeNull(); expect(after.controlReceipts).toEqual([]); expect(after.session!.epoch).toBe(source + 1);
    expect(after.session!.needsRekey).toBe(false); expect(members(scope.store)).not.toContain(toHex(f.member.keyID));
    expect(members(scope.store)).toHaveLength(roster === 'sole survivor' ? 1 : 2);
    const member = f.store(f.member); await member.exclusive(() => member.sync()); expect(member.load().session!.removed).toBe(true);
    if (late) {
      await late.exclusive(() => late.sync());
      expect(late.load().session!.epoch).toBe(source + 1); expect(late.load().session!.root).toBe(after.session!.root);
      await late.send('helper after completed removal'); await scope.store.exclusive(() => scope.store.sync());
      expect(scope.store.load().outbox.at(-1)!.text).toBe('helper after completed removal');
    }
  });
  it('retains the original removal receipt across the repair journal and finishes after a lost ACK and restart', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await stagedRemoval(f, owner, 'Member');
    const removeId = toHex(wireOf(original.controls[0]).msg_id), source = wireOf(original.controls[0]).conv_epoch;
    expireControl(original.controls[1]);
    const repair = owner.prepareRetry(); expect(repair.phase).toBe('removal_rekey'); expect(repair.controls).toHaveLength(1);
    expect(repair.origin).toEqual({ kind: 'remove', controls: original.controls, welcomes: [], sentControls: original.sentControls, sentWelcomes: 0, target: original.target, delivery: 'unknown' });
    expect(repair.target).toBeUndefined();
    owner.saveRetry(repair);
    expect(owner.load().controlReceipts).toEqual([expect.objectContaining({ messageId: removeId, epoch: source, valid: true })]);
    loseAckAt(f, 1);
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('ambiguous POST');
    const uncertain = owner.load();
    // The relay accepted the rotation but the acknowledgement was lost, so the counter still reads unsent.
    expect(uncertain.operation).toMatchObject({ phase: 'removal_rekey', sentControls: 0, controls: repair.controls });
    expect(uncertain.controlReceipts.find(entry => entry.messageId === removeId)).toMatchObject({ valid: true });
    const count = f.rows.length, restarted = f.store(f.owner), service = new QntmGroupActions(), scope = { key: 'removal-restart', store: restarted };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('accepted_cleanup');
    const rotationId = toHex(wireOf(repair.controls[0]).msg_id);
    expect(restarted.load().controlReceipts.map(entry => entry.messageId).sort()).toEqual([removeId, rotationId].sort());
    await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash });
    expect(f.rows).toHaveLength(count); expect(restarted.load().operation).toBeNull(); expect(restarted.load().session!.epoch).toBe(source + 1);
    expect(f.rows.map(row => base64UrlEncode(row.envelope)).filter(row => row === repair.controls[0])).toHaveLength(1);
  });
  it.each(['before review', 'between review and commit'] as const)('lets a helper rotation finish the accepted removal without posting (%s)', async when => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    const source = wireOf(original.controls[0]).conv_epoch; await late.exclusive(() => late.sync());
    expireControl(original.controls[1]);
    const service = new QntmGroupActions(), scope = { key: `helper-${when}`, store: owner };
    let review = await (when === 'before review' ? (async () => { await run(late, 'rekey'); return service.execute(scope, { operation: 'prepare', action: 'retry' }); })()
      : service.execute(scope, { operation: 'prepare', action: 'retry' })) as any;
    if (when === 'between review and commit') {
      expect(review.review.retryMode).toBe('replacement_rotation');
      await run(late, 'rekey');
      const count = f.rows.length;
      await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('configuration changed');
      expect(f.rows).toHaveLength(count); expect(owner.load().operation).toEqual(original);
      review = await service.execute(scope, { operation: 'prepare', action: 'retry' });
    }
    expect(review.review.retryMode).toBe('accepted_cleanup');
    const count = f.rows.length;
    await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash });
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toBeNull();
    expect(owner.load().session!.epoch).toBe(source + 1); expect(owner.load().session!.root).toBe(late.load().session!.root);
    expect(members(owner)).not.toContain(toHex(f.member.keyID));
  });
  it('never re-removes a target readmitted after the accepted removal completed', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner);
    await stagedRemoval(f, owner, 'Member'); await late.exclusive(() => late.sync());
    await run(late, 'rekey'); await run(late, 'add', { contact: 'Member' });
    const member = f.store(f.member, undefined, late.link()); await member.exclusive(() => member.open());
    const count = f.rows.length;
    expect(owner.prepareRetry()).toEqual(owner.load().operation); expect(owner.fulfilled(owner.load(), owner.load().operation!)).toBe(false);
    await owner.exclusive(() => owner.sync()); expect(owner.fulfilled(owner.load(), owner.load().operation!)).toBe(true);
    await owner.exclusive(() => owner.resume());
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toBeNull(); expect(members(owner)).toContain(toHex(f.member.keyID));
    await member.send('readmitted and still present'); await owner.exclusive(() => owner.sync());
    expect(owner.load().outbox.at(-1)!.text).toBe('readmitted and still present');
  });
  it('completes the current roster after a same-epoch readmission without re-removing it', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    await late.exclusive(() => late.sync());
    const source = wireOf(original.controls[0]).conv_epoch, lateState = late.load().session!;
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_add', createGroupAddBody(f.late, [f.member.publicKey]))));
    await owner.exclusive(() => owner.sync());
    expect(members(owner)).toContain(toHex(f.member.keyID)); expect(owner.load().session!.needsRekey).toBe(true);
    expireControl(original.controls[1]);
    const repair = owner.prepareRetry(); expect(repair.phase).toBe('removal_rekey');
    owner.saveRetry(repair); const count = f.rows.length; await owner.exclusive(() => owner.resume());
    expect(f.rows).toHaveLength(count + 1);
    const posted = deserializeEnvelope(f.rows.at(-1)!.envelope);
    expect(posted.conv_epoch).toBe(source); expect(owner.load().operation).toBeNull(); expect(members(owner)).toContain(toHex(f.member.keyID));
    expect(owner.load().session!.admissions[toHex(f.member.keyID)].completion!.rekeyId).toBe(toHex(posted.msg_id));
  });
  it.each(['pinned', 'legacy'] as const)('never publishes an exact unaccepted removal against a same-epoch readmission (%s journal)', async journal => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner);
    let original = await stagedRemoval(f, owner, 'Member', { delivery: 'none' });
    if (journal === 'legacy') { const state = owner.load(); delete state.operation!.target; owner.save(state); original = owner.load().operation!; }
    await late.exclusive(() => late.sync()); const lateState = late.load().session!;
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_remove', createGroupRemoveBody([f.member.keyID]))));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_add', createGroupAddBody(f.late, [f.member.publicKey]))));
    await owner.exclusive(() => owner.sync()); expect(members(owner)).toContain(toHex(f.member.keyID));
    const count = f.rows.length;
    expect(() => owner.prepareRetry()).toThrow(journal === 'legacy' ? 'later admission' : 'original admission');
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow(journal === 'legacy' ? 'later admission' : 'original admission');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toEqual(original);
  });
  it('drops the original removal proof with a losing repair branch and keeps the journal after the challenged welcome', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    await late.exclusive(() => late.sync()); const lateState = late.load().session!, removeId = toHex(wireOf(original.controls[0]).msg_id);
    expireControl(original.controls[1]);
    const repair = owner.prepareRetry(); owner.saveRetry(repair); loseAckAt(f, 1);
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('ambiguous POST');
    const repairId = toHex(wireOf(repair.controls[0]).msg_id);
    let competitor; do { competitor = prepareGroupSessionRekey(f.late, lateState); } while (toHex(competitor.rekey.msg_id) >= repairId);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(competitor.rekey));
    await owner.exclusive(() => owner.sync());
    const rewound = owner.load();
    expect(rewound.session!.recovery).not.toBeNull();
    expect(rewound.controlReceipts.find(entry => entry.messageId === repairId)).toMatchObject({ valid: false });
    // The removal was applied at the source epoch before the rotation: it stays inside the winning frame.
    expect(rewound.controlReceipts.find(entry => entry.messageId === removeId)).toMatchObject({ valid: true });
    let count = f.rows.length;
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('recovery is required'); expect(f.rows).toHaveLength(count);
    const accepted = receiveGroupEvent(f.late, competitor.rekey, lateState).state;
    const refreshed = prepareGroupWelcomeRefresh(f.late, accepted, [f.owner.publicKey], undefined, new Uint8Array(Buffer.from(rewound.session!.recovery!.challenge, 'hex')), f.rows.at(-1)!.seq);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await owner.exclusive(() => owner.open(late.link()));
    const replaced = owner.load();
    expect(replaced.session!.recovery).toBeNull(); expect(replaced.session!.root).toBe(accepted.root); expect(members(owner)).not.toContain(toHex(f.member.keyID));
    expect(replaced.controlReceipts.every(entry => !entry.valid)).toBe(true); expect(owner.controlAccepted(replaced, original.controls[0])).toBe(false);
    count = f.rows.length;
    // Conservative by design: the welcome attests the helper's branch, not our earlier control, so nothing is inferred.
    expect(() => owner.prepareRetry()).toThrow('no longer verified in current history');
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('no longer verified in current history');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toMatchObject({ phase: 'removal_rekey', controls: repair.controls, origin: repair.origin });
  });
  it.each(['recovery', 'sender removed', 'journal changed', 'roster changed', 'removal proof invalidated'] as const)('rechecks authority and proof after review and before release (%s)', async barrier => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    await late.exclusive(() => late.sync()); const lateState = late.load().session!;
    expireControl(original.controls[1]);
    const service = new QntmGroupActions(), scope = { key: `race-${barrier}`, store: owner };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('replacement_rotation');
    const mutate = async () => {
      const state = owner.load();
      if (barrier === 'recovery') state.session!.recovery = { afterSequence: Math.max(1, state.cursor), reason: 'missing_history', challenge: '44'.repeat(32) };
      else if (barrier === 'sender removed') state.session!.removed = true;
      else if (barrier === 'journal changed') state.operation!.sentControls = 1;
      else if (barrier === 'removal proof invalidated') state.controlReceipts = state.controlReceipts.map(entry => ({ ...entry, valid: false }));
      if (barrier !== 'roster changed') { owner.save(state); return; }
      await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_add', createGroupAddBody(f.late, [generateIdentity().publicKey]))));
    };
    await mutate();
    let count = f.rows.length;
    await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation!.phase).toBeUndefined();
    // Even a saved repair rechecks the same state barriers immediately before its POST.
    if (barrier === 'journal changed') return;
    const fresh = fixture(), owner2 = fresh.store(fresh.owner), late2 = await helperJoined(fresh, owner2), original2 = await stagedRemoval(fresh, owner2, 'Member');
    await late2.exclusive(() => late2.sync()); const lateState2 = late2.load().session!;
    expireControl(original2.controls[1]);
    const repair = owner2.prepareRetry(); owner2.saveRetry(repair);
    const state = owner2.load();
    if (barrier === 'recovery') state.session!.recovery = { afterSequence: Math.max(1, state.cursor), reason: 'missing_history', challenge: '45'.repeat(32) };
    else if (barrier === 'sender removed') state.session!.removed = true;
    else if (barrier === 'removal proof invalidated') state.controlReceipts = state.controlReceipts.map(entry => ({ ...entry, valid: false }));
    if (barrier !== 'roster changed') owner2.save(state);
    else await fresh.client.postMessage(fresh.conversation.id, serializeEnvelope(createGroupControlMessage(fresh.late, groupSessionConversation(lateState2), 'group_add', createGroupAddBody(fresh.late, [generateIdentity().publicKey]))));
    count = fresh.rows.length;
    await expect(owner2.exclusive(() => owner2.resume())).rejects.toThrow();
    expect(fresh.rows).toHaveLength(count); expect(owner2.load().operation?.phase ?? owner2.load().operation?.action).toBeDefined();
    expect(owner2.load().session!.epoch).toBe(wireOf(original2.controls[0]).conv_epoch);
  });
  it('keeps flat bounded evidence across repeated expired repairs and refuses beyond the limits', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await stagedRemoval(f, owner, 'Member');
    expireControl(original.controls[1]);
    const first = owner.prepareRetry(); owner.saveRetry(first); dropPostAt(f, 1);
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow('ambiguous POST');
    expect(owner.load().operation).toMatchObject({ phase: 'removal_rekey', sentControls: 0 }); expect(owner.load().operation!.superseded).toBeUndefined();
    expireControl(first.controls[0]);
    const second = owner.prepareRetry();
    expect(second.controls).not.toEqual(first.controls); expect(second.origin).toEqual(first.origin);
    expect(second.superseded).toEqual([{ phase: 'removal_rekey', controls: first.controls, welcomes: [], sentControls: 0, sentWelcomes: 0, delivery: 'unknown' }]);
    const bounded = owner.load(); bounded.operation!.superseded = Array.from({ length: 256 }, () => ({ phase: 'removal_rekey' as const, controls: [], welcomes: [], sentControls: 0, sentWelcomes: 0, delivery: 'unknown' as const }));
    owner.save(bounded);
    const count = f.rows.length;
    expect(() => owner.prepareRetry()).toThrow('evidence reached its limit'); expect(f.rows).toHaveLength(count);
    const unbounded = owner.load(); unbounded.operation!.superseded = undefined; owner.save(unbounded);
    owner.saveRetry(owner.prepareRetry()); await owner.exclusive(() => owner.resume());
    expect(f.rows).toHaveLength(count + 1); expect(owner.load().operation).toBeNull();
  });
  it('proves the original removal after real replay-cache eviction and binds its receipt to the repair journal', async () => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member');
    await late.exclusive(() => late.sync()); const lateState = late.load().session!, removeId = toHex(wireOf(original.controls[0]).msg_id);
    const state = owner.load(), seen = state.session!.seen;
    let entries = Object.keys(seen).length;
    while (entries < MAX_SEEN) {
      const id = randomBytes(16).toString('hex');
      if (id in seen) continue;
      seen[id] = { digest: randomBytes(32).toString('hex'), epoch: 0 };
      entries++;
    }
    owner.save(state);
    // Real eviction: authenticated same-epoch controls from the helper fill the bounded cache.
    for (let index = 0; index < 8; index++) {
      await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.late, groupSessionConversation(lateState), 'group_add', createGroupAddBody(f.late, [generateIdentity().publicKey]))));
    }
    await owner.exclusive(() => owner.sync());
    expect(owner.load().session!.seen[removeId]).toBeUndefined(); expect(owner.controlAccepted(owner.load(), original.controls[0])).toBe(true);
    expireControl(original.controls[1]);
    const repair = owner.prepareRetry(); owner.saveRetry(repair);
    expect(owner.load().controlReceipts).toEqual([expect.objectContaining({ messageId: removeId, valid: true })]);
    const disk = JSON.parse(readFileSync(owner.filename, 'utf8')), tampered = { ...disk, controlReceipts: [{ ...disk.controlReceipts[0], digest: '00'.repeat(32) }] };
    writeFileSync(owner.filename, JSON.stringify(tampered)); expect(() => owner.load()).toThrow('do not match the pending operation');
    writeFileSync(owner.filename, JSON.stringify(disk));
    const count = f.rows.length; await owner.exclusive(() => owner.resume());
    expect(f.rows).toHaveLength(count + 1); expect(owner.load().operation).toBeNull(); expect(members(owner)).not.toContain(toHex(f.member.keyID)); expect(members(owner)).toHaveLength(10);
  });
  it.each(['expired', 'superseded'] as const)('preserves an unaccepted removal with a precise reason when it is %s', async stale => {
    const f = fixture(), owner = f.store(f.owner), late = await helperJoined(f, owner), original = await stagedRemoval(f, owner, 'Member', { delivery: 'none' });
    if (stale === 'expired') expireControl(original.controls[0]);
    else { await late.exclusive(() => late.sync()); await run(late, 'rekey'); await owner.exclusive(() => owner.sync()); }
    const count = f.rows.length;
    expect(() => owner.prepareRetry()).toThrow(`${stale} before its acceptance was verified`);
    await expect(owner.exclusive(() => owner.resume())).rejects.toThrow();
    expect(() => owner.prepare('rekey', {})).toThrow('pending operation');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation).toEqual(original); expect(members(owner)).toContain(toHex(f.member.keyID));
  });
  it.each(['expired', 'roster changed', 'exact', 'superseded', 'lost ack'] as const)('keeps a standalone rotation exact, renews it, or finishes it (%s)', async stale => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    if (stale === 'lost ack') loseAckAt(f, 1); else dropPostAt(f, 1);
    await expect(run(member, 'rekey')).rejects.toThrow('ambiguous POST');
    const original = member.load().operation!, source = wireOf(original.controls[0]).conv_epoch;
    if (stale === 'expired') expireControl(original.controls[0]);
    else if (stale === 'roster changed') {
      // A bare same-epoch addition changes the roster the saved rotation wrapped keys for, without rotating.
      await owner.exclusive(() => owner.sync());
      await f.client.postMessage(f.conversation.id, serializeEnvelope(createGroupControlMessage(f.owner, groupSessionConversation(owner.load().session!), 'group_add', createGroupAddBody(f.owner, [f.late.publicKey]))));
    } else if (stale === 'superseded') await run(owner, 'rekey');
    const service = new QntmGroupActions(), scope = { key: `rotation-${stale}`, store: f.store(f.member) }, count = f.rows.length;
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    const expected = stale === 'exact' ? 'exact' : stale === 'expired' || stale === 'roster changed' ? 'replacement_rotation' : 'accepted_cleanup';
    expect(review.review.retryMode).toBe(expected); expect(scope.store.load().operation).toEqual(original);
    await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash });
    const posted = f.rows.slice(count).map(row => base64UrlEncode(row.envelope)), after = scope.store.load();
    expect(after.operation).toBeNull(); expect(after.session!.needsRekey).toBe(false);
    if (expected === 'accepted_cleanup') expect(posted).toEqual([]);
    else if (expected === 'exact') expect(posted).toEqual([original.controls[0]]);
    else {
      expect(posted).toHaveLength(1); expect(posted[0]).not.toBe(original.controls[0]); expect(wireOf(posted[0]).conv_epoch).toBe(source);
      expect(review.review.effect).toContain('stale saved rotation');
    }
    expect(after.session!.epoch).toBe(source + 1);
    await owner.exclusive(() => owner.sync()); expect(owner.load().session!.root).toBe(after.session!.root);
    if (stale === 'roster changed') expect(members(scope.store)).toHaveLength(3);
    await scope.store.send('rotation settled'); await owner.exclusive(() => owner.sync()); expect(owner.load().outbox.at(-1)!.text).toBe('rotation settled');
  });
  it.each(['sender removed', 'recovery', 'evidence limit'] as const)('never lets a stale rotation bypass current authority or evidence bounds (%s)', async barrier => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    dropPostAt(f, 1); await expect(run(member, 'rekey')).rejects.toThrow('ambiguous POST');
    const original = member.load().operation!; expireControl(original.controls[0]);
    if (barrier === 'sender removed') { await run(owner, 'remove', { contact: 'Member' }); await member.exclusive(() => member.sync()); }
    else {
      const state = member.load();
      if (barrier === 'recovery') state.session!.recovery = { afterSequence: Math.max(1, state.cursor), reason: 'missing_history', challenge: '46'.repeat(32) };
      else state.operation!.superseded = Array.from({ length: 256 }, () => ({ phase: 'rekey' as const, controls: [], welcomes: [], sentControls: 0, sentWelcomes: 0, delivery: 'unknown' as const }));
      member.save(state);
    }
    const count = f.rows.length;
    expect(() => member.prepareRetry()).toThrow(barrier === 'sender removed' ? 'removed' : barrier === 'recovery' ? 'incomplete' : 'limit');
    await expect(member.exclusive(() => member.resume())).rejects.toThrow();
    expect(f.rows).toHaveLength(count); expect(member.load().operation!.controls).toEqual(original.controls);
  });
  it('denies retry when the original action is no longer permitted and voids a review whose journal was mutated', async () => {
    const f = fixture(), owner = f.store(f.owner), original = await stagedRemoval(f, owner, 'Member');
    expireControl(original.controls[1]);
    const service = new QntmGroupActions(), permitted = owner.binding.groupActions!;
    owner.binding.groupActions = permitted.filter(action => action !== 'remove');
    await expect(service.execute({ key: 'denied', store: owner }, { operation: 'prepare', action: 'retry' })).rejects.toThrow('no longer locally permitted');
    owner.binding.groupActions = permitted;
    const review = await service.execute({ key: 'mutated', store: owner }, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('replacement_rotation');
    const state = owner.load(); state.operation!.origin = undefined; state.operation!.contact = 'Late'; owner.save(state);
    const count = f.rows.length;
    await expect(service.execute({ key: 'mutated', store: owner }, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(count); expect(owner.load().operation!.phase).toBeUndefined();
  });
});
describe('OpenClaw pending-control acceptance receipts', () => {
  it.each(['rekey', 'remove'] as const)('finishes an accepted %s after real replay-cache eviction and restart without a POST', async action => {
    const f = fixture(), member = f.store(f.member);
    if (action === 'remove') await run(member, 'add', { contact: 'Late' });
    const operation = await acceptedPending(f, member, action, action === 'remove' ? { contact: 'Late' } : {});
    const last = operation.controls.at(-1)!, outer = deserializeEnvelope(base64UrlDecode(last)), id = toHex(outer.msg_id);
    const latched = member.load();
    expect(latched.session!.seen[id]).toBeDefined(); expect(latched.controlReceipts).toHaveLength(operation.controls.length);
    await evictWithAuthenticatedTraffic(f, member, f.owner);
    const evicted = member.load();
    expect(evicted.session!.seen[id]).toBeUndefined();
    const receipt = evicted.controlReceipts.find(entry => entry.messageId === id)!;
    expect(receipt).toMatchObject({ digest: toHex(new QSP1Suite().hash(base64UrlDecode(last))), epoch: outer.conv_epoch, valid: true });
    expect(receipt.sequence).toBeGreaterThan(0); expect(receipt.sequence).toBeLessThanOrEqual(evicted.cursor);
    expect(member.controlAccepted(evicted, last)).toBe(true);
    const count = f.rows.length, restarted = f.store(f.member), service = new QntmGroupActions(), scope = { key: `accepted-${action}`, store: restarted };
    expect(restarted.status().pendingOperation).toMatchObject({ action, acceptedControls: operation.controls.length });
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('accepted_cleanup'); expect(review.review.acceptedControls).toBe(operation.controls.length);
    expect(review.review.effect).toContain('No messages will be posted'); expect(restarted.load().operation).toEqual(operation);
    const result = await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }) as any;
    expect(result.status).toBe('submitted');
    expect(f.rows).toHaveLength(count); expect(restarted.load().operation).toBeNull(); expect(restarted.load().controlReceipts).toEqual([]);
    expect(restarted.load().session!.epoch).toBe(restoreGroupSession(f.member, operation.expected).epoch);
    if (action === 'remove') expect(groupSessionConversation(restarted.load().session!).participants.map(toHex)).not.toContain(toHex(f.late.keyID));
  });
  it.each([false, true])('finishes an accepted rotation after a later canonical rotation without reposting (evicted=%s)', async evicted => {
    const f = fixture(), member = f.store(f.member), operation = await acceptedPending(f, member, 'rekey');
    if (evicted) await evictWithAuthenticatedTraffic(f, member, f.owner);
    await run(f.store(f.owner), 'rekey'); await member.exclusive(() => member.sync());
    expect(member.load().session!.epoch).toBe(2); expect(member.load().controlReceipts[0].valid).toBe(true);
    const count = f.rows.length, restarted = f.store(f.member);
    expect(restarted.prepareRetry()).toEqual(operation);
    await restarted.exclusive(() => restarted.resume());
    expect(f.rows).toHaveLength(count); expect(restarted.load().operation).toBeNull(); expect(restarted.load().controlReceipts).toEqual([]);
    expect(restarted.load().session!.epoch).toBe(2);
  });
  it('keeps cache-only evidence exact for a remove journal after a later rotation, while a rotation intent is fulfilled by it', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const operation = await acceptedPending(f, member, 'remove', { contact: 'Late' });
    const legacy = JSON.parse(readFileSync(member.filename, 'utf8')); delete legacy.controlReceipts; writeFileSync(member.filename, JSON.stringify(legacy));
    await run(f.store(f.owner), 'rekey');
    const count = f.rows.length, restarted = f.store(f.member);
    expect(restarted.load().controlReceipts).toEqual([]);
    // The removal itself is only cache-proven; its completed effect is finished locally without re-removal.
    expect(restarted.fulfilled(restarted.load(), operation)).toBe(true);
    await restarted.exclusive(() => restarted.resume());
    expect(f.rows).toHaveLength(count); expect(restarted.load().operation).toBeNull();
    expect(groupSessionConversation(restarted.load().session!).participants.map(toHex)).not.toContain(toHex(f.late.keyID));
  });
  it('finishes an accepted text through the monitor cleanup path after replay-cache eviction', async () => {
    const f = fixture(), member = f.store(f.member), operation = await acceptedPending(f, member, 'send');
    await evictWithAuthenticatedTraffic(f, member, f.owner);
    expect(member.load().session!.seen[toHex(deserializeEnvelope(base64UrlDecode(operation.controls[0])).msg_id)]).toBeUndefined();
    const count = f.rows.length, restarted = f.store(f.member);
    expect(restarted.finishAcceptedSend()).toBe(true);
    expect(restarted.load().operation).toBeNull(); expect(restarted.load().controlReceipts).toEqual([]); expect(f.rows).toHaveLength(count);
  });
  it('invalidates the losing source rekey that a rewind leaves in the replay cache, and keeps it invalid after the challenged welcome', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner), source = owner.load().session!;
    const operation = await acceptedPending(f, member, 'rekey');
    const wire = operation.controls[0], id = toHex(deserializeEnvelope(base64UrlDecode(wire)).msg_id);
    let winner; do { winner = prepareGroupSessionRekey(f.owner, source); } while (toHex(winner.rekey.msg_id) >= id);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(winner.rekey));
    await member.exclusive(() => member.sync());
    const rewound = member.load();
    expect(rewound.session!.recovery).not.toBeNull();
    expect(rewound.session!.seen[id]?.digest).toBe(toHex(new QSP1Suite().hash(base64UrlDecode(wire))));
    expect(rewound.controlReceipts[0]).toMatchObject({ messageId: id, valid: false });
    expect(member.controlAccepted(rewound, wire)).toBe(false);
    let count = f.rows.length;
    await expect(member.exclusive(() => member.resume())).rejects.toThrow('recovery is required');
    expect(f.rows).toHaveLength(count); expect(member.load().operation).toEqual(operation);
    const accepted = receiveGroupEvent(f.owner, winner.rekey, source).state;
    const refreshed = prepareGroupWelcomeRefresh(f.owner, accepted, [f.member.publicKey], undefined,
      new Uint8Array(Buffer.from(rewound.session!.recovery!.challenge, 'hex')), f.rows.at(-1)!.seq);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await member.exclusive(() => member.open(owner.link()));
    const replaced = member.load();
    expect(replaced.session!.recovery).toBeNull(); expect(replaced.session!.root).toBe(accepted.root);
    expect(replaced.controlReceipts[0]).toMatchObject({ messageId: id, valid: false });
    expect(member.controlAccepted(replaced, wire)).toBe(false);
    count = f.rows.length;
    // The verified competitor left the source epoch: the rotation intent is fulfilled without reposting the losing bytes.
    expect(member.prepareRetry()).toEqual(operation); expect(member.fulfilled(replaced, operation)).toBe(true);
    await member.exclusive(() => member.resume());
    expect(f.rows).toHaveLength(count); expect(member.load().operation).toBeNull(); expect(member.load().controlReceipts).toEqual([]);
    expect(f.rows.map(row => base64UrlEncode(row.envelope)).filter(row => row === wire)).toHaveLength(1);
  });
  it('invalidates a receipt accepted on a losing descendant branch', async () => {
    const f = fixture(), member = f.store(f.member), source = f.store(f.owner).load().session!;
    await run(member, 'rekey');
    const first = member.load().session!.rekeys[0].messageId;
    const operation = await acceptedPending(f, member, 'rekey');
    const wire = operation.controls[0], id = toHex(deserializeEnvelope(base64UrlDecode(wire)).msg_id);
    expect(member.load().controlReceipts[0]).toMatchObject({ messageId: id, epoch: 1, valid: true });
    let winner; do { winner = prepareGroupSessionRekey(f.owner, source); } while (toHex(winner.rekey.msg_id) >= first);
    await f.client.postMessage(f.conversation.id, serializeEnvelope(winner.rekey));
    await member.exclusive(() => member.sync());
    const rewound = member.load();
    expect(rewound.session!.recovery).not.toBeNull(); expect(rewound.session!.seen[id]).toBeUndefined();
    expect(rewound.controlReceipts[0]).toMatchObject({ messageId: id, epoch: 1, valid: false });
    expect(rewound.controlReceipts[0].sequence).toBeGreaterThan(0);
    expect(member.controlAccepted(rewound, wire)).toBe(false);
    const count = f.rows.length;
    await expect(member.exclusive(() => member.resume())).rejects.toThrow();
    expect(f.rows).toHaveLength(count); expect(member.load().operation).toEqual(operation);
  });
  it('drops earlier control proof when a challenged welcome replaces the checkpoint, even on the same branch', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    const operation = await acceptedPending(f, member, 'rekey');
    await owner.send('missed retained row'); f.rows.splice(f.rows.length - 1, 1);
    await member.exclusive(() => member.sync());
    const paused = member.load();
    expect(paused.session!.recovery).not.toBeNull(); expect(paused.controlReceipts[0].valid).toBe(true);
    await run(owner, 'refresh', { contact: 'Member', challenge: paused.session!.recovery!.challenge });
    await member.exclusive(() => member.open(owner.link()));
    const replaced = member.load();
    expect(replaced.session!.recovery).toBeNull(); expect(replaced.session!.epoch).toBe(1);
    expect(replaced.controlReceipts[0]).toMatchObject({ valid: false }); expect(member.controlAccepted(replaced, operation.controls[0])).toBe(false);
    const count = f.rows.length;
    await member.exclusive(() => member.resume());
    expect(f.rows).toHaveLength(count); expect(member.load().operation).toBeNull();
  });
  it.each(['digest', 'epoch', 'zero sequence', 'future sequence', 'unbound', 'duplicate', 'extra field', 'no operation', 'excess'] as const)('refuses a %s receipt before any action', async tamper => {
    const f = fixture(), member = f.store(f.member); await acceptedPending(f, member, 'rekey');
    const disk = JSON.parse(readFileSync(member.filename, 'utf8')), receipt = disk.controlReceipts[0];
    if (tamper === 'digest') receipt.digest = '00'.repeat(32);
    else if (tamper === 'epoch') receipt.epoch += 1;
    else if (tamper === 'zero sequence') receipt.sequence = 0;
    else if (tamper === 'future sequence') receipt.sequence = disk.cursor + 1;
    else if (tamper === 'unbound') receipt.messageId = '11'.repeat(16);
    else if (tamper === 'duplicate') disk.controlReceipts.push({ ...receipt });
    else if (tamper === 'extra field') receipt.note = 'x';
    else if (tamper === 'no operation') disk.operation = null;
    else disk.controlReceipts = [receipt, { ...receipt, messageId: '22'.repeat(16) }, { ...receipt, messageId: '33'.repeat(16) }];
    writeFileSync(member.filename, JSON.stringify(disk));
    const count = f.rows.length;
    expect(() => member.load()).toThrow();
    await expect(member.exclusive(() => member.resume())).rejects.toThrow();
    expect(f.rows).toHaveLength(count);
  });
  it('requires a new review when acceptance proof changes between prepare and commit', async () => {
    const f = fixture(), member = f.store(f.member), post = f.client.postMessage.bind(f.client);
    f.client.postMessage = async () => { throw new Error('ambiguous POST'); };
    await expect(run(member, 'rekey')).rejects.toThrow('ambiguous POST'); f.client.postMessage = post;
    const operation = member.load().operation!, service = new QntmGroupActions(), scope = { key: 'proof-cas', store: member };
    const exact = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(exact.review.retryMode).toBe('exact'); expect(exact.review.acceptedControls).toBe(0);
    // Late relay acceptance of the identical ciphertext lands before commit.
    await post(f.conversation.id, base64UrlDecode(operation.controls[0]));
    await expect(service.execute(scope, { operation: 'commit', reviewToken: exact.reviewToken, reviewHash: exact.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toEqual(operation);
    expect(member.load().controlReceipts[0]).toMatchObject({ valid: true, sequence: 1 });
    const cleanup = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(cleanup.review.retryMode).toBe('accepted_cleanup'); expect(cleanup.review.acceptedControls).toBe(1);
    // An explicit invalidation after review must also void it, even though the duplicate marker remains.
    const disk = JSON.parse(readFileSync(member.filename, 'utf8')); disk.controlReceipts[0].valid = false; writeFileSync(member.filename, JSON.stringify(disk));
    await expect(service.execute(scope, { operation: 'commit', reviewToken: cleanup.reviewToken, reviewHash: cleanup.reviewHash })).rejects.toThrow('configuration changed');
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toEqual(operation);
    // The explicit invalidation still overrides the duplicate marker; the intent is now
    // fulfilled only because a verified rotation left the source epoch, with no POST.
    expect(member.controlAccepted(member.load(), operation.controls[0])).toBe(false);
    const again = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(again.review.retryMode).toBe('accepted_cleanup'); expect(again.review.acceptedControls).toBe(0);
    await service.execute(scope, { operation: 'commit', reviewToken: again.reviewToken, reviewHash: again.reviewHash });
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toBeNull();
  });
});
describe('OpenClaw durable ordinary groups', () => {
  it.each(['expiry', 'rotation'] as const)('reviews generic founder refresh replacement after %s with its authenticated original challenge', async reason => {
    const f = fixture(), member = f.store(f.member), challenge = '84'.repeat(32);
    const original = genericPending(member, 'Owner', 1, challenge);
    delete original.welcomePurpose; delete original.recoveryChallenge;
    const saved = member.load(); saved.operation = original; member.save(saved); // Earlier native journal.
    if (reason === 'expiry') { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.welcomes[0])).expiry_ts + 1) * 1000); }
    else { await run(f.store(f.owner), 'rekey'); await member.sync(); }
    const count = f.rows.length, current = member.load(), service = new QntmGroupActions(), scope = { key: 'generic-replacement', store: f.store(f.member) };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('replacement_refresh'); expect(review.review.welcomePurpose).toBe('refresh');
    expect(review.review.recoveryChallenge).toBe(challenge); expect(review.review.effect).toContain('cannot undo saved removal');
    expect(member.load().operation).toEqual(original); expect(f.rows).toHaveLength(count);
    f.ambiguous(); await expect(service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).rejects.toThrow('ambiguous POST');
    const revised = member.load().operation!;
    expect(revised.superseded![0]).toMatchObject({ phase: 'refresh', welcomes: original.welcomes, delivery: 'unknown' });
    expect(revised.superseded![0]).not.toHaveProperty('expected'); expect(revised.origin).toBeUndefined();
    const opened = openGroupWelcome(f.owner, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('refresh'); expect(opened.replayFromSequence).toBe(current.cursor);
    expect(toHex(opened.conversation.keys.root)).toBe(current.session!.root);
    const restarted = f.store(f.member), retry = restarted.prepareRetry();
    expect(retry.welcomes).toEqual(revised.welcomes); await restarted.exclusive(() => restarted.resume());
    expect(f.rows.slice(count).map(row => base64UrlEncode(row.envelope))).toEqual([revised.welcomes[0], revised.welcomes[0]]);
  });
  it('keeps a valid uncertain generic refresh byte-for-byte exact across restart and shows its signed challenge', async () => {
    const f = fixture(), member = f.store(f.member), challenge = '81'.repeat(32), original = genericPending(member, 'Owner', 604800, challenge);
    delete original.welcomePurpose; delete original.recoveryChallenge; const state = member.load(); state.operation = original; member.save(state);
    f.ambiguous(); await expect(member.resume()).rejects.toThrow('ambiguous POST');
    const service = new QntmGroupActions(), scope = { key: 'generic-exact', store: f.store(f.member) };
    const review = await service.execute(scope, { operation: 'prepare', action: 'retry' }) as any;
    expect(review.review.retryMode).toBe('exact_refresh'); expect(review.review.recoveryChallenge).toBe(challenge);
    expect(scope.store.load().operation).toEqual(original);
    await service.execute(scope, { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash });
    expect(f.rows.map(row => base64UrlEncode(row.envelope))).toEqual([original.welcomes[0], original.welcomes[0]]);
  });
  it.each(['challenge', 'header', 'signature', 'purpose', 'recipient', 'checkpoint'] as const)('rejects an old generic refresh with mismatched %s before creating replacement evidence', async changed => {
    const f = fixture(), member = f.store(f.member), original = genericPending(member, 'Owner', 1, '77'.repeat(32));
    const state = member.load(), operation = state.operation!;
    if (changed === 'challenge') operation.recoveryChallenge = '78'.repeat(32);
    else if (changed === 'checkpoint') (operation.expected as any).root = '41'.repeat(32);
    else {
      const outer = deserializeEnvelope(base64UrlDecode(operation.welcomes[0]));
      if (changed === 'header') outer.msg_id = generateIdentity().keyID;
      else {
        const signed = unmarshalCanonical<any>(openSecret(f.member.privateKey, f.owner.publicKey, outer.ciphertext));
        if (changed === 'purpose') signed.payload.proto = 'qntm/group-renewal/v1';
        if (changed === 'recipient') signed.payload.recipient_ik_pk = f.late.publicKey;
        signed.signature = changed === 'signature' ? new Uint8Array(64) : new QSP1Suite().sign(f.member.privateKey, marshalCanonical(signed.payload));
        outer.ciphertext = sealSecret(f.member.privateKey, f.owner.publicKey, marshalCanonical(signed));
      }
      operation.welcomes = [base64UrlEncode(serializeEnvelope(outer))];
    }
    member.save(state);
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.welcomes[0])).expiry_ts + 1) * 1000);
    expect(() => member.prepareRetry()).toThrow(); expect(member.load().operation).toEqual(operation); expect(f.rows).toHaveLength(0);
  });
  it.each(['extra', 'missing', 'altered', 'rekeyed', 'absent'] as const)('compares a validly signed old generic refresh admissions map (%s) against its saved checkpoint', async changed => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const original = genericPending(member, 'Owner', 1, '77'.repeat(32));
    const state = member.load(), operation = state.operation!, kid = toHex(f.late.keyID);
    const outer = deserializeEnvelope(base64UrlDecode(operation.welcomes[0]));
    const signed = unmarshalCanonical<any>(openSecret(f.member.privateKey, f.owner.publicKey, outer.ciphertext));
    expect(Object.keys(signed.payload.admissions)).toEqual([kid]);
    const admissions = signed.payload.admissions as Record<string, any>;
    if (changed === 'extra') admissions[toHex(f.owner.keyID)] = { ...admissions[kid] };
    else if (changed === 'missing') delete admissions[kid];
    else if (changed === 'altered') admissions[kid].source_epoch += 1;
    else if (changed === 'rekeyed') admissions[kid].rekey_hash = new Uint8Array(32).fill(0x12);
    else delete signed.payload.admissions; // Older generic journal without provenance stays compatible.
    // Re-sign so only the admissions comparison, not the signature, can reject it.
    signed.signature = new QSP1Suite().sign(f.member.privateKey, marshalCanonical(signed.payload));
    outer.ciphertext = sealSecret(f.member.privateKey, f.owner.publicKey, marshalCanonical(signed));
    operation.welcomes = [base64UrlEncode(serializeEnvelope(outer))]; member.save(state);
    const count = f.rows.length;
    vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime((deserializeEnvelope(base64UrlDecode(original.welcomes[0])).expiry_ts + 1) * 1000);
    if (changed === 'absent') {
      const retry = member.prepareRetry();
      expect(retry.welcomePurpose).toBe('refresh'); expect(retry.recoveryChallenge).toBe('77'.repeat(32));
      expect(retry.superseded![0].welcomes).toEqual(operation.welcomes);
    } else expect(() => member.prepareRetry()).toThrow('Saved generic refresh admissions differ from its original checkpoint');
    expect(member.load().operation).toEqual(operation); expect(f.rows).toHaveLength(count);
  });
  it.each(['recipient', 'sender', 'recovery'] as const)('blocks generic refresh reconciliation after %s is unavailable', async changed => {
    const f = fixture(), member = f.store(f.owner), original = genericPending(member, 'Member');
    if (changed === 'recipient') {
      const removal = createGroupControlMessage(f.owner, f.conversation, 'group_remove', createGroupRemoveBody([f.member.keyID]));
      await f.client.postMessage(f.conversation.id, serializeEnvelope(removal)); await member.sync();
    } else {
      const state = member.load();
      if (changed === 'sender') state.session!.removed = true;
      else state.session!.recovery = { afterSequence: 1, reason: 'missing_history', challenge: '11'.repeat(32) };
      member.save(state);
    }
    const count = f.rows.length; expect(() => member.prepareRetry()).toThrow();
    await expect(member.exclusive(() => member.resume())).rejects.toThrow();
    expect(member.load().operation).toEqual(original); expect(f.rows).toHaveLength(count);
  });
  it('keeps generic purpose after admission provenance becomes known and still cannot undo recipient removal', async () => {
    const f = fixture(), member = f.store(f.member), owner = f.store(f.owner);
    await run(member, 'add', { contact: 'Late' }); const late = f.store(f.late, undefined, member.link()); await late.open();
    const unknown = member.load(); unknown.session!.admissions = {}; member.save(unknown);
    const original = genericPending(member, 'Late');
    await run(owner, 'remove', { contact: 'Late' }); await late.sync();
    expect(late.load().session!.removed).toBe(true);
    await run(owner, 'add', { contact: 'Late' }); await member.sync();
    expect(member.load().session!.admissions[toHex(f.late.keyID)].completion).not.toBeNull();
    const generic = member.prepareRetry(); expect(generic.welcomePurpose).toBe('refresh');
    expect(generic.superseded![0].welcomes).toEqual(original.welcomes);
    member.saveRetry(generic); await member.resume();
    const opened = openGroupWelcome(f.late, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('refresh');
    expect(() => groupSessionFromWelcome(f.late, opened, f.rows.at(-1)!.seq, late.load().session!)).toThrow('removal');
  });
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
  it('delivers a fresh generic founder refresh whose signed box carries existing admission provenance', async () => {
    const f = fixture(), member = f.store(f.member);
    await run(member, 'add', { contact: 'Late' });
    const before = member.load(), count = f.rows.length;
    expect(Object.keys(before.session!.admissions)).toEqual([toHex(f.late.keyID)]);
    const prepared = member.prepare('refresh', { contact: 'Owner' });
    expect(prepared.welcomePurpose).toBe('refresh');
    expect(restoreGroupSession(f.member, prepared.expected).admissions).toEqual(before.session!.admissions);
    await run(member, 'refresh', { contact: 'Owner' });
    expect(member.load().operation).toBeNull(); expect(f.rows).toHaveLength(count + 1);
    const opened = openGroupWelcome(f.owner, f.rows.at(-1)!.envelope, { inviterPublicKey: f.member.publicKey, conversationId: f.conversation.id });
    expect(opened.purpose).toBe('refresh'); expect(opened.admissions).toEqual(before.session!.admissions);
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
    // The receiver would accept the old bytes as a competing winner, but a verified
    // rotation already fulfilled this intent: finish locally, never publish them.
    expect(member.prepareRetry()).toEqual(pending);
    await member.exclusive(() => member.resume());
    expect(f.rows).toHaveLength(1); expect(member.load().operation).toBeNull();
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
