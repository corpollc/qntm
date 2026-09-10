import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, base64UrlEncode, serializeEnvelope,
  openGroupWelcome, groupSessionFromWelcome, createMessage, groupSessionConversation, prepareGroupWelcomeRefresh,
  receiveGroupEvent, createGroupControlMessage, createGroupRemoveBody, prepareGroupSessionRekey,
  type Identity, type OuterEnvelope,
} from '@corpollc/qntm';
import { QntmGroupStore, groupDispatchDisposition, type GroupTransport } from '../src/group-store.js';
import { QntmGroupActions } from '../src/group-tool.js';
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
    expect(groupDispatchDisposition(member.load(), queued.messageId)).toBe('defer');
    const accepted = receiveGroupEvent(f.owner, low.rekey, source).state;
    const refreshed = prepareGroupWelcomeRefresh(f.owner, accepted, [f.member.publicKey], undefined,
      new Uint8Array(Buffer.from(member.load().session!.recovery!.challenge, 'hex')));
    await f.client.postMessage(f.conversation.id, serializeEnvelope(refreshed.welcomes[0]));
    await member.exclusive(() => member.open(owner.link()));
    expect(member.load().session!.recovery).toBeNull();
    expect(groupDispatchDisposition(member.load(), queued.messageId)).toBe('discard');
    expect(member.load().outbox).toEqual([]);
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
