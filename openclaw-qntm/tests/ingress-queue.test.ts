import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, expect, test } from 'vitest';
import { base64UrlEncode, generateIdentity } from '@corpollc/qntm';
import { QntmIngressQueue, type IngressPayload } from '../src/ingress-queue.js';
import { inboundId } from '../src/checkpoint.js';
import { toHex } from '../src/qntm.js';

const directories: string[] = [];
const queues = new Set<QntmIngressQueue>();
afterEach(() => {
  for (const queue of queues) queue.close(); queues.clear();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});
function fixture(maxPending = 1024) {
  const stateDir = mkdtempSync(join(tmpdir(), 'qntm-ingress-')); directories.push(stateDir);
  let now = 1000;
  const open = () => { const queue = new QntmIngressQueue('test', { stateDir, now: () => now, maxPending }); queues.add(queue); return queue; };
  const close = (queue: QntmIngressQueue) => { queue.close(); queues.delete(queue); };
  return { stateDir, open, close, tick: (time: number) => { now = time; } };
}
function message(id: number, conversation = 1): IngressPayload {
  const identity = generateIdentity();
  return { version: 1, body: {
    conversationId: conversation.toString(16).padStart(32, '0'), messageId: id.toString(16).padStart(32, '0'),
    senderKid: toHex(identity.keyID), senderPublicKey: base64UrlEncode(identity.publicKey),
    epoch: 0, createdAt: 1000, bodyType: 'text', text: 'private payload', gatewayVerified: false,
  } };
}
const enqueue = (queue: QntmIngressQueue, payload: IngressPayload) => queue.enqueue(inboundId(payload.body), payload);

test('ordinary same-ID deliveries retain separate generation and digest identities through restart', async () => {
  const f = fixture(); let queue = f.open();
  const stale = message(1); stale.body.groupDispatch = { generation: '11'.repeat(16), digest: 'aa'.repeat(32) };
  const fresh = structuredClone(stale); fresh.body.text = 'canonical payload';
  fresh.body.groupDispatch = { generation: '22'.repeat(16), digest: 'bb'.repeat(32) };
  expect(fresh.body.messageId).toBe(stale.body.messageId);
  expect(inboundId(fresh.body)).not.toBe(inboundId(stale.body));
  expect((await enqueue(queue, stale)).kind).toBe('accepted');
  expect((await enqueue(queue, fresh)).kind).toBe('accepted');
  f.close(queue); queue = f.open();
  const oldClaim = (await queue.claimNext())!;
  expect(oldClaim.payload.body.text).toBe(stale.body.text); await queue.complete(oldClaim);
  const freshClaim = (await queue.claimNext())!;
  expect(freshClaim.payload.body.text).toBe('canonical payload'); expect(freshClaim.id).toBe(inboundId(fresh.body));
  await queue.complete(freshClaim);
  expect((await enqueue(queue, fresh)).kind).toBe('completed');
  const legacy = message(2);
  expect(inboundId(legacy.body)).toBe(`${legacy.body.conversationId}:${legacy.body.messageId}`);
});

test('restart recovers pending work and a dead claim; stale owners cannot settle the new claim', async () => {
  const f = fixture(); let queue = f.open();
  const first = message(1), second = message(2);
  await enqueue(queue, first); await enqueue(queue, second);
  const old = (await queue.claimNext({ ownerId: 'dead-owner' }))!;
  f.close(queue); queue = f.open(); f.tick(2000);
  expect(await queue.listPending()).toHaveLength(1);
  expect(await queue.recoverStaleClaims({ staleMs: 0, shouldRecover: claim => claim.claim.ownerId === 'dead-owner' })).toBe(1);
  const current = (await queue.claimNext({ ownerId: 'live-owner' }))!;
  expect(current.id).toBe(old.id);
  expect(current.claim.token).not.toBe(old.claim.token);
  expect(await queue.complete(old)).toBe(false);
  expect(await queue.release(old)).toBe(false);
  expect(await queue.fail(old, { reason: 'stale' })).toBe(false);
  expect(await queue.delete(old)).toBe(false);
  expect(await queue.complete(current)).toBe(true);
  f.close(queue); queue = f.open();
  expect((await enqueue(queue, first)).kind).toBe('completed');
  expect((await queue.claimNext())?.id).toBe(inboundId(second.body));
});

test('keeps lane order, blocks live claims across queue instances, and preserves a refreshed claim', async () => {
  const f = fixture(); const queue = f.open(), other = f.open();
  const first = message(9), second = message(1), independent = message(2, 2);
  for (const body of [first, second, independent]) await enqueue(queue, body);
  const active = (await queue.claimNext())!;
  expect(active.id).toBe(inboundId(first.body)); // Arrival order, not random message ID order.
  expect((await other.claimNext())?.id).toBe(inboundId(independent.body));
  expect(await other.claimNext()).toBeNull();
  expect(await queue.recoverStaleClaims({ staleMs: 0, shouldRecover: () => false })).toBe(0);
  expect(await queue.recoverStaleClaims({ staleMs: 0, shouldRecover: async claim => {
    f.tick(3000); await other.refreshClaim(claim); return true;
  } })).toBe(0);
  expect(await queue.release(active, { recordAttempt: false })).toBe(true);
  expect((await queue.listPending())[0].attempts).toBe(0);
});

test('failed dispatch stays recoverable without persisting host exception text', async () => {
  const f = fixture(); const queue = f.open(); const body = message(1);
  await enqueue(queue, body);
  let claim = (await queue.claimNext())!;
  await queue.release(claim, { lastError: 'secret exception text' });
  const [pending] = await queue.listPending();
  expect(pending.attempts).toBe(1);
  expect(pending.lastError).toBe('qntm host delivery failed');
  claim = (await queue.claimNext())!;
  await queue.fail(claim, { reason: 'secret reason', message: 'secret exception text' });
  expect((await enqueue(queue, body)).kind).toBe('failed');
  expect(await queue.listFailed()).toMatchObject([{ payload: body, reason: 'host_delivery_failed', message: 'qntm host delivery failed' }]);
  expect((await queue.resubmit(inboundId(body.body))).kind).toBe('resubmitted');
  expect((await queue.listPending())[0].attempts).toBe(0);
});

test('bounds active storage atomically but permits duplicate admission when full', async () => {
  const f = fixture(1); const queue = f.open(), other = f.open();
  const body = message(1);
  await enqueue(queue, body); await queue.claimNext();
  await expect(enqueue(other, message(2))).rejects.toThrow('queue is full');
  expect((await enqueue(other, body)).kind).toBe('claimed');
  expect(await queue.listPending()).toHaveLength(0);
});

test('private tombstones discard plaintext; retention never prunes active claims', async () => {
  const f = fixture(); const queue = f.open();
  for (let i = 1; i <= 4; i++) await enqueue(queue, message(i, i));
  const completed = (await queue.claimNext())!; await queue.complete(completed);
  const failed = (await queue.claimNext())!; await queue.fail(failed, { reason: 'test' });
  const active = (await queue.claimNext())!;
  expect(statSync(queue.filename).mode & 0o777).toBe(0o600);
  expect(statSync(queue.filename + '-wal').mode & 0o777).toBe(0o600);
  const db = new DatabaseSync(queue.filename);
  expect(db.prepare('SELECT payload FROM ingress WHERE id=?').get(completed.id)?.payload).toBeNull();
  db.close();
  f.tick(20_000);
  expect(await queue.prune({ pendingTtlMs: 0, completedTtlMs: 0, failedTtlMs: 0, protectIds: [failed.id] })).toBe(2);
  expect((await queue.listClaims())[0].id).toBe(active.id);
  expect(await queue.listFailed()).toHaveLength(1);
  expect(await queue.prune({ failedMaxEntries: 0 })).toBe(1);
});

test('invalid payloads, corrupt storage and unknown schema fail closed', async () => {
  const f = fixture(); let queue = f.open(); const body = message(1);
  await expect(queue.enqueue('wrong-id', body)).rejects.toThrow('Invalid qntm ingress event');
  await enqueue(queue, body);
  const filename = queue.filename; f.close(queue);
  const db = new DatabaseSync(filename);
  db.prepare('UPDATE ingress SET payload=?').run('{"secret":"never-echo",'); db.close();
  queue = f.open();
  await expect(queue.listPending()).rejects.toThrow(/^Invalid persisted qntm ingress record$/);
  f.close(queue);
  const unsupported = new DatabaseSync(filename); unsupported.exec('PRAGMA user_version=99'); unsupported.close();
  expect(() => f.open()).toThrow('Unsupported qntm ingress database version');
  writeFileSync(filename, 'not sqlite');
  expect(() => f.open()).toThrow();
});

test('SQLite capacity failure rolls back admission and leaves existing work recoverable', async () => {
  const f = fixture(); const queue = f.open();
  const first = message(1); await enqueue(queue, first);
  // Constrain this connection to its current page count to exercise SQLITE_FULL.
  const db = (queue as unknown as { db: DatabaseSync }).db;
  const pages = db.prepare('PRAGMA page_count').get()!.page_count;
  db.exec(`PRAGMA max_page_count=${pages}`);
  const oversized = message(2); oversized.body.text = 'x'.repeat(65536);
  await expect(enqueue(queue, oversized)).rejects.toThrow();
  expect((await queue.listPending()).map(row => row.id)).toEqual([inboundId(first.body)]);
  db.exec('PRAGMA max_page_count=65536');
  expect((await enqueue(queue, oversized)).kind).toBe('accepted');
});
