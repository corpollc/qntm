/** Ordinary groups: one durable commit contains keys, replay boundary, pending
 * ciphertext, exact unfinished operation and host dispatch. Gateway state stays
 * in its existing checkpoint and cannot be selected through this API. */
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, openSync, unlinkSync, writeFileSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { resolveStateDir } from 'openclaw/plugin-sdk/state-paths';
import { normalizeAccountId } from 'openclaw/plugin-sdk/account-id';
import {
  DropboxClient, GroupState, QSP1Suite, base64UrlDecode, base64UrlEncode, deserializeEnvelope, serializeEnvelope,
  restoreGroupSession, groupSessionConversation, checkGroupReplayCoverage, checkExpiredGroupControl, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch,
  receiveGroupEvent, requireGroupRecovery, openGroupWelcome, groupSessionFromWelcome, parseGroupLink, createGroupLink,
  assertGroupCanSend, prepareGroupSessionAddition, prepareGroupWelcomeRefresh, prepareGroupSessionRekey,
  assertGroupWelcomeRefreshCurrent, createGroupControlMessage, createGroupRemoveBody,
  prepareGroupAdmissionRenewal, assertGroupAdmissionRenewalCurrent, MAX_GROUP_WELCOME_BYTES, GROUP_WELCOME_TTL,
  createGroupSession, createMessage, keyIDFromPublicKey, unmarshalCanonical, marshalCanonical, openSecret,
  type GroupSessionState, type GroupAddition, type GroupWelcomeRefresh, type GroupAdmissionRenewal, type GroupWelcome, type OuterEnvelope,
} from '@corpollc/qntm';
import { readBoundedFile, writePrivateJSON } from './storage.js';
import { validateInbound, inboundId, MAX_PENDING_DISPATCHES, type QntmInbound } from './checkpoint.js';
import { decodeContactKey } from './accounts.js';
import { toHex } from './qntm.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding, QntmGroupAction } from './types.js';

const seq = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const dispatchGeneration = () => randomUUID().replaceAll('-', '');
const rowSchema = z.object({ seq: seq.min(1), wire: z.string().max(128 * 1024) }).strict();
const MAX_OPERATION_REVISIONS = 256;
const MAX_OPERATION_EVIDENCE_BYTES = 4 * 1024 * 1024;
const evidenceSchema = z.object({
  phase: z.enum(['addition_rekey', 'renewal', 'refresh', 'removal_rekey', 'rekey']), controls: z.array(z.string().max(128 * 1024)).max(2),
  welcomes: z.array(z.string().max(128 * 1024)).max(1), sentControls: seq.max(2), sentWelcomes: seq.max(1), delivery: z.literal('unknown'),
}).strict();
const originalAdditionSchema = z.object({
  controls: z.array(z.string().max(128 * 1024)).length(2), welcomes: z.array(z.string().max(128 * 1024)).length(1),
  sentControls: seq.max(2), sentWelcomes: seq.max(1), recipient: z.string(),
  addId: z.string().regex(/^[0-9a-f]{32}$/), addDigest: z.string().regex(/^[0-9a-f]{64}$/), delivery: z.literal('unknown'),
}).strict();
/** The exact member record and admission incarnation a removal targets, so an
 * exact retry can never remove a later readmission of the same identity. */
const removalTargetSchema = z.object({
  keyId: z.string().regex(/^[0-9a-f]{32}$/), publicKey: z.string().max(44), record: z.string().max(4096),
  admission: z.object({
    addId: z.string().regex(/^[0-9a-f]{32}$/), addDigest: z.string().regex(/^[0-9a-f]{64}$/), sourceEpoch: z.number().int().min(0).max(0xffffffff),
    completion: z.object({ rekeyId: z.string().regex(/^[0-9a-f]{32}$/), rekeyDigest: z.string().regex(/^[0-9a-f]{64}$/) }).strict().nullable(),
  }).strict().nullable(),
}).strict();
export type GroupRemovalTarget = z.infer<typeof removalTargetSchema>;
const originalRemovalSchema = z.object({
  kind: z.literal('remove'), controls: z.array(z.string().max(128 * 1024)).length(2), welcomes: z.array(z.string().max(128 * 1024)).max(0),
  sentControls: seq.max(2), sentWelcomes: seq.max(0), target: removalTargetSchema.optional(), delivery: z.literal('unknown'),
}).strict();
const operationSchema = z.object({
  id: z.string().regex(/^[0-9a-f]{32}$/), action: z.enum(['add', 'remove', 'refresh', 'rekey', 'send']),
  contact: z.string().optional(), publicKey: z.string().optional(), text: z.string().optional(),
  origin: z.union([originalAdditionSchema, originalRemovalSchema]).optional(), phase: z.enum(['addition_rekey', 'removal_rekey']).optional(),
  target: removalTargetSchema.optional(),
  superseded: z.array(evidenceSchema).max(MAX_OPERATION_REVISIONS).optional(),
  welcomePurpose: z.enum(['refresh', 'renewal']).optional(), recoveryChallenge: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  expected: z.unknown(), controls: z.array(z.string().max(128 * 1024)).max(2),
  welcomes: z.array(z.string().max(128 * 1024)).max(1), sentControls: seq.max(2), sentWelcomes: seq.max(1),
}).strict();
export type GroupOperation = z.infer<typeof operationSchema>;
type RemovalOrigin = z.infer<typeof originalRemovalSchema>;
function removalOrigin(operation: GroupOperation): RemovalOrigin | undefined {
  return operation.origin && 'kind' in operation.origin ? operation.origin : undefined;
}
function additionOrigin(operation: GroupOperation): z.infer<typeof originalAdditionSchema> | undefined {
  return operation.origin && !('kind' in operation.origin) ? operation.origin : undefined;
}
/** Exact wires whose acceptance evidence this journal may hold: the current
 * controls plus, for a removal repair, the original accepted removal. Never
 * arbitrary superseded ciphertext. */
function receiptWires(operation: GroupOperation | null): string[] {
  if (!operation) return [];
  const origin = removalOrigin(operation);
  return operation.phase === 'removal_rekey' && origin ? [origin.controls[0], ...operation.controls] : operation.controls;
}
/** Exact acceptance evidence for one pending control, latched only from
 * authenticated receive. Observed delivery (digest, ID, source epoch, relay
 * sequence) is kept apart from whether that branch is still canonical. */
const controlReceiptSchema = z.object({
  messageId: z.string().regex(/^[0-9a-f]{32}$/), digest: z.string().regex(/^[0-9a-f]{64}$/),
  epoch: z.number().int().min(0).max(0xffffffff), sequence: seq.min(1), valid: z.boolean(),
}).strict();
export type GroupControlReceipt = z.infer<typeof controlReceiptSchema>;
const schema = z.object({
  version: z.literal(1), seed: z.string().regex(/^[0-9a-f]{64}$/), revision: seq,
  cursor: seq, bootstrap: seq, session: z.unknown().nullable(),
  pending: z.array(rowSchema).max(256), outbox: z.array(z.unknown()).max(MAX_PENDING_DISPATCHES),
  receipts: z.array(seq.min(1)).max(8192), operation: operationSchema.nullable(), removedSequence: seq,
  dispatchGeneration: z.string().regex(/^[0-9a-f]{32}$/).optional(),
  controlReceipts: z.array(controlReceiptSchema).max(2).optional(),
}).strict();
export type GroupRow = z.infer<typeof rowSchema>;
export interface GroupCheckpoint extends Omit<z.infer<typeof schema>, 'session' | 'outbox' | 'dispatchGeneration' | 'controlReceipts'> {
  session: GroupSessionState | null; outbox: QntmInbound[]; dispatchGeneration: string; controlReceipts: GroupControlReceipt[];
}
/** Pending host jobs are rechecked immediately before entering the agent. */
export function groupDispatchDisposition(state: GroupCheckpoint, inbound: QntmInbound): 'dispatch' | 'defer' | 'discard' {
  const binding = inbound.groupDispatch;
  if (!binding || binding.generation !== state.dispatchGeneration || state.session?.removed) return 'discard';
  if (!state.session || state.session.recovery || state.session.needsRekey || state.operation) return 'defer';
  const seen = state.session.seen[inbound.messageId];
  return !seen || seen.digest === binding.digest ? 'dispatch' : 'discard';
}
export type GroupTransport = Pick<DropboxClient, 'receiveMessages' | 'postMessage'>;
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function group(state: GroupSessionState): GroupState {
  const result = new GroupState(); result.applyGenesis(unmarshalCanonical(base64UrlDecode(state.snapshot))); return result;
}
function envelope(wire: string): OuterEnvelope { return deserializeEnvelope(base64UrlDecode(wire)); }
function encode(value: OuterEnvelope): string { return base64UrlEncode(serializeEnvelope(value)); }
function wireDigest(wire: string): string { return toHex(new QSP1Suite().hash(base64UrlDecode(wire))); }
function requireValue(value: unknown, message: string): asserts value { if (!value) throw new Error(message); }
/** Pin the exact member record and admission incarnation a removal targets. */
export function removalTarget(session: GroupSessionState, kid: Uint8Array): GroupRemovalTarget {
  const member = group(session).snapshot().founding_members.find(row => toHex(row.key_id) === toHex(kid));
  requireValue(member, 'Invalid removed member');
  return removalTargetSchema.parse({ keyId: toHex(kid), publicKey: base64UrlEncode(member.public_key),
    record: base64UrlEncode(marshalCanonical(member)), admission: structuredClone(session.admissions[toHex(kid)] ?? null) });
}
const locks = new Map<string, Promise<unknown>>();
export class QntmGroupStore {
  readonly filename: string;
  private readonly seed: string;
  constructor(readonly account: ResolvedQntmAccount, readonly binding: ResolvedQntmBinding,
    options: { stateDir?: string; client?: GroupTransport } = {}) {
    requireValue(account.identity && binding.ordinaryGroup && !binding.gatewayActions?.length, 'An ordinary group binding is required');
    this.filename = path.join(options.stateDir ?? resolveStateDir(), 'plugins/qntm/accounts', normalizeAccountId(account.accountId), 'groups', `${binding.conversationId}.json`);
    this.seed = digest({ relay: account.relayUrl.replace(/\/+$/, ''), identity: toHex(account.identity.publicKey),
      conversation: binding.conversationId, initialSession: binding.groupSeed?.session ?? null });
    this.client = options.client ?? new DropboxClient(account.relayUrl);
  }
  readonly client: GroupTransport;
  load(): GroupCheckpoint {
    let raw: Buffer;
    try { raw = readBoundedFile(this.filename, 16 * 1024 * 1024); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const session = this.binding.groupSeed ? restoreGroupSession(this.account.identity!, this.binding.groupSeed.session) : null;
      const cursor = this.binding.groupSeed?.cursor ?? 0;
      seq.parse(cursor);
      return { version: 1, seed: this.seed, revision: 0, cursor, bootstrap: cursor, session,
        pending: [], outbox: [], receipts: [], operation: null, removedSequence: 0, dispatchGeneration: dispatchGeneration(), controlReceipts: [] };
    }
    const parsed = schema.parse(JSON.parse(raw.toString('utf8')));
    requireValue(parsed.seed === this.seed, 'Group checkpoint identity or initial configuration changed; preserve and inspect its private file');
    const session = parsed.session ? restoreGroupSession(this.account.identity!, parsed.session) : null;
    requireValue(!session || session.conversationId === this.binding.conversationId, 'Group checkpoint conversation mismatch');
    const outbox = parsed.outbox.map(validateInbound);
    requireValue(outbox.every(item => item.conversationId === this.binding.conversationId), 'Group dispatch conversation mismatch');
    if (parsed.operation) { restoreGroupSession(this.account.identity!, parsed.operation.expected); this.checkEvidence(parsed.operation); }
    const state = { ...parsed, session, outbox, dispatchGeneration: parsed.dispatchGeneration ?? dispatchGeneration(), controlReceipts: parsed.controlReceipts ?? [] };
    this.checkReceipts(state);
    return state;
  }
  save(state: GroupCheckpoint): void {
    requireValue(this.load().revision === state.revision, 'Concurrent group writer; reload before retrying');
    requireValue(state.pending.reduce((sum, row) => sum + base64UrlDecode(row.wire).length, 0) <= 4 * 1024 * 1024, 'Group pending ciphertext exceeds 4 MiB');
    const next = { ...state, revision: state.revision + 1 };
    schema.parse(next);
    if (next.operation) this.checkEvidence(next.operation);
    this.checkReceipts(next);
    writePrivateJSON(this.filename, next, 16 * 1024 * 1024);
    state.revision = next.revision;
  }
  /** Every receipt must name one exact pending control of this conversation at
   * a verified relay sequence. Anything else fails closed. */
  private checkReceipts(state: Pick<GroupCheckpoint, 'operation' | 'controlReceipts' | 'cursor'>): void {
    const receipts = state.controlReceipts, controls = receiptWires(state.operation);
    const bound = (receipt: GroupControlReceipt) => controls.some(wire => {
      try {
        const outer = envelope(wire);
        return toHex(outer.msg_id) === receipt.messageId && wireDigest(wire) === receipt.digest
          && outer.conv_epoch === receipt.epoch && toHex(outer.conv_id) === this.binding.conversationId;
      } catch { return false; }
    });
    requireValue(receipts.length <= controls.length && new Set(receipts.map(receipt => receipt.messageId)).size === receipts.length
      && receipts.every(receipt => receipt.sequence <= state.cursor && bound(receipt)),
    'Group control receipts do not match the pending operation; preserve and inspect its private file');
  }
  private static receiptsFor(receipts: GroupControlReceipt[], controls: string[]): GroupControlReceipt[] {
    const digests = new Set(controls.map(wireDigest));
    return receipts.filter(receipt => digests.has(receipt.digest));
  }
  /** Latched exact evidence for one pending control, or undefined when unknown. */
  controlReceipt(state: GroupCheckpoint, wire: string): GroupControlReceipt | undefined {
    const digest = wireDigest(wire), id = toHex(envelope(wire).msg_id);
    return state.controlReceipts.find(receipt => receipt.messageId === id && receipt.digest === digest);
  }
  /** Exact branch-valid acceptance of a pending control. A latched receipt
   * decides first, so its explicit invalidation overrides a duplicate marker
   * that a rewind left in the bounded cache. Without a receipt, only the
   * retained marker counts; older evicted evidence stays unknown. No relay
   * acknowledgement, bare ID, missing target or expected root is proof. */
  controlAccepted(state: GroupCheckpoint, wire: string): boolean {
    if (!state.session) return false;
    const outer = envelope(wire), id = toHex(outer.msg_id), digest = wireDigest(wire);
    const receipt = state.controlReceipts.find(receipt => receipt.messageId === id && receipt.digest === digest);
    if (receipt) return receipt.valid && receipt.epoch === outer.conv_epoch && receipt.sequence > 0 && receipt.sequence <= state.cursor;
    const known = state.session.seen[id];
    return known?.digest === digest && known.epoch === outer.conv_epoch;
  }
  private latchReceipt(state: GroupCheckpoint, wire: string, outer: OuterEnvelope, sequence: number): void {
    const digest = wireDigest(wire);
    if (!receiptWires(state.operation).some(control => wireDigest(control) === digest)) return;
    const id = toHex(outer.msg_id);
    state.controlReceipts = [...state.controlReceipts.filter(receipt => receipt.messageId !== id),
      { messageId: id, digest, epoch: outer.conv_epoch, sequence, valid: true }];
  }
  /** A canonical rewind at this source epoch supersedes every rekey that had
   * advanced from it and everything accepted on those descendants. Controls
   * applied at the source epoch before the rotation remain part of its frame. */
  private invalidateRewound(state: GroupCheckpoint, sourceEpoch: number, frames: GroupSessionState['rekeys']): void {
    const losing = new Set(frames.filter(frame => frame.epoch >= sourceEpoch).map(frame => frame.messageId));
    state.controlReceipts = state.controlReceipts.map(receipt => receipt.epoch > sourceEpoch || losing.has(receipt.messageId)
      ? { ...receipt, valid: false } : receipt);
  }
  /** Serialize tool, outbound and monitor writes across instances and processes. */
  async exclusive<T>(run: () => Promise<T>): Promise<T> {
    const previous = locks.get(this.filename) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(async () => {
      mkdirSync(path.dirname(this.filename), { recursive: true, mode: 0o700 });
      let fd: number | undefined;
      const filename = this.filename + '.lock', deadline = Date.now() + 30_000;
      while (fd === undefined) {
        try { fd = openSync(filename, 'wx', 0o600); writeFileSync(fd, JSON.stringify({ pid: process.pid })); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
          try {
            const owner = JSON.parse(readBoundedFile(filename, 1024).toString('utf8'));
            requireValue(Number.isSafeInteger(owner.pid) && owner.pid > 0, 'Invalid group writer lock');
            try { process.kill(owner.pid, 0); } catch (probe) { if ((probe as NodeJS.ErrnoException).code === 'ESRCH') unlinkSync(filename); else throw probe; }
          } catch (read) { if ((read as NodeJS.ErrnoException).code !== 'ENOENT') throw read; }
          requireValue(Date.now() < deadline, 'Group profile is busy in another process');
          await delay(50);
        }
      }
      try { return await run(); } finally { closeSync(fd); unlinkSync(filename); }
    });
    locks.set(this.filename, next);
    try { return await next; } finally { if (locks.get(this.filename) === next) locks.delete(this.filename); }
  }
  link(): string { return createGroupLink({ conversationId: this.binding.conversation.id, inviterPublicKey: this.account.identity!.publicKey, relayUrl: this.account.relayUrl }); }
  status() {
    const state = this.load();
    return { status: !state.session ? 'awaiting_welcome' : state.session.recovery ? 'recovery_required' : state.session.removed ? 'removed' : state.session.needsRekey ? 'rotation_required' : 'ready',
      conversationId: this.binding.conversationId, epoch: state.session?.epoch, cursor: state.cursor,
      recovery: state.session?.recovery, pendingOperation: state.operation && { id: state.operation.id, action: state.operation.action,
        phase: state.operation.phase, welcomePurpose: state.operation.welcomePurpose,
        acceptedControls: state.operation.controls.filter(wire => this.controlAccepted(state, wire)).length },
      members: state.session ? group(state.session).snapshot().founding_members.map(member => ({ keyId: toHex(member.key_id), publicKey: base64UrlEncode(member.public_key) })) : [],
      contacts: Object.entries(this.account.config.contacts ?? {}).map(([name, key]) => ({ name, publicKey: base64UrlEncode(decodeContactKey(key)) })),
      groupLink: this.link(), permittedActions: this.binding.groupActions ?? [] };
  }
  /** Caller owns the writer lock. All rows, including unreadable ones, count toward coverage. */
  receive(rows: GroupRow[], head: number, replayBeforeCursor = false): void {
    const state = this.load(); seq.parse(head);
    requireValue(head >= state.cursor, 'Relay head moved behind saved group cursor');
    if (!state.session) return;
    const previousRecovery = state.session.recovery?.challenge, previousRemoved = state.session.removed;
    state.session = checkGroupReplayCoverage(state.session, state.cursor, head, [...rows.map(row => row.seq), ...state.receipts.filter(value => value > state.cursor && value <= head)]);
    const pending = new Map([...state.pending, ...rows.filter(row => replayBeforeCursor || row.seq > state.cursor)].map(row => [row.seq, row]));
    // Inspect the entire batch before producing plaintext. New members cannot
    // authenticate a delayed competing rekey using pre-admission source keys.
    // Bootstrap uses the welcome-specific guard and its signed exact hashes.
    if (!replayBeforeCursor) for (const row of pending.values()) {
      let wire: OuterEnvelope;
      try { wire = envelope(row.wire); } catch { continue; }
      state.session = checkGroupUnverifiableEpoch(state.session, wire, row.seq);
    }
    const now = Math.floor(Date.now() / 1000);
    let progress = true;
    while (progress && !state.session.recovery) {
      progress = false;
      for (const [sequence, row] of [...pending].sort(([a], [b]) => a - b)) {
        let wire: OuterEnvelope;
        try { wire = envelope(row.wire); } catch { pending.delete(sequence); continue; }
        if ((wire as unknown as { kind?: string }).kind === 'group_welcome') { pending.delete(sequence); continue; }
        if (!Number.isSafeInteger(wire.expiry_ts) || !Number.isSafeInteger(wire.conv_epoch)) { pending.delete(sequence); continue; }
        if (replayBeforeCursor && wire.conv_epoch < state.session.epoch && !state.session.rekeys.some(frame => frame.epoch === wire.conv_epoch)) { pending.delete(sequence); continue; }
        if (wire.expiry_ts < now) {
          state.session = checkExpiredGroupControl(this.account.identity!, state.session, wire, sequence);
          if (wire.conv_epoch <= state.session.epoch || state.session.recovery || state.session.removed) pending.delete(sequence);
          if (state.session.recovery) break;
          continue;
        }
        try {
          const event = receiveGroupEvent(this.account.identity!, wire, state.session);
          if (event.rewound) this.invalidateRewound(state, wire.conv_epoch, state.session.rekeys);
          state.session = event.state; pending.delete(sequence); progress = true;
          // Only fresh authenticated acceptance latches proof; a duplicate marker
          // may be a losing rekey the rewind left behind at its source epoch.
          if (!event.duplicate) this.latchReceipt(state, row.wire, wire, sequence);
          if (event.rewound) {
            // Branch reconciliation needs proof beyond this adapter's retained
            // ciphertext. Discard undispatched plaintext before recovery.
            state.outbox = [];
            state.session = requireGroupRecovery(event.state, Math.max(sequence, state.cursor), 'missing_history');
            break;
          }
          if (state.session.removed) state.removedSequence = Math.max(state.removedSequence, sequence);
          if (!event.duplicate && !state.session.removed && !event.message.inner.body_type.startsWith('group_')) {
            const message = event.message, text = new TextDecoder().decode(message.inner.body), senderKid = toHex(message.inner.sender_kid);
            if (senderKid !== toHex(this.account.identity!.keyID) && (this.binding.trigger !== 'mention' || this.binding.triggerNames.some(name => text.toLowerCase().includes(name.toLowerCase())))) {
              const inbound = validateInbound({ conversationId: this.binding.conversationId, messageId: toHex(wire.msg_id), senderKid,
                senderPublicKey: base64UrlEncode(message.inner.sender_ik_pk), epoch: wire.conv_epoch, createdAt: wire.created_ts * 1000,
                bodyType: message.inner.body_type, text, gatewayVerified: false,
                groupDispatch: { generation: state.dispatchGeneration, digest: state.session.seen[toHex(wire.msg_id)].digest } });
              if (!state.outbox.some(item => inboundId(item) === inboundId(inbound))) state.outbox.push(inbound);
            }
          }
        } catch { /* Future or competing-branch ciphertext is bounded and revisited after progress. */ }
      }
    }
    if (state.session.recovery || state.session.removed) state.outbox = [];
    if (state.session.recovery?.challenge !== previousRecovery || state.session.removed !== previousRemoved) state.dispatchGeneration = dispatchGeneration();
    state.pending = state.session.recovery ? [] : [...pending.values()];
    state.cursor = head; state.receipts = state.receipts.filter(sequence => sequence > head);
    this.save(state);
  }
  async sync(): Promise<void> {
    const state = this.load();
    if (!state.session) { await this.open(); return; }
    const result = await this.client.receiveMessages(this.binding.conversation.id, state.cursor);
    this.receive(result.entries.map(entry => ({ seq: entry.seq, wire: base64UrlEncode(entry.envelope) })), result.sequence);
  }
  /** Finish a crashed text delivery only after exact authenticated replay.
   * Caller owns the writer lock. This never publishes or replaces ciphertext;
   * uncertain sends and membership operations still require explicit retry. */
  finishAcceptedSend(): boolean {
    const state = this.load(), operation = state.operation;
    if (operation?.action !== 'send' || operation.controls.length !== 1 || operation.welcomes.length
      || !state.session || state.session.recovery || state.session.removed || state.session.needsRekey) return false;
    if (!this.controlAccepted(state, operation.controls[0])) return false;
    state.operation = null; state.controlReceipts = []; this.save(state); return true;
  }
  async open(link = this.binding.groupLink): Promise<void> {
    requireValue(link, 'Configure a public group link from a pinned contact');
    const locator = parseGroupLink(link);
    requireValue(toHex(locator.conversationId) === this.binding.conversationId && locator.relayUrl === this.account.relayUrl.replace(/\/+$/, ''), 'Group link conversation or relay differs from host configuration');
    requireValue(Object.values(this.account.config.contacts ?? {}).some(key => toHex(decodeContactKey(key)) === toHex(locator.inviterPublicKey)), 'Group link inviter is not a configured contact');
    const result = await this.client.receiveMessages(locator.conversationId, 0);
    const rows = result.entries.map(entry => ({ seq: entry.seq, wire: base64UrlEncode(entry.envelope) }));
    let state = this.load();
    if (state.session) {
      this.receive(rows, result.sequence); state = this.load();
      if (!state.session!.removed && !state.session!.needsRekey && !state.session!.recovery) return;
    }
    const candidates: Array<{ row: GroupRow; opened: GroupWelcome }> = [];
    for (const row of rows) {
      try {
        candidates.push({ row, opened: openGroupWelcome(this.account.identity!, base64UrlDecode(row.wire),
          { inviterPublicKey: locator.inviterPublicKey, conversationId: locator.conversationId }) });
      } catch { /* Not a valid unexpired welcome from this pinned contact. */ }
    }
    candidates.sort((a, b) => {
      const epoch = b.opened.conversation.currentEpoch - a.opened.conversation.currentEpoch;
      if (epoch) return epoch;
      const aAddition = a.opened.purpose === 'addition', bAddition = b.opened.purpose === 'addition';
      if (aAddition !== bAddition) return aAddition ? 1 : -1;
      // Renewals carry historical admission evidence, not a fresh rekey ID.
      if (a.opened.purpose !== 'addition' || b.opened.purpose !== 'addition') return b.row.seq - a.row.seq;
      const aId = toHex(a.opened.rekeyId), bId = toHex(b.opened.rekeyId);
      return aId < bId ? -1 : aId > bId ? 1 : b.row.seq - a.row.seq;
    });
    for (const { row, opened } of candidates) {
      let next: GroupSessionState, replayFromSequence: number;
      try {
        if (state.removedSequence && opened.purpose === 'addition' && row.seq <= state.removedSequence) continue;
        next = groupSessionFromWelcome(this.account.identity!, opened, row.seq, state.session ?? undefined);
        // A complete sequence can still hide an old-source competing rekey
        // that this new member has no pre-admission key to authenticate.
        next = checkGroupWelcomeReplay(next, opened, result.sequence, result.entries);
        replayFromSequence = opened.replayFromSequence;
      } catch { continue; }
      state.session = next; state.cursor = replayFromSequence; state.bootstrap = replayFromSequence; state.pending = []; state.outbox = [];
      state.dispatchGeneration = dispatchGeneration();
      // The installed welcome attests the sender's branch, not which of our
      // earlier controls survive on it. Replay below can latch fresh proof.
      state.controlReceipts = state.controlReceipts.map(receipt => ({ ...receipt, valid: false }));
      this.save(state); this.receive(rows.filter(item => item.seq > replayFromSequence), result.sequence, true); return;
    }
    throw new Error('No current welcome for this identity; retain the profile and ask a current member for a challenged refresh or explicit readmission');
  }
  prepare(action: Exclude<QntmGroupAction, 'retry' | 'open'>, options: { contact?: string; challenge?: string; text?: string }): GroupOperation {
    const state = this.load(); requireValue(state.session && !state.operation, 'Join the group and finish its pending operation first');
    const identity = this.account.identity!, session = state.session;
    const contact = options.contact, configured = contact ? this.account.config.contacts?.[contact] : undefined;
    const recipient = configured ? decodeContactKey(configured) : undefined;
    if (['add', 'remove', 'refresh'].includes(action)) requireValue(recipient, 'Select a locally configured contact by name');
    if (options.challenge) requireValue(/^[0-9a-f]{64}$/.test(options.challenge) && ['add', 'refresh'].includes(action), 'Recovery challenge must be 64 hex characters for add or refresh');
    const challenge = options.challenge ? new Uint8Array(Buffer.from(options.challenge, 'hex')) : undefined;
    let controls: OuterEnvelope[] = [], welcomes: OuterEnvelope[] = [], expected = session;
    let welcomePurpose: GroupOperation['welcomePurpose'], target: GroupRemovalTarget | undefined;
    if (action === 'add' || action === 'refresh') {
      const admission = recipient && session.admissions[toHex(keyIDFromPublicKey(recipient))];
      welcomePurpose = action === 'refresh' ? admission?.completion ? 'renewal' : 'refresh' : undefined;
      const value = action === 'add' ? prepareGroupSessionAddition(identity, session, [recipient!], undefined, challenge, state.cursor)
        : welcomePurpose === 'renewal' ? prepareGroupAdmissionRenewal(identity, session, recipient!,
          { addId: admission!.addId, addDigest: admission!.addDigest }, undefined, challenge, state.cursor)
          : prepareGroupWelcomeRefresh(identity, session, [recipient!], undefined, challenge, state.cursor);
      // A refresh seals the full current admission map; its expected checkpoint
      // must carry the same map so the signed intent can be compared on retry.
      expected = createGroupSession(identity, value.conversation, value.state, { signedEpoch: session.signedEpoch,
        ...(action === 'refresh' ? { admissions: welcomePurpose === 'renewal' ? (value as GroupAdmissionRenewal).admissions : session.admissions } : {}) });
      if (action === 'add') controls = [(value as GroupAddition).addition, (value as GroupAddition).rekey];
      welcomes = value.welcomes;
    } else if (action === 'rekey') {
      const value = prepareGroupSessionRekey(identity, session); controls = [value.rekey]; expected = receiveGroupEvent(identity, value.rekey, session).state;
    } else if (action === 'remove') {
      assertGroupCanSend(identity, session);
      const kid = keyIDFromPublicKey(recipient!);
      target = removalTarget(session, kid);
      const remove = createGroupControlMessage(identity, groupSessionConversation(session), 'group_remove', createGroupRemoveBody([kid]));
      const removed = receiveGroupEvent(identity, remove, session).state;
      const value = prepareGroupSessionRekey(identity, removed); controls = [remove, value.rekey]; expected = receiveGroupEvent(identity, value.rekey, removed).state;
    } else {
      assertGroupCanSend(identity, session);
      requireValue(typeof options.text === 'string' && options.text.length > 0 && Buffer.byteLength(options.text) <= 65536, 'Text must contain 1–65536 UTF-8 bytes');
      controls = [createMessage(identity, groupSessionConversation(session), 'text', new TextEncoder().encode(options.text))];
    }
    return { id: randomUUID().replaceAll('-', ''), action, contact, publicKey: recipient && base64UrlEncode(recipient), text: options.text,
      welcomePurpose, recoveryChallenge: options.challenge, ...(target ? { target } : {}),
      expected, controls: controls.map(encode), welcomes: welcomes.map(encode), sentControls: 0, sentWelcomes: 0 };
  }
  saveOperation(operation: GroupOperation): void {
    const state = this.load(); requireValue(!state.operation, 'An exact group operation is already pending');
    state.operation = operationSchema.parse(operation); state.controlReceipts = []; this.save(state);
  }
  private additionProof(state: GroupCheckpoint, operation: GroupOperation) {
    const origin = additionOrigin(operation), controls = origin?.controls ?? operation.controls;
    requireValue(operation.action === 'add' && !removalOrigin(operation) && controls.length === 2
      && operation.publicKey && state.session, 'Invalid original addition journal');
    const wire = base64UrlDecode(controls[0]), addition = deserializeEnvelope(wire);
    requireValue(encode(addition) === controls[0] && toHex(addition.conv_id) === this.binding.conversationId,
      'Saved addition context is invalid');
    const recipient = base64UrlDecode(operation.publicKey), kid = toHex(keyIDFromPublicKey(recipient));
    const expected = { addId: toHex(addition.msg_id), addDigest: toHex(new QSP1Suite().hash(wire)) };
    if (origin) requireValue(origin.recipient === operation.publicKey && origin.addId === expected.addId
      && origin.addDigest === expected.addDigest, 'Original addition evidence differs from the saved recipient or ciphertext');
    const admission = state.session.admissions[kid];
    return admission?.addId === expected.addId && admission.addDigest === expected.addDigest
      ? { admission, recipient, expected } : undefined;
  }
  private welcomeBase(operation: GroupOperation) {
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    return { conversation: groupSessionConversation(expected), state: group(expected), welcomes: operation.welcomes.map(envelope) };
  }
  private assertExactAddition(state: GroupCheckpoint, operation: GroupOperation): void {
    const proof = this.additionProof(state, operation), rekey = envelope(operation.controls[1]);
    requireValue(proof?.admission.completion?.rekeyId === toHex(rekey.msg_id)
      && proof.admission.completion.rekeyDigest === toHex(new QSP1Suite().hash(base64UrlDecode(operation.controls[1]))),
    'Original completing rekey is no longer canonical');
    assertGroupWelcomeRefreshCurrent(this.account.identity!, state.session!, this.welcomeBase(operation) as GroupWelcomeRefresh);
  }
  private checkContact(operation: GroupOperation): void {
    if (operation.contact) requireValue(this.account.config.contacts?.[operation.contact]
      && base64UrlEncode(decodeContactKey(this.account.config.contacts[operation.contact])) === operation.publicKey,
    'Pending operation contact pin changed; preserve it for reconciliation');
  }
  private additionChallenge(operation: GroupOperation): string | undefined {
    // Draft journals stored the optional challenge only inside their signed box.
    if (operation.recoveryChallenge !== undefined) return operation.recoveryChallenge;
    const identity = this.account.identity!, original = additionOrigin(operation) ?? operation, outer = envelope(original.welcomes[0]);
    const plain = openSecret(identity.privateKey, base64UrlDecode(operation.publicKey!), outer.ciphertext);
    const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain), payload = signed.payload;
    const { ciphertext: _ciphertext, ...header } = outer;
    const same = (a: unknown, b: unknown) => toHex(marshalCanonical(a)) === toHex(marshalCanonical(b));
    requireValue(toHex(plain) === toHex(marshalCanonical(signed))
      && payload.proto === 'qntm/group-welcome/v1' && same(payload.inviter_ik_pk, identity.publicKey)
      && same(payload.recipient_ik_pk, base64UrlDecode(operation.publicKey!))
      && toHex(outer.conv_id) === this.binding.conversationId
      && same(payload.addition_id, envelope(original.controls[0]).msg_id)
      && same(payload.rekey_id, envelope(original.controls[1]).msg_id) && same(payload.envelope, header)
      && new QSP1Suite().verify(identity.publicKey, marshalCanonical(payload), signed.signature), 'Invalid saved welcome challenge binding');
    const challenge = payload.recovery_challenge;
    requireValue(challenge === undefined || challenge instanceof Uint8Array && challenge.length === 32, 'Invalid saved recovery challenge');
    return challenge === undefined ? undefined : toHex(challenge as Uint8Array);
  }
  /** Authenticate the old generic intent without treating its expired keys as
   * current authority. A recipient can open its box but cannot forge our signature. */
  private genericRefreshContext(operation: GroupOperation): { recipient: Uint8Array; challenge?: string } {
    requireValue(operation.action === 'refresh' && operation.welcomePurpose !== 'renewal' && !operation.origin && !operation.phase
      && operation.controls.length === 0 && operation.welcomes.length === 1 && operation.publicKey, 'Invalid saved generic refresh intent');
    const identity = this.account.identity!, wire = base64UrlDecode(operation.welcomes[0]);
    const fields = (value: unknown, names: string[]) => value !== null && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).sort().join(',') === names.sort().join(',');
    const same = (a: unknown, b: unknown) => toHex(marshalCanonical(a)) === toHex(marshalCanonical(b));
    const outer = deserializeEnvelope(wire), at = Math.floor(Date.now() / 1000);
    requireValue(wire.length <= MAX_GROUP_WELCOME_BYTES && fields(outer, ['v', 'suite', 'kind', 'conv_id', 'msg_id', 'conv_epoch', 'created_ts', 'expiry_ts', 'ciphertext'])
      && encode(outer) === operation.welcomes[0] && outer.v === 1 && outer.suite === 'QSP-1'
      && (outer as OuterEnvelope & { kind?: string }).kind === 'group_welcome'
      && outer.msg_id instanceof Uint8Array && outer.msg_id.length === 16 && toHex(outer.conv_id) === this.binding.conversationId
      && Number.isSafeInteger(outer.conv_epoch) && outer.conv_epoch >= 0 && outer.conv_epoch <= 0xffffffff
      && Number.isSafeInteger(outer.created_ts) && outer.created_ts > 0 && outer.created_ts <= at + 600
      && Number.isSafeInteger(outer.expiry_ts) && outer.expiry_ts > outer.created_ts
      && outer.expiry_ts - outer.created_ts <= GROUP_WELCOME_TTL, 'Invalid saved generic refresh envelope');
    const recipient = base64UrlDecode(operation.publicKey), plain = openSecret(identity.privateKey, recipient, outer.ciphertext);
    const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain);
    requireValue(fields(signed, ['payload', 'signature']) && signed.signature instanceof Uint8Array && signed.signature.length === 64
      && toHex(plain) === toHex(marshalCanonical(signed)), 'Invalid saved generic refresh signature container');
    const payload = signed.payload, { ciphertext: _ciphertext, ...header } = outer;
    const optional = ['replay_from_seq', 'admissions', 'recovery_challenge'].filter(key => payload && Object.hasOwn(payload, key));
    requireValue(fields(payload, ['proto', 'envelope', 'inviter_ik_pk', 'recipient_ik_pk', 'group_key', 'group_state', ...optional])
      && payload.proto === 'qntm/group-refresh/v1' && same(payload.envelope, header)
      && same(payload.inviter_ik_pk, identity.publicKey) && same(payload.recipient_ik_pk, recipient)
      && new QSP1Suite().verify(identity.publicKey, marshalCanonical(payload), signed.signature), 'Invalid saved generic refresh binding or signature');
    const expected = restoreGroupSession(identity, operation.expected), oldRoster = group(expected).snapshot();
    requireValue(expected.conversationId === this.binding.conversationId && outer.conv_epoch === expected.epoch
      && payload.group_key instanceof Uint8Array && toHex(payload.group_key) === expected.root && same(payload.group_state, oldRoster)
      && oldRoster.founding_members.some(member => same(member.public_key, recipient))
      && oldRoster.founding_members.some(member => same(member.public_key, identity.publicKey)), 'Saved generic refresh differs from its original checkpoint');
    requireValue(payload.replay_from_seq === undefined || Number.isSafeInteger(payload.replay_from_seq) && (payload.replay_from_seq as number) >= 0,
      'Invalid saved refresh replay anchor');
    if (payload.admissions !== undefined) {
      // Older generic journals omit provenance; when present it must equal the
      // validated checkpoint map in its completed wire form, entry for entry.
      const unhex = (text: string) => new Uint8Array(Buffer.from(text, 'hex'));
      const wired = Object.fromEntries(Object.entries(expected.admissions).map(([kid, record]) => {
        requireValue(record.completion, 'Saved generic refresh admissions differ from its original checkpoint');
        return [kid, { add_id: unhex(record.addId), add_hash: unhex(record.addDigest), source_epoch: record.sourceEpoch,
          rekey_id: unhex(record.completion.rekeyId), rekey_hash: unhex(record.completion.rekeyDigest) }];
      }));
      requireValue(same(payload.admissions, wired), 'Saved generic refresh admissions differ from its original checkpoint');
    }
    const value = payload.recovery_challenge;
    requireValue(value === undefined || value instanceof Uint8Array && value.length === 32, 'Invalid saved refresh recovery challenge');
    const challenge = value === undefined ? undefined : toHex(value as Uint8Array);
    requireValue(operation.recoveryChallenge === undefined || operation.recoveryChallenge === challenge, 'Saved refresh challenge differs from its signed intent');
    return { recipient, challenge };
  }
  private assertGenericRecipient(state: GroupCheckpoint, recipient: Uint8Array): void {
    requireValue(state.session, 'Missing group checkpoint');
    assertGroupCanSend(this.account.identity!, state.session);
    requireValue(group(state.session).snapshot().founding_members.some(member => toHex(member.public_key) === toHex(recipient)),
      'Original refresh recipient is no longer a current member');
  }
  private prepareGenericRetry(state: GroupCheckpoint, operation: GroupOperation): GroupOperation {
    const { recipient, challenge } = this.genericRefreshContext(operation);
    this.assertGenericRecipient(state, recipient);
    const exact: GroupOperation = { ...operation, welcomePurpose: 'refresh', recoveryChallenge: challenge };
    try { assertGroupWelcomeRefreshCurrent(this.account.identity!, state.session!, this.welcomeBase(operation) as GroupWelcomeRefresh); return exact; }
    catch { /* A fresh review may redeliver current keys to the same full member key. */ }
    // Keep the generic purpose even if this recipient now has known admission
    // provenance. Only a separately reviewed renewal can recover readmission.
    const refreshed = prepareGroupWelcomeRefresh(this.account.identity!, state.session!, [recipient], undefined,
      challenge ? new Uint8Array(Buffer.from(challenge, 'hex')) : undefined, state.cursor);
    const next: GroupOperation = { ...exact, welcomes: refreshed.welcomes.map(encode), sentWelcomes: 0,
      expected: createGroupSession(this.account.identity!, refreshed.conversation, refreshed.state,
        { signedEpoch: state.session!.signedEpoch, admissions: state.session!.admissions }),
      superseded: this.retainSuperseded(operation) };
    this.checkEvidence(next); return next;
  }
  private checkEvidence(operation: GroupOperation): void {
    requireValue((operation.superseded?.length ?? 0) <= MAX_OPERATION_REVISIONS
      && marshalCanonical({ origin: operation.origin ?? null, superseded: operation.superseded ?? [] }).length <= MAX_OPERATION_EVIDENCE_BYTES,
    'Saved recovery evidence reached its limit; preserve the operation');
  }
  private retainSuperseded(operation: GroupOperation): GroupOperation['superseded'] {
    const superseded = [...operation.superseded ?? [], { phase: operation.phase ?? (operation.welcomePurpose === 'renewal' ? 'renewal' as const : operation.action === 'rekey' ? 'rekey' as const : 'refresh' as const),
      controls: [...operation.controls], welcomes: [...operation.welcomes], sentControls: operation.sentControls,
      sentWelcomes: operation.sentWelcomes, delivery: 'unknown' as const }];
    this.checkEvidence({ ...operation, superseded }); return superseded;
  }
  private originalAddition(operation: GroupOperation, expected: { addId: string; addDigest: string }): NonNullable<GroupOperation['origin']> {
    return additionOrigin(operation) ?? { controls: [...operation.controls], welcomes: [...operation.welcomes], sentControls: operation.sentControls,
      sentWelcomes: operation.sentWelcomes, recipient: operation.publicKey!, ...expected, delivery: 'unknown' };
  }
  private assertPendingRotation(state: GroupCheckpoint, operation: GroupOperation): void {
    const proof = this.additionProof(state, operation);
    requireValue(proof && state.session, 'Original addition is no longer the current admission');
    assertGroupCanSend(this.account.identity!, { ...state.session, needsRekey: false });
    requireValue(state.session.needsRekey && !proof.admission.completion && proof.admission.sourceEpoch === state.session.epoch,
      'Original admission is not awaiting its completing rotation');
    const outer = envelope(operation.controls[operation.phase ? 0 : 1]);
    requireValue(outer.expiry_ts >= Math.floor(Date.now() / 1000), 'Saved completing rotation expired');
    const trial = receiveGroupEvent(this.account.identity!, outer, state.session).state;
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    requireValue(trial.root === expected.root && trial.epoch === expected.epoch && trial.snapshot === expected.snapshot,
      'Saved completing rotation differs from the current roster');
  }
  private assertRenewal(state: GroupCheckpoint, operation: GroupOperation): void {
    requireValue(operation.publicKey && state.session, 'Saved renewal recipient is missing');
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    const recipient = base64UrlDecode(operation.publicKey), admission = expected.admissions[toHex(keyIDFromPublicKey(recipient))];
    requireValue(admission?.completion, 'Saved renewal admission proof is missing');
    if (operation.origin) {
      const proof = this.additionProof(state, operation);
      requireValue(proof?.admission.completion && proof.expected.addId === admission.addId && proof.expected.addDigest === admission.addDigest,
        'Renewal differs from its original admission');
    }
    assertGroupAdmissionRenewalCurrent(this.account.identity!, state.session,
      { ...this.welcomeBase(operation), recipient, admission, admissions: expected.admissions } as GroupAdmissionRenewal);
  }
  /** The saved removal intent: the journal itself or a repair's exact origin. */
  private removalIntent(operation: GroupOperation): { intent: { controls: string[]; target?: GroupRemovalTarget }; wire: string; source: number } {
    const origin = removalOrigin(operation);
    const intent = operation.phase === 'removal_rekey' ? origin : operation;
    requireValue(operation.action === 'remove' && intent && intent.controls.length === 2 && !intent.welcomes.length
      && (operation.phase === 'removal_rekey' ? operation.controls.length === 1 && !operation.welcomes.length : !origin), 'Invalid saved removal intent');
    const wire = intent.controls[0], outer = envelope(wire);
    requireValue(encode(outer) === wire && toHex(outer.conv_id) === this.binding.conversationId, 'Invalid saved removal context');
    return { intent, wire, source: outer.conv_epoch };
  }
  private static removedMembers(message: { inner: { body: Uint8Array } }): Uint8Array[] {
    const body = unmarshalCanonical<{ removed_members?: unknown }>(message.inner.body), members = body?.removed_members;
    requireValue(Array.isArray(members) && members.every(kid => kid instanceof Uint8Array && kid.length === 16), 'Invalid saved removal body');
    return members as Uint8Array[];
  }
  /** Refuse to publish an old removal against a later admission of its target.
   * Journals saved before target pinning still detect a readmission sourced at
   * the current epoch: the intent was prepared while no addition was pending. */
  private assertRemovalTargetCurrent(session: GroupSessionState, intent: { target?: GroupRemovalTarget }, removed: Uint8Array[]): void {
    const target = intent.target;
    if (!target) {
      for (const kid of removed) requireValue(session.admissions[toHex(kid)]?.sourceEpoch !== session.epoch,
        'Saved removal predates a later admission of its target; preserve it for reconciliation');
      return;
    }
    requireValue(removed.length === 1 && toHex(removed[0]) === target.keyId, 'Saved removal differs from its pinned target; preserve it for reconciliation');
    let current: GroupRemovalTarget | undefined;
    try { current = removalTarget(session, removed[0]); } catch { /* No longer a member. */ }
    requireValue(current && toHex(marshalCanonical(current)) === toHex(marshalCanonical(target)),
      'Saved removal no longer targets its original admission; preserve it for reconciliation');
  }
  /** Exact saved rotation ciphertext stays exact only while it still applies. */
  private assertRotationCurrent(session: GroupSessionState, wire: string, expected: unknown): void {
    const outer = envelope(wire);
    requireValue(outer.expiry_ts >= Math.floor(Date.now() / 1000), 'Saved rotation expired');
    requireValue(outer.conv_epoch === session.epoch, 'Saved rotation no longer targets the current epoch');
    const trial = receiveGroupEvent(this.account.identity!, outer, session).state, want = restoreGroupSession(this.account.identity!, expected);
    requireValue(trial.root === want.root && trial.epoch === want.epoch && trial.snapshot === want.snapshot, 'Saved rotation differs from the current roster');
  }
  private rotationJournal(session: GroupSessionState, base: GroupOperation): GroupOperation {
    const rotation = prepareGroupSessionRekey(this.account.identity!, session);
    const trial = receiveGroupEvent(this.account.identity!, rotation.rekey, session).state;
    return { ...base, controls: [encode(rotation.rekey)], welcomes: [], sentControls: 0, sentWelcomes: 0,
      expected: createGroupSession(this.account.identity!, rotation.conversation, rotation.state, { signedEpoch: session.signedEpoch, admissions: trial.admissions }) };
  }
  /** A proven removal that any verified rotation already carried past its
   * source epoch, or a rotation intent that a verified rotation fulfilled,
   * finishes locally with no POST. Proof comes only from exact acceptance. */
  fulfilled(state: GroupCheckpoint, operation: GroupOperation): boolean {
    if (!state.session || state.session.recovery) return false;
    if (operation.action === 'remove') {
      const { wire, source } = this.removalIntent(operation);
      return this.controlAccepted(state, wire) && state.session.epoch > source;
    }
    if (operation.action !== 'rekey' || operation.phase || operation.origin || operation.controls.length !== 1 || operation.welcomes.length) return false;
    try { assertGroupCanSend(this.account.identity!, { ...state.session, needsRekey: false }); } catch { return false; }
    return state.session.epoch > envelope(operation.controls[0]).conv_epoch;
  }
  /** Finish an accepted removal from current membership; never re-remove. */
  private prepareRemovalRetry(state: GroupCheckpoint, operation: GroupOperation): GroupOperation {
    const identity = this.account.identity!, session = state.session!, { intent, wire, source } = this.removalIntent(operation);
    if (!this.controlAccepted(state, wire)) {
      // Absent targets, predicted roots and acknowledgements prove nothing. A
      // same-epoch, unexpired removal keeps its exact bytes for retry.
      requireValue(operation.phase !== 'removal_rekey', 'Original removal is no longer verified in current history; preserve it for reconciliation');
      requireValue(session.epoch === source, 'Saved removal was superseded before its acceptance was verified; preserve it for reconciliation');
      const outer = envelope(wire);
      requireValue(outer.expiry_ts >= Math.floor(Date.now() / 1000), 'Saved removal expired before its acceptance was verified; preserve it for reconciliation');
      let event: ReturnType<typeof receiveGroupEvent>;
      try { event = receiveGroupEvent(identity, outer, session); }
      catch { throw new Error('Saved removal cannot be verified against the current branch; preserve it for reconciliation'); }
      if (!event.duplicate) this.assertRemovalTargetCurrent(session, intent, QntmGroupStore.removedMembers(event.message));
      return operation;
    }
    if (session.epoch > source) return operation; // A verified rotation already left the removal's epoch: local cleanup only.
    requireValue(session.needsRekey, 'Accepted removal is not awaiting its completing rotation; preserve it for reconciliation');
    assertGroupCanSend(identity, { ...session, needsRekey: false });
    try { this.assertRotationCurrent(session, operation.controls[operation.phase === 'removal_rekey' ? 0 : 1], operation.expected); return operation; }
    catch { /* Review a fresh rotation for the current remaining roster. */ }
    const origin: RemovalOrigin = removalOrigin(operation) ?? { kind: 'remove', controls: [...operation.controls], welcomes: [], sentControls: operation.sentControls,
      sentWelcomes: 0, ...(operation.target ? { target: operation.target } : {}), delivery: 'unknown' };
    const next = this.rotationJournal(session, { ...operation, phase: 'removal_rekey', origin, target: undefined,
      superseded: operation.phase === 'removal_rekey' ? this.retainSuperseded(operation) : operation.superseded });
    this.checkEvidence(next); return next;
  }
  /** Keep an exact rotation, finish a fulfilled one, or renew a still-current intent. */
  private prepareRotationRetry(state: GroupCheckpoint, operation: GroupOperation): GroupOperation {
    const session = state.session!;
    requireValue(operation.action === 'rekey' && !operation.phase && !operation.origin && operation.controls.length === 1 && !operation.welcomes.length, 'Invalid saved rotation intent');
    const wire = operation.controls[0], outer = envelope(wire);
    requireValue(encode(outer) === wire && toHex(outer.conv_id) === this.binding.conversationId, 'Invalid saved rotation context');
    if (this.controlAccepted(state, wire)) return operation;
    assertGroupCanSend(this.account.identity!, { ...session, needsRekey: false });
    if (session.epoch > outer.conv_epoch) return operation; // Any verified later rotation fulfils a standalone rotation intent.
    try { this.assertRotationCurrent(session, wire, operation.expected); return operation; }
    catch { /* Review a replacement rotation for the current roster. */ }
    const next = this.rotationJournal(session, { ...operation, superseded: this.retainSuperseded(operation) });
    this.checkEvidence(next); return next;
  }
  /** Plan only: every replacement needs a fresh concrete tool review before
   * journal writes or POST. Unknown valid delivery remains byte-for-byte exact. */
  prepareRetry(): GroupOperation {
    const state = this.load(), operation = state.operation;
    requireValue(operation, 'No saved group operation to retry');
    if (operation.welcomes.length && operation.sentWelcomes === operation.welcomes.length) return operation;
    this.checkContact(operation);
    if (operation.action === 'remove' || operation.action === 'rekey') {
      requireValue(state.session, 'Missing group checkpoint');
      return operation.action === 'remove' ? this.prepareRemovalRetry(state, operation) : this.prepareRotationRetry(state, operation);
    }
    if (operation.action === 'refresh' && operation.welcomePurpose !== 'renewal') return this.prepareGenericRetry(state, operation);
    if (operation.action !== 'add' && operation.welcomePurpose !== 'renewal') return operation;
    requireValue(state.session && operation.publicKey, 'Missing group checkpoint or recipient');
    const recipient = base64UrlDecode(operation.publicKey), kid = toHex(keyIDFromPublicKey(recipient));
    const proof = operation.action === 'add' ? this.additionProof(state, operation) : undefined;
    if (operation.action === 'add' && !proof) {
      requireValue(!operation.origin && !state.session.needsRekey && !state.session.admissions[kid]
        && state.session.epoch === envelope(operation.controls[0]).conv_epoch,
      'Original addition is no longer the current admission; preserve it for reconciliation');
      return operation;
    }
    if (proof && !proof.admission.completion) {
      assertGroupCanSend(this.account.identity!, { ...state.session, needsRekey: false });
      requireValue(state.session.needsRekey && proof.admission.sourceEpoch === state.session.epoch,
        'Original admission is not awaiting its completing rotation');
      try { this.assertPendingRotation(state, operation); return operation; } catch { /* Review a new rotation from current verified roster. */ }
      const challenge = this.additionChallenge(operation), rotation = prepareGroupSessionRekey(this.account.identity!, state.session);
      const trial = receiveGroupEvent(this.account.identity!, rotation.rekey, state.session).state;
      const next: GroupOperation = { ...operation, phase: 'addition_rekey', welcomePurpose: undefined, recoveryChallenge: challenge,
        origin: this.originalAddition(operation, proof.expected), controls: [encode(rotation.rekey)], welcomes: [], sentControls: 0, sentWelcomes: 0,
        expected: createGroupSession(this.account.identity!, rotation.conversation, rotation.state,
          { signedEpoch: state.session.signedEpoch, admissions: trial.admissions }),
        superseded: operation.phase ? this.retainSuperseded(operation) : operation.superseded };
      this.checkEvidence(next); return next;
    }
    assertGroupCanSend(this.account.identity!, state.session);
    const saved = restoreGroupSession(this.account.identity!, operation.expected);
    const expected = proof?.expected ?? saved.admissions[kid];
    const current = state.session.admissions[kid];
    requireValue(expected && current?.completion && current.addId === expected.addId && current.addDigest === expected.addDigest,
      'Original addition is no longer the current admission; preserve it for reconciliation');
    try {
      if (operation.phase) throw new Error('Verified rotation still requires current welcome review');
      if (operation.welcomePurpose === 'renewal') this.assertRenewal(state, operation);
      else this.assertExactAddition(state, operation);
      return operation;
    } catch { /* Same completed admission permits a newly reviewed current-key renewal. */ }
    const challenge = operation.action === 'add' ? this.additionChallenge(operation) : operation.recoveryChallenge;
    const renewed = prepareGroupAdmissionRenewal(this.account.identity!, state.session, recipient,
      { addId: expected.addId, addDigest: expected.addDigest }, undefined,
      challenge ? new Uint8Array(Buffer.from(challenge, 'hex')) : undefined, state.cursor);
    const next: GroupOperation = { ...operation, phase: undefined, welcomePurpose: 'renewal', recoveryChallenge: challenge,
      controls: [], sentControls: 0, welcomes: renewed.welcomes.map(encode), sentWelcomes: 0,
      expected: createGroupSession(this.account.identity!, renewed.conversation, renewed.state,
        { signedEpoch: state.session.signedEpoch, admissions: renewed.admissions }),
      origin: operation.action === 'add' ? this.originalAddition(operation, expected) : operation.origin,
      superseded: operation.origin || operation.welcomePurpose === 'renewal' ? this.retainSuperseded(operation) : operation.superseded };
    this.checkEvidence(next); return next;
  }
  /** Caller owns writer lock and has matched the complete review fingerprint. */
  saveRetry(operation: GroupOperation): void {
    const state = this.load();
    requireValue(state.operation?.id === operation.id, 'Pending operation changed before retry');
    state.operation = operationSchema.parse(operation);
    // Superseded controls keep only their flat 'unknown' evidence; receipts follow
    // the exact pending wires, including a repair's original accepted removal.
    state.controlReceipts = QntmGroupStore.receiptsFor(state.controlReceipts, receiptWires(state.operation)); this.save(state);
  }
  /** Caller owns the writer lock through replay, every POST and its journal write. */
  async resume(): Promise<number | undefined> {
    let publishedSequence: number | undefined;
    await this.sync();
    let state = this.load(), operation = state.operation;
    requireValue(operation, 'No saved group operation to retry');
    // This is only local journal cleanup. Acknowledged welcomes need no new
    // network publication or current membership authority after a later change.
    if (operation.welcomes.length && operation.sentWelcomes === operation.welcomes.length) {
      state.operation = null; state.controlReceipts = []; this.save(state); return;
    }
    requireValue(state.session && !state.session.recovery && !state.session.removed, 'No retryable group operation or recovery is required');
    this.checkContact(operation);
    if ((operation.action === 'remove' || operation.action === 'rekey') && this.fulfilled(state, operation)) {
      state.operation = null; state.controlReceipts = []; this.save(state); return;
    }
    if (operation.phase === 'removal_rekey') {
      const { wire: removal, source } = this.removalIntent(operation);
      if (!this.controlAccepted(state, operation.controls[0])) {
        // Release only while the proven removal still awaits its rotation; an
        // ACK installs no keys and only exact replay can finish the journal.
        requireValue(this.controlAccepted(state, removal), 'Original removal is no longer verified in current history; preserve it for reconciliation');
        requireValue(state.session.epoch === source && state.session.needsRekey, 'Accepted removal is not awaiting its completing rotation; preserve it for reconciliation');
        assertGroupCanSend(this.account.identity!, { ...state.session, needsRekey: false });
        this.assertRotationCurrent(state.session, operation.controls[0], operation.expected);
        publishedSequence = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(operation.controls[0]));
        state = this.load();
        requireValue(state.operation && digest(state.operation) === digest(operation), 'Pending operation changed during rotation release');
        operation = state.operation; operation.sentControls = 1; this.save(state);
      }
      await this.sync(); state = this.load(); operation = state.operation!;
      requireValue(state.session && !state.session.recovery && this.fulfilled(state, operation),
        'Completing rotation is not verified in replay; preserve the operation and retry');
      state.operation = null; state.controlReceipts = []; this.save(state); return publishedSequence;
    }
    if (operation.phase === 'addition_rekey') {
      let proof = this.additionProof(state, operation);
      requireValue(proof, 'Original addition is no longer the current admission');
      if (!proof.admission.completion) {
        this.assertPendingRotation(state, operation);
        // No ACK receipt advances control coverage or installs predicted keys.
        // Even an acknowledged repair with no replay remains exact-retry-only.
        await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(operation.controls[0]));
        state = this.load();
        requireValue(state.operation && digest(state.operation) === digest(operation), 'Pending operation changed during rotation release');
        operation = state.operation; operation.sentControls = 1; this.save(state);
        await this.sync(); state = this.load(); proof = this.additionProof(state, operation);
      }
      requireValue(state.session && !state.session.recovery && proof?.admission.completion,
        'Completing rotation is not verified in replay; preserve the operation and retry');
      assertGroupCanSend(this.account.identity!, state.session);
      // Keep exact repair evidence. A second reviewed retry prepares a welcome
      // from this fully replayed cursor, including a competing canonical winner.
      return;
    }
    for (; operation.sentControls < operation.controls.length;) {
      const wire = operation.controls[operation.sentControls], outer = envelope(wire);
      await this.sync(); state = this.load();
      requireValue(state.session && state.operation && digest(state.operation) === digest(operation), 'Pending operation changed during replay');
      const proof = operation.action === 'add' && !operation.origin ? this.additionProof(state, operation) : undefined;
      const proven = Boolean(proof && (operation.sentControls === 0 || proof.admission.completion));
      if (!proven) {
        if (operation.action === 'add') {
          assertGroupCanSend(this.account.identity!, { ...state.session, needsRekey: false });
          if (operation.sentControls === 0) requireValue(!state.session.needsRekey && state.session.epoch === outer.conv_epoch
            && !state.session.admissions[toHex(keyIDFromPublicKey(base64UrlDecode(operation.publicKey!)))],
          'Original addition is no longer safe to publish; preserve it for reconciliation');
          else requireValue(proof, 'Original addition is no longer the current admission');
        }
        // Receiver support for delayed competing rekeys is not permission to
        // publish a newly obsolete local operation. Only exact replay can skip it.
        if (!this.controlAccepted(state, wire)) {
          requireValue(outer.conv_epoch === state.session.epoch, 'Unaccepted saved control targets an obsolete epoch; preserve it for reconciliation');
          requireValue(outer.expiry_ts >= Math.floor(Date.now() / 1000), 'Saved group operation expired; preserve it for reconciliation');
          const preflight = receiveGroupEvent(this.account.identity!, outer, state.session);
          if (!preflight.duplicate) {
            if (operation.action === 'remove' && operation.sentControls === 0) this.assertRemovalTargetCurrent(state.session, operation, QntmGroupStore.removedMembers(preflight.message));
            publishedSequence = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(wire));
          }
        }
      }
      state = this.load(); operation = state.operation!; operation.sentControls++; this.save(state);
      // A helper's verified rotation may finish an accepted removal before its saved rotation is posted.
      if (operation.action === 'remove' && operation.sentControls === 1) {
        await this.sync(); state = this.load(); operation = state.operation!;
        if (this.fulfilled(state, operation)) { state.operation = null; state.controlReceipts = []; this.save(state); return publishedSequence; }
      }
    }
    await this.sync(); state = this.load(); operation = state.operation!;
    requireValue(state.session, 'Missing group checkpoint');
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    assertGroupCanSend(this.account.identity!, state.session);
    if (operation.action === 'add' && !operation.origin) this.assertExactAddition(state, operation);
    else for (const wire of operation.controls) requireValue(this.controlAccepted(state, wire), 'Exact saved control or send has not been accepted');
    // Latched receipts stay valid only while their branch is canonical, so a
    // fully receipted control set may finish after a later legitimate rotation.
    // Cache-only evidence cannot establish that lineage and stays exact.
    const receipted = operation.controls.length > 0 && !operation.welcomes.length
      && operation.controls.every(wire => this.controlReceipt(state, wire)?.valid);
    requireValue(operation.action === 'send' || state.session.root === expected.root && state.session.epoch === expected.epoch && state.session.snapshot === expected.snapshot
      || receipted && state.session.epoch > expected.epoch,
    'Pending group operation no longer matches accepted state; preserve it for reconciliation');
    const base = this.welcomeBase(operation);
    if (operation.welcomePurpose === 'renewal') this.assertRenewal(state, operation);
    else if (operation.action === 'refresh') {
      this.assertGenericRecipient(state, this.genericRefreshContext(operation).recipient);
      assertGroupWelcomeRefreshCurrent(this.account.identity!, state.session, base as GroupWelcomeRefresh);
    }
    for (; operation.sentWelcomes < operation.welcomes.length;) {
      const wire = operation.welcomes[operation.sentWelcomes];
      requireValue(envelope(wire).expiry_ts >= Math.floor(Date.now() / 1000), 'Saved welcome expired; preserve the operation for reconciliation');
      const receipt = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(wire));
      state = this.load(); operation = state.operation!; operation.sentWelcomes++; state.receipts.push(receipt); this.save(state);
    }
    state = this.load(); state.operation = null; state.controlReceipts = []; this.save(state);
    return publishedSequence;
  }
  async send(text: string): Promise<{ messageId: string; sequence: number }> {
    return this.exclusive(async () => {
      await this.sync(); const operation = this.prepare('send', { text }); this.saveOperation(operation);
      const sequence = await this.resume();
      requireValue(sequence !== undefined, 'Fresh send did not return a relay receipt');
      return { messageId: toHex(envelope(operation.controls[0]).msg_id), sequence };
    });
  }
  async removeOutbox(id: string): Promise<void> {
    await this.exclusive(async () => { const state = this.load(); state.outbox = state.outbox.filter(item => inboundId(item) !== id); this.save(state); });
  }
}
