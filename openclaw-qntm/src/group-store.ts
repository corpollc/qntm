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
  restoreGroupSession, groupSessionConversation, checkGroupReplayCoverage, checkExpiredGroupControl,
  receiveGroupEvent, requireGroupRecovery, openGroupWelcome, groupSessionFromWelcome, parseGroupLink, createGroupLink,
  assertGroupCanSend, prepareGroupSessionAddition, prepareGroupWelcomeRefresh, prepareGroupSessionRekey,
  assertGroupAdditionAccepted, assertGroupWelcomeRefreshCurrent, createGroupControlMessage, createGroupRemoveBody,
  createGroupSession, createMessage, keyIDFromPublicKey, unmarshalCanonical,
  type GroupSessionState, type GroupAddition, type GroupWelcomeRefresh, type OuterEnvelope,
} from '@corpollc/qntm';
import { readBoundedFile, writePrivateJSON } from './storage.js';
import { validateInbound, inboundId, MAX_PENDING_DISPATCHES, type QntmInbound } from './checkpoint.js';
import { decodeContactKey } from './accounts.js';
import { toHex } from './qntm.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding, QntmGroupAction } from './types.js';

const seq = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const rowSchema = z.object({ seq: seq.min(1), wire: z.string().max(128 * 1024) }).strict();
const operationSchema = z.object({
  id: z.string().regex(/^[0-9a-f]{32}$/), action: z.enum(['add', 'remove', 'refresh', 'rekey', 'send']),
  contact: z.string().optional(), publicKey: z.string().optional(), text: z.string().optional(),
  expected: z.unknown(), controls: z.array(z.string().max(128 * 1024)).max(2),
  welcomes: z.array(z.string().max(128 * 1024)).max(1), sentControls: seq.max(2), sentWelcomes: seq.max(1),
}).strict();
export type GroupOperation = z.infer<typeof operationSchema>;
const schema = z.object({
  version: z.literal(1), seed: z.string().regex(/^[0-9a-f]{64}$/), revision: seq,
  cursor: seq, bootstrap: seq, session: z.unknown().nullable(),
  pending: z.array(rowSchema).max(256), outbox: z.array(z.unknown()).max(MAX_PENDING_DISPATCHES),
  receipts: z.array(seq.min(1)).max(8192), operation: operationSchema.nullable(), removedSequence: seq,
}).strict();
export type GroupRow = z.infer<typeof rowSchema>;
export interface GroupCheckpoint extends Omit<z.infer<typeof schema>, 'session' | 'outbox'> {
  session: GroupSessionState | null; outbox: QntmInbound[];
}
/** Pending host jobs are rechecked immediately before entering the agent. */
export function groupDispatchDisposition(state: GroupCheckpoint, messageId: string): 'dispatch' | 'defer' | 'discard' {
  if (state.session?.removed) return 'discard';
  if (!state.session || state.session.recovery || state.session.needsRekey || state.operation) return 'defer';
  return state.session.seen[messageId] ? 'dispatch' : 'discard';
}
export type GroupTransport = Pick<DropboxClient, 'receiveMessages' | 'postMessage'>;
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function group(state: GroupSessionState): GroupState {
  const result = new GroupState(); result.applyGenesis(unmarshalCanonical(base64UrlDecode(state.snapshot))); return result;
}
function envelope(wire: string): OuterEnvelope { return deserializeEnvelope(base64UrlDecode(wire)); }
function encode(value: OuterEnvelope): string { return base64UrlEncode(serializeEnvelope(value)); }
function requireValue(value: unknown, message: string): asserts value { if (!value) throw new Error(message); }
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
        pending: [], outbox: [], receipts: [], operation: null, removedSequence: 0 };
    }
    const parsed = schema.parse(JSON.parse(raw.toString('utf8')));
    requireValue(parsed.seed === this.seed, 'Group checkpoint identity or initial configuration changed; preserve and inspect its private file');
    const session = parsed.session ? restoreGroupSession(this.account.identity!, parsed.session) : null;
    requireValue(!session || session.conversationId === this.binding.conversationId, 'Group checkpoint conversation mismatch');
    const outbox = parsed.outbox.map(validateInbound);
    requireValue(outbox.every(item => item.conversationId === this.binding.conversationId), 'Group dispatch conversation mismatch');
    if (parsed.operation) restoreGroupSession(this.account.identity!, parsed.operation.expected);
    return { ...parsed, session, outbox };
  }
  save(state: GroupCheckpoint): void {
    requireValue(this.load().revision === state.revision, 'Concurrent group writer; reload before retrying');
    requireValue(state.pending.reduce((sum, row) => sum + base64UrlDecode(row.wire).length, 0) <= 4 * 1024 * 1024, 'Group pending ciphertext exceeds 4 MiB');
    const next = { ...state, revision: state.revision + 1 };
    schema.parse(next);
    writePrivateJSON(this.filename, next, 16 * 1024 * 1024);
    state.revision = next.revision;
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
      recovery: state.session?.recovery, pendingOperation: state.operation && { id: state.operation.id, action: state.operation.action },
      members: state.session ? group(state.session).snapshot().founding_members.map(member => ({ keyId: toHex(member.key_id), publicKey: base64UrlEncode(member.public_key) })) : [],
      contacts: Object.entries(this.account.config.contacts ?? {}).map(([name, key]) => ({ name, publicKey: base64UrlEncode(decodeContactKey(key)) })),
      groupLink: this.link(), permittedActions: this.binding.groupActions ?? [] };
  }
  /** Caller owns the writer lock. All rows, including unreadable ones, count toward coverage. */
  receive(rows: GroupRow[], head: number, replayBeforeCursor = false): void {
    const state = this.load(); seq.parse(head);
    requireValue(head >= state.cursor, 'Relay head moved behind saved group cursor');
    if (!state.session) return;
    state.session = checkGroupReplayCoverage(state.session, state.cursor, head, [...rows.map(row => row.seq), ...state.receipts.filter(value => value > state.cursor && value <= head)]);
    const pending = new Map([...state.pending, ...rows.filter(row => replayBeforeCursor || row.seq > state.cursor)].map(row => [row.seq, row]));
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
          state.session = event.state; pending.delete(sequence); progress = true;
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
                bodyType: message.inner.body_type, text, gatewayVerified: false });
              if (!state.outbox.some(item => inboundId(item) === inboundId(inbound))) state.outbox.push(inbound);
            }
          }
        } catch { /* Future or competing-branch ciphertext is bounded and revisited after progress. */ }
      }
    }
    if (state.session.recovery || state.session.removed) state.outbox = [];
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
    const candidates = rows.toSorted((a, b) => b.seq - a.seq);
    for (const row of candidates) {
      let next: GroupSessionState, replayFromSequence: number;
      try {
        const opened = openGroupWelcome(this.account.identity!, base64UrlDecode(row.wire), { inviterPublicKey: locator.inviterPublicKey, conversationId: locator.conversationId });
        if (state.removedSequence && opened.purpose === 'addition' && row.seq <= state.removedSequence) continue;
        next = groupSessionFromWelcome(this.account.identity!, opened, row.seq, state.session ?? undefined);
        replayFromSequence = opened.replayFromSequence;
      } catch { continue; }
      state.session = next; state.cursor = replayFromSequence; state.bootstrap = replayFromSequence; state.pending = []; state.outbox = [];
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
    if (action === 'add' || action === 'refresh') {
      const value = action === 'add' ? prepareGroupSessionAddition(identity, session, [recipient!], undefined, challenge, state.cursor)
        : prepareGroupWelcomeRefresh(identity, session, [recipient!], undefined, challenge, state.cursor);
      expected = createGroupSession(identity, value.conversation, value.state);
      if (action === 'add') controls = [(value as GroupAddition).addition, (value as GroupAddition).rekey];
      welcomes = value.welcomes;
    } else if (action === 'rekey') {
      const value = prepareGroupSessionRekey(identity, session); controls = [value.rekey]; expected = receiveGroupEvent(identity, value.rekey, session).state;
    } else if (action === 'remove') {
      assertGroupCanSend(identity, session);
      const remove = createGroupControlMessage(identity, groupSessionConversation(session), 'group_remove', createGroupRemoveBody([keyIDFromPublicKey(recipient!)]));
      const removed = receiveGroupEvent(identity, remove, session).state;
      const value = prepareGroupSessionRekey(identity, removed); controls = [remove, value.rekey]; expected = receiveGroupEvent(identity, value.rekey, removed).state;
    } else {
      assertGroupCanSend(identity, session);
      requireValue(typeof options.text === 'string' && options.text.length > 0 && Buffer.byteLength(options.text) <= 65536, 'Text must contain 1–65536 UTF-8 bytes');
      controls = [createMessage(identity, groupSessionConversation(session), 'text', new TextEncoder().encode(options.text))];
    }
    return { id: randomUUID().replaceAll('-', ''), action, contact, publicKey: recipient && base64UrlEncode(recipient), text: options.text,
      expected, controls: controls.map(encode), welcomes: welcomes.map(encode), sentControls: 0, sentWelcomes: 0 };
  }
  saveOperation(operation: GroupOperation): void {
    const state = this.load(); requireValue(!state.operation, 'An exact group operation is already pending');
    state.operation = operationSchema.parse(operation); this.save(state);
  }
  async resume(): Promise<number | undefined> {
    let publishedSequence: number | undefined;
    await this.sync();
    let state = this.load(), operation = state.operation;
    requireValue(operation && state.session && !state.session.recovery && !state.session.removed, 'No retryable group operation or recovery is required');
    if (operation.contact) requireValue(this.account.config.contacts?.[operation.contact]
      && base64UrlEncode(decodeContactKey(this.account.config.contacts[operation.contact])) === operation.publicKey, 'Pending operation contact pin changed; preserve it for reconciliation');
    for (; operation.sentControls < operation.controls.length;) {
      const wire = operation.controls[operation.sentControls], outer = envelope(wire);
      requireValue(outer.expiry_ts >= Math.floor(Date.now() / 1000), 'Saved group operation expired; preserve it for reconciliation');
      await this.sync(); state = this.load();
      requireValue(state.session, 'Missing group checkpoint');
      // Validate the exact pending control against freshly replayed state before
      // publishing it. A verified ambiguous POST needs no second publication.
      const preflight = receiveGroupEvent(this.account.identity!, outer, state.session);
      if (!preflight.duplicate) publishedSequence = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(wire));
      state = this.load(); operation = state.operation!; operation.sentControls++; this.save(state);
    }
    await this.sync(); state = this.load(); operation = state.operation!;
    requireValue(state.session, 'Missing group checkpoint');
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    assertGroupCanSend(this.account.identity!, state.session);
    requireValue(state.session.root === expected.root && state.session.epoch === expected.epoch && state.session.snapshot === expected.snapshot, 'Pending group operation no longer matches accepted state; preserve it for reconciliation');
    for (const wire of operation.controls) {
      const outer = envelope(wire);
      requireValue(state.session.seen[toHex(outer.msg_id)]?.digest === toHex(new QSP1Suite().hash(base64UrlDecode(wire))), 'Exact saved control or send has not been accepted');
    }
    const base = { conversation: groupSessionConversation(expected), state: group(expected), welcomes: operation.welcomes.map(envelope) };
    if (operation.action === 'add') assertGroupAdditionAccepted(this.account.identity!, state.session,
      { ...base, addition: envelope(operation.controls[0]), rekey: envelope(operation.controls[1]) } as GroupAddition);
    if (operation.action === 'refresh') assertGroupWelcomeRefreshCurrent(this.account.identity!, state.session, base as GroupWelcomeRefresh);
    for (; operation.sentWelcomes < operation.welcomes.length;) {
      const wire = operation.welcomes[operation.sentWelcomes];
      requireValue(envelope(wire).expiry_ts >= Math.floor(Date.now() / 1000), 'Saved welcome expired; preserve the operation for reconciliation');
      const receipt = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(wire));
      state = this.load(); operation = state.operation!; operation.sentWelcomes++; state.receipts.push(receipt); this.save(state);
    }
    state = this.load(); state.operation = null; this.save(state);
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
