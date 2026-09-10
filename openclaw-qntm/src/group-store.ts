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
  prepareGroupAdmissionRenewal, assertGroupAdmissionRenewalCurrent,
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
const originalAdditionSchema = z.object({
  controls: z.array(z.string().max(128 * 1024)).length(2), welcomes: z.array(z.string().max(128 * 1024)).length(1),
  sentControls: seq.max(2), sentWelcomes: seq.max(1), recipient: z.string(),
  addId: z.string().regex(/^[0-9a-f]{32}$/), addDigest: z.string().regex(/^[0-9a-f]{64}$/), delivery: z.literal('unknown'),
}).strict();
const operationSchema = z.object({
  id: z.string().regex(/^[0-9a-f]{32}$/), action: z.enum(['add', 'remove', 'refresh', 'rekey', 'send']),
  contact: z.string().optional(), publicKey: z.string().optional(), text: z.string().optional(),
  origin: originalAdditionSchema.optional(),
  welcomePurpose: z.enum(['refresh', 'renewal']).optional(), recoveryChallenge: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  expected: z.unknown(), controls: z.array(z.string().max(128 * 1024)).max(2),
  welcomes: z.array(z.string().max(128 * 1024)).max(1), sentControls: seq.max(2), sentWelcomes: seq.max(1),
}).strict();
export type GroupOperation = z.infer<typeof operationSchema>;
const schema = z.object({
  version: z.literal(1), seed: z.string().regex(/^[0-9a-f]{64}$/), revision: seq,
  cursor: seq, bootstrap: seq, session: z.unknown().nullable(),
  pending: z.array(rowSchema).max(256), outbox: z.array(z.unknown()).max(MAX_PENDING_DISPATCHES),
  receipts: z.array(seq.min(1)).max(8192), operation: operationSchema.nullable(), removedSequence: seq,
  dispatchGeneration: z.string().regex(/^[0-9a-f]{32}$/).optional(),
}).strict();
export type GroupRow = z.infer<typeof rowSchema>;
export interface GroupCheckpoint extends Omit<z.infer<typeof schema>, 'session' | 'outbox' | 'dispatchGeneration'> {
  session: GroupSessionState | null; outbox: QntmInbound[]; dispatchGeneration: string;
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
        pending: [], outbox: [], receipts: [], operation: null, removedSequence: 0, dispatchGeneration: dispatchGeneration() };
    }
    const parsed = schema.parse(JSON.parse(raw.toString('utf8')));
    requireValue(parsed.seed === this.seed, 'Group checkpoint identity or initial configuration changed; preserve and inspect its private file');
    const session = parsed.session ? restoreGroupSession(this.account.identity!, parsed.session) : null;
    requireValue(!session || session.conversationId === this.binding.conversationId, 'Group checkpoint conversation mismatch');
    const outbox = parsed.outbox.map(validateInbound);
    requireValue(outbox.every(item => item.conversationId === this.binding.conversationId), 'Group dispatch conversation mismatch');
    if (parsed.operation) restoreGroupSession(this.account.identity!, parsed.operation.expected);
    return { ...parsed, session, outbox, dispatchGeneration: parsed.dispatchGeneration ?? dispatchGeneration() };
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
    const wire = base64UrlDecode(operation.controls[0]), outer = deserializeEnvelope(wire);
    if (state.session.seen[toHex(outer.msg_id)]?.digest !== toHex(new QSP1Suite().hash(wire))) return false;
    state.operation = null; this.save(state); return true;
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
    let welcomePurpose: GroupOperation['welcomePurpose'];
    if (action === 'add' || action === 'refresh') {
      const admission = recipient && session.admissions[toHex(keyIDFromPublicKey(recipient))];
      welcomePurpose = action === 'refresh' ? admission?.completion ? 'renewal' : 'refresh' : undefined;
      const value = action === 'add' ? prepareGroupSessionAddition(identity, session, [recipient!], undefined, challenge, state.cursor)
        : welcomePurpose === 'renewal' ? prepareGroupAdmissionRenewal(identity, session, recipient!,
          { addId: admission!.addId, addDigest: admission!.addDigest }, undefined, challenge, state.cursor)
          : prepareGroupWelcomeRefresh(identity, session, [recipient!], undefined, challenge, state.cursor);
      expected = createGroupSession(identity, value.conversation, value.state, { signedEpoch: session.signedEpoch,
        ...(welcomePurpose === 'renewal' ? { admissions: (value as GroupAdmissionRenewal).admissions } : {}) });
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
      welcomePurpose, recoveryChallenge: options.challenge,
      expected, controls: controls.map(encode), welcomes: welcomes.map(encode), sentControls: 0, sentWelcomes: 0 };
  }
  saveOperation(operation: GroupOperation): void {
    const state = this.load(); requireValue(!state.operation, 'An exact group operation is already pending');
    state.operation = operationSchema.parse(operation); this.save(state);
  }
  private additionProof(state: GroupCheckpoint, operation: GroupOperation) {
    requireValue(operation.action === 'add' && !operation.origin && operation.controls.length === 2
      && operation.publicKey && state.session, 'Invalid original addition journal');
    const wire = base64UrlDecode(operation.controls[0]), addition = deserializeEnvelope(wire);
    requireValue(encode(addition) === operation.controls[0] && toHex(addition.conv_id) === this.binding.conversationId,
      'Saved addition context is invalid');
    const recipient = base64UrlDecode(operation.publicKey), kid = toHex(keyIDFromPublicKey(recipient));
    const expected = { addId: toHex(addition.msg_id), addDigest: toHex(new QSP1Suite().hash(wire)) };
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
    const identity = this.account.identity!, outer = envelope(operation.welcomes[0]);
    const plain = openSecret(identity.privateKey, base64UrlDecode(operation.publicKey!), outer.ciphertext);
    const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain), payload = signed.payload;
    const { ciphertext: _ciphertext, ...header } = outer;
    const same = (a: unknown, b: unknown) => toHex(marshalCanonical(a)) === toHex(marshalCanonical(b));
    requireValue(toHex(plain) === toHex(marshalCanonical(signed))
      && payload.proto === 'qntm/group-welcome/v1' && same(payload.inviter_ik_pk, identity.publicKey)
      && same(payload.recipient_ik_pk, base64UrlDecode(operation.publicKey!))
      && toHex(outer.conv_id) === this.binding.conversationId
      && same(payload.addition_id, envelope(operation.controls[0]).msg_id)
      && same(payload.rekey_id, envelope(operation.controls[1]).msg_id) && same(payload.envelope, header)
      && new QSP1Suite().verify(identity.publicKey, marshalCanonical(payload), signed.signature), 'Invalid saved welcome challenge binding');
    const challenge = payload.recovery_challenge;
    requireValue(challenge === undefined || challenge instanceof Uint8Array && challenge.length === 32, 'Invalid saved recovery challenge');
    return challenge === undefined ? undefined : toHex(challenge as Uint8Array);
  }
  /** Plan only: replacement ciphertext is reviewed before any journal or POST changes.
   * A renewed operation is exact-retry-only; repeated expiry remains blocked. */
  prepareRetry(): GroupOperation {
    const state = this.load(), operation = state.operation;
    requireValue(operation, 'No saved group operation to retry');
    if (operation.welcomes.length && operation.sentWelcomes === operation.welcomes.length) return operation;
    this.checkContact(operation);
    if (operation.action !== 'add' || operation.origin) return operation;
    const proof = this.additionProof(state, operation);
    if (!proof?.admission.completion) return operation;
    assertGroupCanSend(this.account.identity!, state.session!);
    try {
      this.assertExactAddition(state, operation);
      requireValue(operation.welcomes.every(wire => envelope(wire).expiry_ts >= Math.floor(Date.now() / 1000)), 'Expired original welcome');
      return operation;
    } catch { /* Exact completed admission permits current-key renewal, not readmission. */ }
    const challenge = this.additionChallenge(operation);
    const renewed = prepareGroupAdmissionRenewal(this.account.identity!, state.session!, proof.recipient, proof.expected,
      undefined, challenge ? new Uint8Array(Buffer.from(challenge, 'hex')) : undefined, state.cursor);
    return { ...operation, welcomePurpose: 'renewal', recoveryChallenge: challenge, controls: [], sentControls: 0,
      welcomes: renewed.welcomes.map(encode), sentWelcomes: 0,
      expected: createGroupSession(this.account.identity!, renewed.conversation, renewed.state,
        { signedEpoch: state.session!.signedEpoch, admissions: renewed.admissions }),
      origin: { controls: [...operation.controls], welcomes: [...operation.welcomes], sentControls: operation.sentControls,
        sentWelcomes: operation.sentWelcomes, recipient: operation.publicKey!, ...proof.expected, delivery: 'unknown' } };
  }
  /** Caller owns writer lock and has matched the complete review fingerprint. */
  saveRetry(operation: GroupOperation): void {
    const state = this.load();
    requireValue(state.operation?.id === operation.id, 'Pending operation changed before retry');
    state.operation = operationSchema.parse(operation); this.save(state);
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
      state.operation = null; this.save(state); return;
    }
    requireValue(state.session && !state.session.recovery && !state.session.removed, 'No retryable group operation or recovery is required');
    this.checkContact(operation);
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
        requireValue(state.session.seen[toHex(outer.msg_id)] || outer.expiry_ts >= Math.floor(Date.now() / 1000),
          'Saved group operation expired; preserve it for reconciliation');
        const preflight = receiveGroupEvent(this.account.identity!, outer, state.session);
        if (!preflight.duplicate) publishedSequence = await this.client.postMessage(this.binding.conversation.id, base64UrlDecode(wire));
      }
      state = this.load(); operation = state.operation!; operation.sentControls++; this.save(state);
    }
    await this.sync(); state = this.load(); operation = state.operation!;
    requireValue(state.session, 'Missing group checkpoint');
    const expected = restoreGroupSession(this.account.identity!, operation.expected);
    assertGroupCanSend(this.account.identity!, state.session);
    if (operation.action === 'add' && !operation.origin) this.assertExactAddition(state, operation);
    else for (const wire of operation.controls) {
      const outer = envelope(wire);
      requireValue(state.session.seen[toHex(outer.msg_id)]?.digest === toHex(new QSP1Suite().hash(base64UrlDecode(wire))), 'Exact saved control or send has not been accepted');
    }
    requireValue(operation.action === 'send' || state.session.root === expected.root && state.session.epoch === expected.epoch && state.session.snapshot === expected.snapshot,
      'Pending group operation no longer matches accepted state; preserve it for reconciliation');
    const base = this.welcomeBase(operation);
    if (operation.welcomePurpose === 'renewal') {
      requireValue(operation.publicKey, 'Saved renewal recipient is missing');
      const recipient = base64UrlDecode(operation.publicKey), admission = expected.admissions[toHex(keyIDFromPublicKey(recipient))];
      requireValue(admission?.completion, 'Saved renewal admission proof is missing');
      if (operation.origin) requireValue(operation.origin.recipient === operation.publicKey
        && operation.origin.addId === admission.addId && operation.origin.addDigest === admission.addDigest, 'Renewal differs from its original admission');
      assertGroupAdmissionRenewalCurrent(this.account.identity!, state.session,
        { ...base, recipient, admission, admissions: expected.admissions } as GroupAdmissionRenewal);
    } else if (operation.action === 'refresh') assertGroupWelcomeRefreshCurrent(this.account.identity!, state.session, base as GroupWelcomeRefresh);
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
