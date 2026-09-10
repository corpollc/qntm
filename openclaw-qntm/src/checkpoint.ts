import path from 'node:path';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  addParticipant, base64UrlDecode, base64UrlEncode, createGatewaySession, inviteFromURL,
  keyIDFromPublicKey, parseGatewayBody, validateGatewayContext,
  type Conversation, type GatewaySessionState,
} from '@corpollc/qntm';
import { normalizeAccountId } from 'openclaw/plugin-sdk/account-id';
import { resolveStateDir } from 'openclaw/plugin-sdk/state-paths';
import { parseStoredConversationRecord, toHex } from './qntm.js';
import { readConversationCursor } from './state.js';
import { readBoundedFile, writePrivateJSON } from './storage.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding } from './types.js';

const hex16 = z.string().regex(/^[0-9a-f]{32}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const epoch = z.number().int().min(0).max(0xffffffff);
const sequence = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const MAX_PENDING_DISPATCHES = 64;
export const MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024;
const InboundSchema = z.object({
  conversationId: hex16, messageId: hex16, senderKid: hex16,
  senderPublicKey: z.string().max(44), epoch, createdAt: sequence,
  bodyType: z.string().min(1).max(128), text: z.string().max(65536),
  gatewayVerified: z.boolean(),
  // Private ordinary-group delivery authority; never part of a qntm event ID.
  groupDispatch: z.object({ generation: hex16, digest }).strict().optional(),
}).strict();
export type QntmInbound = z.infer<typeof InboundSchema>;
export interface QntmCheckpoint {
  version: 1;
  seedHash: string;
  identityKid: string;
  cursor: number;
  /** Legacy cursor suppresses old wakeups while available protocol history is replayed. */
  suppressThrough: number;
  conversation: Conversation;
  session: GatewaySessionState;
  outbox: QntmInbound[];
}
const SessionSchema = z.object({
  version: z.literal(1), participants: z.record(z.string(), z.string()),
  gateway: z.object({
    accepted: z.boolean(), context: z.unknown(),
    invitation: z.object({ messageId: hex16, text: z.string().max(65536), body: z.unknown() }).strict(),
  }).strict().optional(),
  removed: z.boolean(), events: z.array(z.object({
    body: z.unknown(), senderKid: z.string().max(24), conversationId: hex16,
    epoch, messageId: hex16, createdAt: sequence,
  }).strict()).max(4096),
  seen: z.record(hex16, digest),
}).strict();
const CheckpointSchema = z.object({
  version: z.literal(1), seedHash: digest, identityKid: hex16, cursor: sequence, suppressThrough: sequence,
  conversation: z.unknown(), session: SessionSchema, outbox: z.array(InboundSchema).max(MAX_PENDING_DISPATCHES),
}).strict();

export function validateInbound(value: unknown): QntmInbound {
  const message = InboundSchema.parse(value);
  const key = base64UrlDecode(message.senderPublicKey);
  if (key.length !== 32 || toHex(keyIDFromPublicKey(key)) !== message.senderKid
    || Buffer.byteLength(message.text) > 65536) throw new Error('Invalid persisted qntm message');
  return message;
}
export function inboundId(message: QntmInbound): string {
  const id = `${message.conversationId}:${message.messageId}`;
  return message.groupDispatch ? `${id}:group:${message.groupDispatch.generation}:${message.groupDispatch.digest}` : id;
}
function conversationJSON(conversation: Conversation) {
  return {
    id: toHex(conversation.id), type: conversation.type,
    keys: { root: toHex(conversation.keys.root), aeadKey: toHex(conversation.keys.aeadKey), nonceKey: toHex(conversation.keys.nonceKey) },
    participants: conversation.participants.map(toHex), currentEpoch: conversation.currentEpoch,
    createdAt: conversation.createdAt.toISOString(),
  };
}
function seedHash(account: ResolvedQntmAccount, binding: ResolvedQntmBinding): string {
  return createHash('sha256').update(JSON.stringify({
    relay: account.relayUrl.replace(/\/$/, ''), identity: toHex(account.identity!.publicKey),
    conversation: binding.conversationId, type: binding.conversation.type,
    epoch: binding.conversation.currentEpoch, keys: [binding.conversation.keys.root, binding.conversation.keys.aeadKey, binding.conversation.keys.nonceKey].map(toHex),
  })).digest('hex');
}

export class QntmCheckpointStore {
  constructor(readonly account: ResolvedQntmAccount, private readonly options: {
    stateDir?: string;
    write?: typeof writePrivateJSON;
  } = {}) {
    if (!account.identity) throw new Error('qntm identity is not configured');
  }

  path(binding: ResolvedQntmBinding): string {
    hex16.parse(binding.conversationId);
    return path.join(this.options.stateDir ?? resolveStateDir(), 'plugins', 'qntm', 'accounts',
      normalizeAccountId(this.account.accountId), 'conversations', `${binding.conversationId}.json`);
  }

  load(binding: ResolvedQntmBinding): QntmCheckpoint {
    let raw: Buffer;
    try { raw = readBoundedFile(this.path(binding), MAX_CHECKPOINT_BYTES); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const conversation = structuredClone(binding.conversation);
      addParticipant(conversation, this.account.identity!.publicKey);
      const publicKeys = [this.account.identity!.publicKey];
      if (binding.invite) {
        const inviter = inviteFromURL(binding.invite).inviter_ik_pk;
        if (conversation.participants.some(kid => toHex(kid) === toHex(keyIDFromPublicKey(inviter)))) publicKeys.push(inviter);
      }
      return {
        version: 1, seedHash: seedHash(this.account, binding), identityKid: toHex(this.account.identity!.keyID),
        cursor: 0, suppressThrough: readConversationCursor({ accountId: this.account.accountId,
          conversationId: binding.conversationId, stateDir: this.options.stateDir }),
        conversation, session: createGatewaySession(conversation, publicKeys), outbox: [],
      };
    }
    try {
      const parsed = CheckpointSchema.parse(JSON.parse(raw.toString('utf8')));
      if (parsed.seedHash !== seedHash(this.account, binding) || parsed.identityKid !== toHex(this.account.identity!.keyID)) {
        throw new Error('checkpoint belongs to another identity or configuration');
      }
      const conversation = parseStoredConversationRecord(parsed.conversation as Parameters<typeof parseStoredConversationRecord>[0]);
      if (toHex(conversation.id) !== binding.conversationId) throw new Error('conversation mismatch');
      const session = parsed.session as GatewaySessionState;
      if (Object.keys(session.participants).length > 1000 || Object.keys(session.seen).length > 8192) throw new Error('state limit exceeded');
      for (const [kid, publicKey] of Object.entries(session.participants)) {
        const key = base64UrlDecode(publicKey);
        if (key.length !== 32 || base64UrlEncode(keyIDFromPublicKey(key)) !== kid) throw new Error('participant mismatch');
      }
      if (session.gateway) {
        validateGatewayContext(session.gateway.context);
        if (session.gateway.context.conversationId !== binding.conversationId
          || (session.gateway.accepted && session.gateway.context.epoch !== conversation.currentEpoch)) throw new Error('gateway context mismatch');
        const invite = parseGatewayBody('gate.promote', session.gateway.invitation.text);
        if (JSON.stringify(invite) !== JSON.stringify(session.gateway.invitation.body)) throw new Error('invitation mismatch');
      }
      for (const event of session.events) {
        if (event.conversationId !== binding.conversationId) throw new Error('event mismatch');
        parseGatewayBody(event.body.type, JSON.stringify(event.body));
      }
      const outbox = parsed.outbox.map(validateInbound);
      if (outbox.some(message => message.conversationId !== binding.conversationId)
        || new Set(outbox.map(inboundId)).size !== outbox.length) throw new Error('outbox mismatch');
      return { ...parsed, conversation, session, outbox };
    } catch { throw new Error('Invalid qntm checkpoint; preserve the file and inspect the local configuration before retrying'); }
  }

  commit(binding: ResolvedQntmBinding, checkpoint: QntmCheckpoint): void {
    sequence.parse(checkpoint.cursor);
    if (checkpoint.seedHash !== seedHash(this.account, binding) || checkpoint.identityKid !== toHex(this.account.identity!.keyID)
      || toHex(checkpoint.conversation.id) !== binding.conversationId || checkpoint.outbox.length > MAX_PENDING_DISPATCHES) {
      throw new Error('qntm checkpoint identity/configuration changed or dispatch queue is full');
    }
    const value = { ...checkpoint, conversation: conversationJSON(checkpoint.conversation), session: structuredClone(checkpoint.session) };
    // Old workflow history can be forgotten; it can never authorize a new vote
    // once its verified request/proposal has been evicted. Keep the recent tail.
    while (Buffer.byteLength(JSON.stringify(value.session.events)) > 8 * 1024 * 1024) value.session.events.splice(0, 64);
    (this.options.write ?? writePrivateJSON)(this.path(binding), value, MAX_CHECKPOINT_BYTES);
  }

  removeOutbox(binding: ResolvedQntmBinding, id: string): void {
    const state = this.load(binding);
    state.outbox = state.outbox.filter(message => inboundId(message) !== id);
    this.commit(binding, state);
  }
}
