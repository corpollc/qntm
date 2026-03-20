/**
 * Integration test harness for multi-agent gateway scenarios.
 *
 * Manages:
 * - Isolated CLI agent profiles via unique temp config dirs
 * - In-memory dropbox relay for message routing
 * - Deterministic API fixtures for testing
 * - Transcript wait helpers
 * - Cleanup on test teardown
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateIdentity,
  keyIDFromPublicKey,
  base64UrlEncode,
  createInvite,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  createMessage,
  decryptMessage,
  serializeEnvelope,
  deserializeEnvelope,
  defaultTTL,
  buildSignedReceipt,
} from '@corpollc/qntm';
import type { Identity, Conversation, ReadReceiptPayload } from '@corpollc/qntm';

// ---- In-memory dropbox relay ----

interface StoredEnvelope {
  seq: number;
  data: Uint8Array;
}

// Match the shipped clients: creators only know themselves until peers are learned locally.
const MIN_RECEIPT_ACKS = 2;

export class InMemoryRelay {
  private conversations = new Map<string, StoredEnvelope[]>();
  private heads = new Map<string, number>();
  /** receipts[convId][msgIdHex] = Set of reader_kid hex strings */
  private receipts = new Map<string, Map<string, Set<string>>>();

  post(convIdHex: string, envelope: Uint8Array): number {
    const messages = this.conversations.get(convIdHex) || [];
    const seq = (this.heads.get(convIdHex) || 0) + 1;
    messages.push({ seq, data: envelope });
    this.conversations.set(convIdHex, messages);
    this.heads.set(convIdHex, seq);
    return seq;
  }

  poll(convIdHex: string, fromSeq: number, maxMessages = 200): { messages: Uint8Array[]; sequence: number } {
    const messages = this.conversations.get(convIdHex) || [];
    const head = this.heads.get(convIdHex) || 0;
    let upToSeq = head;
    if (upToSeq < fromSeq) {
      upToSeq = fromSeq;
    }
    if (maxMessages > 0 && fromSeq + maxMessages < upToSeq) {
      upToSeq = fromSeq + maxMessages;
    }
    const visible = messages.filter(m => m.seq > fromSeq && m.seq <= upToSeq);
    return {
      messages: visible.map(m => m.data),
      sequence: upToSeq,
    };
  }

  /**
   * Record a read receipt. Returns whether the message was deleted
   * (i.e. unique readers >= required_acks).
   */
  submitReceipt(payload: ReadReceiptPayload): { recorded: boolean; deleted: boolean; receipts: number } {
    const convId = payload.conv_id.toLowerCase();
    const msgId = payload.msg_id.toLowerCase();
    const readerKid = payload.reader_kid.toLowerCase();

    if (!this.receipts.has(convId)) {
      this.receipts.set(convId, new Map());
    }
    const convReceipts = this.receipts.get(convId)!;
    if (!convReceipts.has(msgId)) {
      convReceipts.set(msgId, new Set());
    }
    const readers = convReceipts.get(msgId)!;
    readers.add(readerKid);

    const shouldDelete = readers.size >= payload.required_acks;
    if (shouldDelete) {
      // Remove the message from the conversation
      const messages = this.conversations.get(convId);
      if (messages) {
        // Find and remove the message by deserializing to match msg_id
        const idx = messages.findIndex(m => {
          try {
            const env = deserializeEnvelope(m.data);
            return bytesToHex(env.msg_id).toLowerCase() === msgId;
          } catch { return false; }
        });
        if (idx !== -1) {
          messages.splice(idx, 1);
        }
      }
      convReceipts.delete(msgId);
    }

    return { recorded: true, deleted: shouldDelete, receipts: readers.size };
  }

  /** Count messages currently stored for a conversation */
  messageCount(convIdHex: string): number {
    return (this.conversations.get(convIdHex) || []).length;
  }

  clear(): void {
    this.conversations.clear();
    this.heads.clear();
    this.receipts.clear();
  }
}

// ---- CLI agent profile ----

export class CLIAgent {
  readonly name: string;
  readonly identity: Identity;
  readonly kidHex: string;
  readonly kidB64: string;
  readonly configDir: string;
  private conversations = new Map<string, Conversation>();
  private cursors = new Map<string, number>();

  constructor(name: string) {
    this.name = name;
    this.identity = generateIdentity();
    const kid = keyIDFromPublicKey(this.identity.publicKey);
    this.kidHex = bytesToHex(kid);
    this.kidB64 = base64UrlEncode(kid);
    this.configDir = mkdtempSync(join(tmpdir(), `qntm-agent-${name}-`));
  }

  createConversation(name: string): { convIdHex: string; conversation: Conversation } {
    const invite = createInvite(this.identity, 'group');
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    addParticipant(conv, this.identity.publicKey);
    const convIdHex = bytesToHex(invite.conv_id);
    this.conversations.set(convIdHex, conv);
    return { convIdHex, conversation: conv };
  }

  joinConversation(convIdHex: string, conv: Conversation): void {
    addParticipant(conv, this.identity.publicKey);
    this.conversations.set(convIdHex, conv);
  }

  getConversation(convIdHex: string): Conversation | undefined {
    return this.conversations.get(convIdHex);
  }

  sendMessage(relay: InMemoryRelay, convIdHex: string, bodyType: string, body: Uint8Array): number {
    const conv = this.conversations.get(convIdHex);
    if (!conv) throw new Error(`Agent ${this.name}: conversation ${convIdHex} not found`);
    const envelope = createMessage(this.identity, conv, bodyType, body, undefined, defaultTTL());
    const serialized = serializeEnvelope(envelope);
    const seq = relay.post(convIdHex, serialized);
    const receipt = buildSignedReceipt(
      this.identity,
      conv.id,
      envelope.msg_id,
      Math.max(MIN_RECEIPT_ACKS, conv.participants.length),
    );
    relay.submitReceipt(receipt);
    return seq;
  }

  sendText(relay: InMemoryRelay, convIdHex: string, text: string): number {
    return this.sendMessage(relay, convIdHex, 'text', new TextEncoder().encode(text));
  }

  /**
   * Receive messages and emit read receipts for each successfully decrypted message.
   * Returns the decrypted messages (excluding self-echoes).
   */
  receiveAndReceipt(relay: InMemoryRelay, convIdHex: string): Array<{ bodyType: string; body: Uint8Array; senderKid: string }> {
    const conv = this.conversations.get(convIdHex);
    if (!conv) throw new Error(`Agent ${this.name}: conversation ${convIdHex} not found`);
    const cursor = this.cursors.get(convIdHex) || 0;
    const result = relay.poll(convIdHex, cursor);

    const received: Array<{ bodyType: string; body: Uint8Array; senderKid: string }> = [];
    const requiredAcks = Math.max(MIN_RECEIPT_ACKS, conv.participants.length);

    for (const envelopeBytes of result.messages) {
      try {
        const envelope = deserializeEnvelope(envelopeBytes);
        const msg = decryptMessage(envelope, conv);
        const senderKid = base64UrlEncode(new Uint8Array(msg.inner.sender_kid));

        // Emit receipt for every successfully processed message
        const receipt = buildSignedReceipt(this.identity, conv.id, envelope.msg_id, requiredAcks);
        relay.submitReceipt(receipt);

        // Skip self-echoes from the returned results
        if (senderKid === this.kidB64) continue;
        received.push({
          bodyType: msg.inner.body_type,
          body: new Uint8Array(msg.inner.body),
          senderKid,
        });
      } catch {
        continue;
      }
    }

    if (result.sequence > cursor) {
      this.cursors.set(convIdHex, result.sequence);
    }

    return received;
  }

  receiveMessages(relay: InMemoryRelay, convIdHex: string): Array<{ bodyType: string; body: Uint8Array; senderKid: string }> {
    const conv = this.conversations.get(convIdHex);
    if (!conv) throw new Error(`Agent ${this.name}: conversation ${convIdHex} not found`);
    const cursor = this.cursors.get(convIdHex) || 0;
    const result = relay.poll(convIdHex, cursor);

    const received: Array<{ bodyType: string; body: Uint8Array; senderKid: string }> = [];
    for (const envelopeBytes of result.messages) {
      try {
        const envelope = deserializeEnvelope(envelopeBytes);
        const msg = decryptMessage(envelope, conv);
        const senderKid = base64UrlEncode(new Uint8Array(msg.inner.sender_kid));
        // Skip self-echoes
        if (senderKid === this.kidB64) continue;
        received.push({
          bodyType: msg.inner.body_type,
          body: new Uint8Array(msg.inner.body),
          senderKid,
        });
      } catch {
        continue;
      }
    }

    if (result.sequence > cursor) {
      this.cursors.set(convIdHex, result.sequence);
    }

    return received;
  }

  cleanup(): void {
    try {
      rmSync(this.configDir, { recursive: true, force: true });
    } catch {
      // Best effort
    }
  }
}

// ---- Deterministic API fixture ----

export interface FixtureResponse {
  status: number;
  contentType: string;
  body: string;
}

export class APIFixture {
  private routes = new Map<string, FixtureResponse>();

  register(verb: string, path: string, response: FixtureResponse): void {
    this.routes.set(`${verb.toUpperCase()} ${path}`, response);
  }

  handle(verb: string, path: string): FixtureResponse {
    return this.routes.get(`${verb.toUpperCase()} ${path}`) || {
      status: 404,
      contentType: 'text/plain',
      body: 'Not Found',
    };
  }
}

// ---- Wait helpers ----

export async function waitForCondition(
  check: () => boolean,
  timeoutMs = 5000,
  pollMs = 50,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (check()) return;
    await new Promise(r => setTimeout(r, pollMs));
  }
  throw new Error(`Condition not met within ${timeoutMs}ms`);
}

// ---- Utilities ----

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
