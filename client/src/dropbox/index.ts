/**
 * DropboxClient — HTTP transport for the qntm dropbox relay.
 *
 * Mirrors the Go HTTPStorageProvider's sequenced send/poll API:
 *   POST /v1/send  — append an envelope to a conversation
 *   POST /v1/poll  — fetch envelopes from a sequence cursor
 */

import { QSP1Suite } from '../crypto/qsp1.js';
import type { Identity } from '../types.js';

const DEFAULT_BASE_URL = 'https://inbox.qntm.corpo.llc';
const _suite = new QSP1Suite();

// ---------- wire types (match archived Go structs in attic/go/dropbox/http.go) ----------

interface SendEnvelopeRequest {
  conv_id: string;
  envelope_b64: string;
  announce_sig?: string;
}

interface SendEnvelopeResponse {
  seq: number;
}

interface PollConversationRequest {
  conv_id: string;
  from_seq: number;
}

interface PollRequest {
  conversations: PollConversationRequest[];
  max_messages?: number;
}

interface PollMessageResponse {
  seq: number;
  envelope_b64: string;
}

interface PollConversationResponse {
  conv_id: string;
  up_to_seq: number;
  messages: PollMessageResponse[];
}

interface PollResponse {
  conversations: PollConversationResponse[];
}

// ---------- receipt types ----------

export interface ReadReceiptPayload {
  proto: string;
  conv_id: string;
  msg_id: string;
  reader_kid: string;
  reader_ik_pk: string;
  read_ts: number;
  required_acks: number;
  sig: string;
}

export interface ReceiptResponse {
  recorded: boolean;
  deleted: boolean;
  receipts: number;
  required_acks: number;
}

// ---------- helpers ----------

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function uint8ToBase64(bytes: Uint8Array): string {
  // Works in both Node 18+ and browsers
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------- DropboxClient ----------

export interface ReceiveResult {
  /** Decoded envelope bytes, one per message */
  messages: Uint8Array[];
  /** Highest sequence number seen — use as fromSequence on the next poll */
  sequence: number;
}

export const RECEIPT_PROTO = 'qntm-receipt-v1';

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build a signed read receipt payload ready for submission to the relay.
 *
 * @param identity   The reader's identity (private key used to sign)
 * @param convId     Conversation ID (16 bytes)
 * @param msgId      Message ID (16 bytes)
 * @param requiredAcks  Number of unique readers needed before deletion
 */
export function buildSignedReceipt(
  identity: Identity,
  convId: Uint8Array,
  msgId: Uint8Array,
  requiredAcks: number,
): ReadReceiptPayload {
  const convIdHex = toHex(convId);
  const msgIdHex = toHex(msgId);
  const readerKidHex = toHex(_suite.computeKeyID(identity.publicKey));
  const readerIkPk = toBase64Url(identity.publicKey);
  const readTs = Date.now();

  const signable = `${RECEIPT_PROTO}|${convIdHex}|${msgIdHex}|${readerKidHex}|${readTs}|${requiredAcks}`;
  const sig = _suite.sign(identity.privateKey, new TextEncoder().encode(signable));

  return {
    proto: RECEIPT_PROTO,
    conv_id: convIdHex,
    msg_id: msgIdHex,
    reader_kid: readerKidHex,
    reader_ik_pk: readerIkPk,
    read_ts: readTs,
    required_acks: requiredAcks,
    sig: toBase64Url(sig),
  };
}

export class DropboxClient {
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = (baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  }

  /**
   * Post a serialised envelope to a conversation.
   * Returns the sequence number assigned by the relay.
   */
  async postMessage(
    conversationId: Uint8Array,
    envelope: Uint8Array,
    announceSig?: string,
  ): Promise<number> {
    const body: SendEnvelopeRequest = {
      conv_id: toHex(conversationId),
      envelope_b64: uint8ToBase64(envelope),
    };
    if (announceSig) {
      body.announce_sig = announceSig;
    }

    const resp = await fetch(`${this.baseUrl}/v1/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(
        `dropbox send failed: HTTP ${resp.status}${text ? ': ' + text : ''}`,
      );
    }

    const result = (await resp.json()) as SendEnvelopeResponse;
    return result.seq;
  }

  /**
   * Poll for envelopes in a conversation starting after `fromSequence`.
   * Returns decoded envelope bytes and the new cursor sequence.
   */
  async receiveMessages(
    conversationId: Uint8Array,
    fromSequence: number = 0,
    maxMessages?: number,
  ): Promise<ReceiveResult> {
    const reqBody: PollRequest = {
      conversations: [
        {
          conv_id: toHex(conversationId),
          from_seq: fromSequence,
        },
      ],
    };
    if (maxMessages !== undefined && maxMessages > 0) {
      reqBody.max_messages = maxMessages;
    }

    const resp = await fetch(`${this.baseUrl}/v1/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqBody),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(
        `dropbox poll failed: HTTP ${resp.status}${text ? ': ' + text : ''}`,
      );
    }

    const result = (await resp.json()) as PollResponse;

    if (!result.conversations || result.conversations.length === 0) {
      return { messages: [], sequence: fromSequence };
    }

    const conv = result.conversations[0];
    const messages: Uint8Array[] = [];
    for (const msg of conv.messages) {
      try {
        messages.push(base64ToUint8(msg.envelope_b64));
      } catch {
        // Skip messages with invalid base64 encoding
        continue;
      }
    }

    return {
      messages,
      sequence: conv.up_to_seq,
    };
  }

  /**
   * Submit a signed read receipt to the relay.
   * When enough unique readers have receipted a message, the relay deletes it.
   */
  async submitReceipt(payload: ReadReceiptPayload): Promise<ReceiptResponse> {
    const resp = await fetch(`${this.baseUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(
        `dropbox receipt failed: HTTP ${resp.status}${text ? ': ' + text : ''}`,
      );
    }

    return (await resp.json()) as ReceiptResponse;
  }
}
