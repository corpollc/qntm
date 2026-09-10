/**
 * DropboxClient — HTTP transport for the qntm dropbox relay.
 *
 * Uses sequenced send plus websocket-based replay/subscribe:
 *   POST /v1/send  — append an envelope to a conversation
 *   GET /v1/subscribe  — replay from a sequence cursor, then stream live messages
 */

import { QSP1Suite } from '../crypto/qsp1.js';
import { deserializeEnvelope } from '../message/index.js';
import type { Identity } from '../types.js';

const DEFAULT_BASE_URL = 'https://inbox.qntm.corpo.llc';
const _suite = new QSP1Suite();

// ---------- wire types (match archived Go structs in attic/go/dropbox/http.go) ----------

interface SendEnvelopeRequest {
  conv_id: string;
  envelope_b64: string;
  msg_id?: string;
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

interface SubscribeFrameMessage {
  type: 'message';
  seq: number;
  envelope_b64: string;
}

interface SubscribeFramePong {
  type: 'pong';
}

interface SubscribeFrameReady {
  type: 'ready';
  head_seq: number;
}

type SubscribeFrame = SubscribeFrameMessage | SubscribeFrameReady | SubscribeFramePong;

// ---------- receipt types ----------

export interface ReadReceiptPayload {
  proto: string;
  conv_id: string;
  msg_id: string;
  reader_kid: string;
  reader_ik_pk: string;
  read_ts: number;
  /** Signed legacy hint; it cannot authorize deletion. Relay TTL controls retention. */
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
  /** Exact transport sequences, including gaps; same order/bytes as messages. */
  entries: SubscriptionMessage[];
  /** Captured relay head — persist only after validating/processing the replay. */
  sequence: number;
}

export interface SubscriptionMessage {
  seq: number;
  envelope: Uint8Array;
}

export interface SubscriptionCloseEvent {
  code: number;
  reason: string;
  wasClean: boolean;
}

export interface DropboxSubscriptionHandlers {
  onMessage: (message: SubscriptionMessage) => void | Promise<void>;
  /** Serialized after backlog and before live messages, once per connection.
   * Buffer replay until this callback when complete history is needed to act.
   * Use getCursor to resume from durably committed application progress.
   */
  onReady?: (headSequence: number) => void | Promise<void>;
  getCursor?: () => number | Promise<number>;
  onOpen?: () => void;
  onClose?: (event: SubscriptionCloseEvent) => void;
  onError?: (error: Error) => void;
  onReconnect?: (attempt: number, delayMs: number) => void;
}

export interface DropboxSubscription {
  close: (code?: number, reason?: string) => void;
  closed: Promise<void>;
}

export const RECEIPT_PROTO = 'qntm-receipt-v1';

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toWebSocketUrl(baseUrl: string, conversationIdHex: string, fromSequence: number): string {
  const url = new URL(baseUrl);
  if (url.protocol === 'http:') {
    url.protocol = 'ws:';
  } else if (url.protocol === 'https:') {
    url.protocol = 'wss:';
  }
  url.pathname = '/v1/subscribe';
  url.search = '';
  url.searchParams.set('conv_id', conversationIdHex);
  url.searchParams.set('from_seq', String(fromSequence));
  return url.toString();
}

async function webSocketDataToText(data: unknown): Promise<string> {
  if (typeof data === 'string') {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(data));
  }
  if (ArrayBuffer.isView(data)) {
    return new TextDecoder().decode(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  }
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    return data.text();
  }
  throw new Error('unsupported websocket frame payload');
}

/**
 * Build a signed read receipt payload ready for submission to the relay.
 *
 * @param identity   The reader's identity (private key used to sign)
 * @param convId     Conversation ID (16 bytes)
 * @param msgId      Message ID (16 bytes)
 * @param requiredAcks  Signed legacy hint retained for wire compatibility
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
    try {
      body.msg_id = toHex(deserializeEnvelope(envelope).msg_id);
    } catch {
      // Older callers may post opaque bytes without a decodable qntm envelope.
    }
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
    _maxMessages?: number,
  ): Promise<ReceiveResult> {
    if (!Number.isSafeInteger(fromSequence) || fromSequence < 0) throw new Error('invalid receive cursor');
    if (typeof WebSocket === 'undefined') {
      throw new Error('WebSocket is not available in this runtime');
    }

    const conversationIdHex = toHex(conversationId);
    return new Promise<ReceiveResult>((resolve, reject) => {
      const messages: Uint8Array[] = [];
      const entries: SubscriptionMessage[] = [];
      let messageQueue = Promise.resolve();
      let settled = false;
      let currentSequence = fromSequence;
      let headSequence: number | null = null;
      const socket = new WebSocket(toWebSocketUrl(this.baseUrl, conversationIdHex, fromSequence));

      const finish = () => {
        if (settled) return;
        settled = true;
        resolve({
          messages,
          entries,
          sequence: headSequence!,
        });
        try {
          socket.close(1000, 'receive complete');
        } catch {
          // Ignore best-effort close failures.
        }
      };

      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        reject(error instanceof Error ? error : new Error(String(error)));
        try {
          socket.close(4000, 'receive failed');
        } catch {
          // Ignore best-effort close failures.
        }
      };

      socket.addEventListener('message', (event) => {
        messageQueue = messageQueue.then(async () => {
          if (settled) return;
          const payload = await webSocketDataToText(event.data);
          const frame = JSON.parse(payload) as SubscribeFrame;
          if (frame.type === 'message') {
            if (!Number.isSafeInteger(frame.seq) || frame.seq <= 0) throw new Error('invalid subscription sequence');
            const envelope = base64ToUint8(frame.envelope_b64);
            messages.push(envelope);
            entries.push({ seq: frame.seq, envelope });
            currentSequence = Math.max(currentSequence, frame.seq);
            return;
          }
          if (frame.type === 'ready') {
            if (!Number.isSafeInteger(frame.head_seq) || frame.head_seq < currentSequence) throw new Error('invalid subscription head');
            headSequence = frame.head_seq;
            finish();
            return;
          }
          if (frame.type !== 'pong') throw new Error('unsupported subscription frame');
        }).catch(fail);
      });

      socket.addEventListener('error', () => {
        fail(new Error(`dropbox receive failed for conversation ${conversationIdHex}`));
      });

      socket.addEventListener('close', (event) => {
        void messageQueue.then(() => {
          if (!settled) fail(new Error(
            `dropbox receive closed before reaching relay head for conversation ${conversationIdHex}: ` +
            `${event.code}${event.reason ? ` ${event.reason}` : ''}`,
          ));
        });
      });
    });
  }

  subscribeMessages(
    conversationId: Uint8Array,
    fromSequence: number = 0,
    handlers: DropboxSubscriptionHandlers,
  ): DropboxSubscription {
    if (!Number.isSafeInteger(fromSequence) || fromSequence < 0) throw new Error('invalid receive cursor');
    if (typeof WebSocket === 'undefined') {
      throw new Error('WebSocket is not available in this runtime');
    }

    const conversationIdHex = toHex(conversationId);
    let closedByCaller = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let socket: WebSocket | null = null;
    let reconnectAttempt = 0;
    let currentSequence = fromSequence;
    let messageQueue = Promise.resolve();

    let resolveClosed: (() => void) | null = null;
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });

    const clearReconnectTimer = () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const reportError = (error: unknown) => {
      if (!handlers.onError) return;
      handlers.onError(error instanceof Error ? error : new Error(String(error)));
    };

    const scheduleReconnect = () => {
      if (closedByCaller || reconnectTimer) {
        return;
      }
      reconnectAttempt += 1;
      const delayMs = Math.min(30_000, 1_000 * 2 ** Math.min(reconnectAttempt - 1, 5));
      handlers.onReconnect?.(reconnectAttempt, delayMs);
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        // A socket can close while durable application processing is pending.
        // Finish that work before selecting the next replay cursor.
        void messageQueue.then(connect).catch((error) => {
          reportError(error);
          scheduleReconnect();
        });
      }, delayMs);
    };

    const connect = async () => {
      if (closedByCaller) {
        return;
      }

      const resumeSequence = handlers.getCursor
        ? await Promise.resolve(handlers.getCursor())
        : currentSequence;
      if (closedByCaller) return;
      if (!Number.isSafeInteger(resumeSequence) || resumeSequence < 0) throw new Error('invalid receive cursor');
      currentSequence = resumeSequence;

      const ws = new WebSocket(toWebSocketUrl(this.baseUrl, conversationIdHex, resumeSequence));
      socket = ws;
      let failed = false;
      let ready = false;
      let receivedSequence = resumeSequence;

      ws.addEventListener('open', () => {
        if (socket !== ws || closedByCaller) {
          return;
        }
        reconnectAttempt = 0;
        handlers.onOpen?.();
      });

      ws.addEventListener('message', (event) => {
        if (socket !== ws || closedByCaller || failed) return;
        messageQueue = messageQueue
          .then(async () => {
            if (closedByCaller || failed) return;
            const payload = await webSocketDataToText(event.data);
            const frame = JSON.parse(payload) as SubscribeFrame;
            if (frame.type === 'pong') return;
            if (frame.type === 'ready') {
              if (ready || !Number.isSafeInteger(frame.head_seq) || frame.head_seq < receivedSequence) throw new Error('invalid subscription head');
              await handlers.onReady?.(frame.head_seq);
              ready = true;
              // Only a successful ready callback can commit a buffered replay.
              if (handlers.onReady) currentSequence = frame.head_seq;
              return;
            }
            if (frame.type !== 'message') throw new Error('unsupported subscription frame');
            if (!Number.isSafeInteger(frame.seq) || frame.seq <= 0) {
              throw new Error('invalid subscription sequence');
            }

            await handlers.onMessage({
              seq: frame.seq,
              envelope: base64ToUint8(frame.envelope_b64),
            });
            receivedSequence = Math.max(receivedSequence, frame.seq);
            if (!handlers.onReady || ready) currentSequence = Math.max(currentSequence, frame.seq);
          })
          .catch((error) => {
            // Never let a later callback acknowledge past this failed event.
            // Replay from the last successful callback / durable app cursor.
            failed = true;
            reportError(error);
            if (socket === ws && !closedByCaller) {
              ws.close(4000, 'receive callback failed');
            }
          });
      });

      ws.addEventListener('error', () => {
        if (socket !== ws || closedByCaller) {
          return;
        }
        reportError(new Error(`dropbox subscription error for conversation ${conversationIdHex}`));
      });

      ws.addEventListener('close', (event) => {
        if (socket === ws) {
          socket = null;
        }

        handlers.onClose?.({
          code: event.code,
          reason: event.reason,
          wasClean: event.wasClean,
        });

        if (closedByCaller) {
          clearReconnectTimer();
          resolveClosed?.();
          resolveClosed = null;
          return;
        }

        scheduleReconnect();
      });
    };

    void connect().catch((error) => {
      reportError(error);
      scheduleReconnect();
    });

    return {
      close: (code = 1000, reason = 'client closed') => {
        if (closedByCaller) {
          return;
        }
        closedByCaller = true;
        clearReconnectTimer();
        if (socket) {
          socket.close(code, reason);
          return;
        }
        resolveClosed?.();
        resolveClosed = null;
      },
      closed,
    };
  }

  /**
   * Submit a signed read receipt to the relay.
   * Receipts are telemetry only; relay retention is controlled by server TTL.
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
