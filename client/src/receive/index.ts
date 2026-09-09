/** Portable adapter event format. Storage, acknowledgements and scheduling are app-owned. */
import type { Message } from '../types.js';

export type ReceiveEventBody =
  | { unsafe_body: string; unsafe_body_b64?: never }
  | { unsafe_body_b64: string; unsafe_body?: never };

export type ReceivedMessage = ReceiveEventBody & {
  conversation_id: string;
  message_id: string;
  sender_kid: string;
  created_ts: number;
  body_type: string;
  verified: true;
  sequence: number;
};

export interface ReceiveEvent {
  version: 1;
  event_id: string;
  conversation_id: string;
  sequence: number;
  message: ReceivedMessage;
}

function id(value: Uint8Array): string {
  if (!(value instanceof Uint8Array) || value.length !== 16) {
    throw new Error('receive event IDs must be 16 bytes');
  }
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error('receive event sequence and timestamp must be positive safe integers');
  }
  return value;
}

/**
 * Normalize a decryptMessage result for an adapter. This formatter does not
 * reverify signatures or grant authority to received content. Preserve raw body
 * bytes, using UTF-8 when valid and base64 otherwise (also for CBOR group events).
 */
export function createReceiveEvent(message: Message, sequence: number): ReceiveEvent {
  if (message.verified !== true) throw new Error('receive events require a verified message');
  positiveInteger(sequence);
  const { envelope, inner } = message;
  const conversationId = id(envelope.conv_id);
  const messageId = id(envelope.msg_id);
  if (!(inner.body instanceof Uint8Array)) throw new Error('receive event body must be bytes');
  if (typeof inner.body_type !== 'string' || !inner.body_type) {
    throw new Error('receive event body type must be nonempty');
  }
  let body: ReceiveEventBody;
  try {
    // Keep a leading BOM, matching Python's strict UTF-8 decoder.
    body = { unsafe_body: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(inner.body) };
  } catch {
    body = { unsafe_body_b64: btoa(Array.from(inner.body, byte => String.fromCharCode(byte)).join('')) };
  }
  return {
    version: 1,
    event_id: `qntm:${conversationId}:${messageId}`,
    conversation_id: conversationId,
    sequence,
    message: {
      conversation_id: conversationId, message_id: messageId,
      sender_kid: id(inner.sender_kid), created_ts: positiveInteger(envelope.created_ts),
      body_type: inner.body_type, verified: true, sequence, ...body,
    },
  };
}
