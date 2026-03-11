/**
 * DropboxClient — HTTP transport for the qntm dropbox relay.
 *
 * Mirrors the Go HTTPStorageProvider's sequenced send/poll API:
 *   POST /v1/send  — append an envelope to a conversation
 *   POST /v1/poll  — fetch envelopes from a sequence cursor
 */

const DEFAULT_BASE_URL = 'https://inbox.qntm.corpo.llc';

// ---------- wire types (match Go structs in dropbox/http.go) ----------

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
}
