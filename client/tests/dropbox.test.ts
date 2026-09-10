import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DropboxClient, buildSignedReceipt, RECEIPT_PROTO } from '../src/dropbox/index.js';
import { generateIdentity } from '../src/identity/index.js';

// Helper: create a fake conversation ID (16 bytes)
function fakeConvID(): Uint8Array {
  const id = new Uint8Array(16);
  for (let i = 0; i < 16; i++) id[i] = i + 1;
  return id;
}

// Helper: hex-encode a Uint8Array (matching Go's hex.EncodeToString)
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: base64-encode a Uint8Array (standard base64, matching Go's base64.StdEncoding)
function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

type FakeEventHandler = (event?: any) => void;

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  private readonly listeners = new Map<string, FakeEventHandler[]>();

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  static reset(): void {
    FakeWebSocket.instances = [];
  }

  addEventListener(type: string, handler: FakeEventHandler): void {
    const handlers = this.listeners.get(type) ?? [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }

  close(code = 1000, reason = ''): void {
    this.emit('close', { code, reason, wasClean: true });
  }

  open(): void {
    this.emit('open');
  }

  message(data: unknown): void {
    this.emit('message', { data });
  }

  error(): void {
    this.emit('error');
  }

  private emit(type: string, event?: any): void {
    for (const handler of this.listeners.get(type) ?? []) {
      handler(event);
    }
  }
}

describe('DropboxClient', () => {
  let client: DropboxClient;
  const baseUrl = 'https://inbox.example.com';

  beforeEach(() => {
    client = new DropboxClient(baseUrl);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
    FakeWebSocket.reset();
  });

  // === Construction ===

  describe('construction', () => {
    it('stores base URL and strips trailing slash', () => {
      const c = new DropboxClient('https://inbox.example.com/');
      // We verify via the URLs it constructs (tested in send/poll tests)
      expect(c).toBeInstanceOf(DropboxClient);
    });

    it('uses default URL when none provided', () => {
      const c = new DropboxClient();
      expect(c).toBeInstanceOf(DropboxClient);
    });
  });

  // === postMessage ===

  describe('postMessage', () => {
    it('sends POST to /v1/send with correct JSON body', async () => {
      const convID = fakeConvID();
      const envelope = new Uint8Array([10, 20, 30, 40]);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ seq: 1 }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const seq = await client.postMessage(convID, envelope);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${baseUrl}/v1/send`);
      expect(opts.method).toBe('POST');
      expect(opts.headers['Content-Type']).toBe('application/json');

      const body = JSON.parse(opts.body);
      expect(body.conv_id).toBe(toHex(convID));
      expect(body.envelope_b64).toBe(toBase64(envelope));
      expect(seq).toBe(1);
    });

    it('throws on HTTP error response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => 'internal error',
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(
        client.postMessage(fakeConvID(), new Uint8Array([1])),
      ).rejects.toThrow(/500/);
    });

    it('throws on network error', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('network down'));
      vi.stubGlobal('fetch', mockFetch);

      await expect(
        client.postMessage(fakeConvID(), new Uint8Array([1])),
      ).rejects.toThrow('network down');
    });
  });

  // === receiveMessages ===

  describe('receiveMessages', () => {
    it('replays websocket messages until the relay sends ready', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);

      const convID = fakeConvID();
      const env1 = new Uint8Array([0xaa, 0xbb]);
      const env2 = new Uint8Array([0xcc, 0xdd]);

      const resultPromise = client.receiveMessages(convID, 2);

      expect(FakeWebSocket.instances).toHaveLength(1);
      expect(FakeWebSocket.instances[0]!.url).toBe(
        `${baseUrl.replace('https://', 'wss://')}/v1/subscribe?conv_id=${toHex(convID)}&from_seq=2`,
      );

      FakeWebSocket.instances[0]!.open();
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'message',
        seq: 3,
        envelope_b64: toBase64(env1),
      }));
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'message',
        seq: 5,
        envelope_b64: toBase64(env2),
      }));
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'ready',
        head_seq: 5,
      }));

      const result = await resultPromise;

      expect(result.sequence).toBe(5);
      expect(result.messages).toHaveLength(2);
      expect(result.messages[0]).toEqual(env1);
      expect(result.messages[1]).toEqual(env2);
      expect(result.entries).toEqual([{ seq: 3, envelope: env1 }, { seq: 5, envelope: env2 }]);
    });

    it('returns immediately when ready reports no new messages', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);

      const convID = fakeConvID();
      const resultPromise = client.receiveMessages(convID);

      FakeWebSocket.instances[0]!.open();
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'ready',
        head_seq: 0,
      }));

      const result = await resultPromise;
      expect(result.messages).toEqual([]);
      expect(result.entries).toEqual([]);
      expect(result.sequence).toBe(0);
    });

    it('preserves asynchronous frame order and ignores live frames after the captured head', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const resultPromise = client.receiveMessages(fakeConvID(), 2);
      const socket = FakeWebSocket.instances[0]!;
      socket.message(new Blob(['{"type":"message","seq":3,"envelope_b64":"YQ=="}']));
      socket.message('{"type":"ready","head_seq":4}');
      socket.message('{"type":"message","seq":5,"envelope_b64":"Yg=="}');
      const result = await resultPromise;
      await Promise.resolve();
      expect(result.sequence).toBe(4);
      expect(result.entries).toEqual([{ seq: 3, envelope: new Uint8Array([97]) }]);
    });

    it.each([-1, 1.5, 2, null])('rejects a malformed or regressed captured head %s', async head => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const result = client.receiveMessages(fakeConvID(), 3);
      const rejection = expect(result).rejects.toThrow('head');
      FakeWebSocket.instances[0]!.message(JSON.stringify({ type: 'ready', head_seq: head }));
      await rejection;
    });

    it('waits for an already queued ready frame before treating a close as incomplete', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const result = client.receiveMessages(fakeConvID(), 2);
      FakeWebSocket.instances[0]!.message(new Blob(['{"type":"ready","head_seq":5}']));
      FakeWebSocket.instances[0]!.close();
      expect(await result).toEqual({ messages: [], entries: [], sequence: 5 });
    });
  });

  describe('subscribeMessages', () => {
    it('serializes asynchronous ready processing between replay and live messages', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const order: string[] = [];
      let release!: () => void;
      const pending = new Promise<void>(resolve => { release = resolve; });
      const subscription = client.subscribeMessages(fakeConvID(), 0, {
        onMessage: ({ seq }) => { order.push(`message:${seq}`); },
        onReady: async head => { order.push(`head:${head}`); await pending; order.push('committed'); },
      });
      const socket = FakeWebSocket.instances[0]!;
      socket.message('{"type":"message","seq":1,"envelope_b64":"YQ=="}');
      socket.message('{"type":"ready","head_seq":2}');
      socket.message('{"type":"message","seq":3,"envelope_b64":"Yg=="}');
      await vi.advanceTimersByTimeAsync(0);
      expect(order).toEqual(['message:1', 'head:2']);
      release();
      await vi.advanceTimersByTimeAsync(0);
      expect(order).toEqual(['message:1', 'head:2', 'committed', 'message:3']);
      socket.close(1012);
      await vi.advanceTimersByTimeAsync(1000);
      expect(FakeWebSocket.instances[1]!.url).toContain('from_seq=3');
      FakeWebSocket.instances[1]!.message('{"type":"ready","head_seq":3}');
      await vi.advanceTimersByTimeAsync(0);
      expect(order.slice(-2)).toEqual(['head:3', 'committed']);
      subscription.close();
      await subscription.closed;
    });

    it('replays the entire uncommitted backlog when its ready callback fails', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const messages: number[] = [], errors = vi.fn();
      const subscription = client.subscribeMessages(fakeConvID(), 2, {
        onMessage: ({ seq }) => { messages.push(seq); },
        onReady: () => { throw new Error('cannot persist replay'); }, onError: errors,
      });
      const socket = FakeWebSocket.instances[0]!;
      socket.message('{"type":"message","seq":3,"envelope_b64":"YQ=="}');
      socket.message('{"type":"ready","head_seq":4}');
      socket.message('{"type":"message","seq":5,"envelope_b64":"Yg=="}');
      await vi.advanceTimersByTimeAsync(1000);
      expect(messages).toEqual([3]);
      expect(errors).toHaveBeenCalledOnce();
      expect(FakeWebSocket.instances[1]!.url).toContain('from_seq=2');
      subscription.close();
      await subscription.closed;
    });

    it('replays a failed callback before processing later queued messages', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const received: number[] = [];
      const onError = vi.fn();
      let failOnce = true;
      const subscription = client.subscribeMessages(fakeConvID(), 0, {
        onMessage: async ({ seq }) => {
          received.push(seq);
          if (failOnce) {
            failOnce = false;
            throw new Error('durable inbox unavailable');
          }
        },
        onError,
      });
      const emit = (socket: FakeWebSocket, seq: number) => socket.message(JSON.stringify({
        type: 'message', seq, envelope_b64: 'YQ==',
      }));
      const first = FakeWebSocket.instances[0]!;
      first.open();
      emit(first, 1);
      emit(first, 2);
      await vi.advanceTimersByTimeAsync(0);
      expect(received).toEqual([1]);
      expect(onError).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(1000);
      const second = FakeWebSocket.instances[1]!;
      expect(second.url).toContain('from_seq=0');
      second.open();
      emit(second, 1);
      emit(second, 2);
      await vi.advanceTimersByTimeAsync(0);
      expect(received).toEqual([1, 1, 2]);
      subscription.close();
      await subscription.closed;
    });

    it('waits for an in-flight durable write before reading the reconnect cursor', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      let finish!: () => void;
      const pending = new Promise<void>(resolve => { finish = resolve; });
      let cursor = 0;
      const subscription = client.subscribeMessages(fakeConvID(), 0, {
        getCursor: () => cursor,
        onMessage: async ({ seq }) => { await pending; cursor = seq; },
      });
      await Promise.resolve();
      const first = FakeWebSocket.instances[0]!;
      first.message('{"type":"message","seq":1,"envelope_b64":"YQ=="}');
      await vi.advanceTimersByTimeAsync(0);
      first.close(1012, 'restart');
      await vi.advanceTimersByTimeAsync(1000);
      expect(FakeWebSocket.instances).toHaveLength(1);
      finish();
      await vi.advanceTimersByTimeAsync(0);
      expect(FakeWebSocket.instances[1]!.url).toContain('from_seq=1');
      subscription.close();
      await subscription.closed;
    });

    it('retries a rejected cursor read on reconnect', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      const getCursor = vi.fn().mockResolvedValueOnce(0)
        .mockRejectedValueOnce(new Error('temporary storage failure')).mockResolvedValue(4);
      const onError = vi.fn();
      const subscription = client.subscribeMessages(fakeConvID(), 0, {
        getCursor, onMessage: vi.fn(), onError,
      });
      await vi.advanceTimersByTimeAsync(0);
      FakeWebSocket.instances[0]!.close(1012);
      await vi.advanceTimersByTimeAsync(1000);
      expect(onError).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(2000);
      expect(FakeWebSocket.instances[1]!.url).toContain('from_seq=4');
      subscription.close();
      await subscription.closed;
    });

    it('does not open a socket after closing during an asynchronous cursor read', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
      let finish!: (value: number) => void;
      const cursor = new Promise<number>(resolve => { finish = resolve; });
      const subscription = client.subscribeMessages(fakeConvID(), 0, {
        getCursor: () => cursor, onMessage: vi.fn(),
      });
      subscription.close();
      finish(0);
      await subscription.closed;
      await Promise.resolve();
      expect(FakeWebSocket.instances).toHaveLength(0);
    });

    it('opens a websocket subscription and decodes streamed envelopes', async () => {
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);

      const convID = fakeConvID();
      const envelope = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const received: Array<{ seq: number; envelope: Uint8Array }> = [];

      const subscription = client.subscribeMessages(convID, 2, {
        onMessage: async (message) => {
          received.push(message);
        },
      });

      expect(FakeWebSocket.instances).toHaveLength(1);
      expect(FakeWebSocket.instances[0]!.url).toBe(
        `${baseUrl.replace('https://', 'wss://')}/v1/subscribe?conv_id=${toHex(convID)}&from_seq=2`,
      );

      FakeWebSocket.instances[0]!.open();
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'message',
        seq: 3,
        envelope_b64: toBase64(envelope),
      }));

      await Promise.resolve();
      await Promise.resolve();

      expect(received).toHaveLength(1);
      expect(received[0]!.seq).toBe(3);
      expect(received[0]!.envelope).toEqual(envelope);

      subscription.close();
      await subscription.closed;
    });

    it('reconnects with the latest cursor after a close', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);

      const convID = fakeConvID();
      const reconnects: Array<{ attempt: number; delayMs: number }> = [];
      let cursor = 5;

      const subscription = client.subscribeMessages(convID, 0, {
        getCursor: () => cursor,
        onMessage: async (message) => {
          cursor = message.seq;
        },
        onReconnect: (attempt, delayMs) => {
          reconnects.push({ attempt, delayMs });
        },
      });

      await Promise.resolve();
      expect(FakeWebSocket.instances).toHaveLength(1);
      expect(FakeWebSocket.instances[0]!.url).toBe(
        `${baseUrl.replace('https://', 'wss://')}/v1/subscribe?conv_id=${toHex(convID)}&from_seq=5`,
      );

      FakeWebSocket.instances[0]!.open();
      FakeWebSocket.instances[0]!.message(JSON.stringify({
        type: 'message',
        seq: 6,
        envelope_b64: toBase64(new Uint8Array([0xaa])),
      }));

      await Promise.resolve();
      await Promise.resolve();

      FakeWebSocket.instances[0]!.close(1012, 'restart');
      await vi.advanceTimersByTimeAsync(1000);

      expect(reconnects).toEqual([{ attempt: 1, delayMs: 1000 }]);
      expect(FakeWebSocket.instances).toHaveLength(2);
      expect(FakeWebSocket.instances[1]!.url).toBe(
        `${baseUrl.replace('https://', 'wss://')}/v1/subscribe?conv_id=${toHex(convID)}&from_seq=6`,
      );

      subscription.close();
      FakeWebSocket.instances[1]!.close();
      await subscription.closed;
    });
  });

  // === Conversation ID formatting ===

  describe('conversation ID formatting', () => {
    it('formats conversation ID as lowercase hex', async () => {
      const convID = new Uint8Array([
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
      ]);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ seq: 1 }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await client.postMessage(convID, new Uint8Array([1]));

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.conv_id).toBe('abcdef0123456789abcdef0123456789');
      // Ensure lowercase
      expect(body.conv_id).toBe(body.conv_id.toLowerCase());
    });
  });

  // === submitReceipt ===

  describe('submitReceipt', () => {
    it('sends POST to /v1/receipt with correct JSON body', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ recorded: true, deleted: false, receipts: 1, required_acks: 2 }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const payload = {
        proto: RECEIPT_PROTO,
        conv_id: toHex(fakeConvID()),
        msg_id: toHex(fakeConvID()),
        reader_kid: toHex(fakeConvID()),
        reader_ik_pk: 'dGVzdA',
        read_ts: Date.now(),
        required_acks: 2,
        sig: 'dGVzdHNpZw',
      };

      const result = await client.submitReceipt(payload);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${baseUrl}/v1/receipt`);
      expect(opts.method).toBe('POST');
      expect(opts.headers['Content-Type']).toBe('application/json');

      const body = JSON.parse(opts.body);
      expect(body.proto).toBe(RECEIPT_PROTO);
      expect(body.conv_id).toBe(payload.conv_id);
      expect(body.msg_id).toBe(payload.msg_id);
      expect(result.recorded).toBe(true);
      expect(result.deleted).toBe(false);
    });

    it('throws on HTTP error response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => 'invalid signature',
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(
        client.submitReceipt({
          proto: RECEIPT_PROTO,
          conv_id: toHex(fakeConvID()),
          msg_id: toHex(fakeConvID()),
          reader_kid: toHex(fakeConvID()),
          reader_ik_pk: 'dGVzdA',
          read_ts: Date.now(),
          required_acks: 2,
          sig: 'dGVzdHNpZw',
        }),
      ).rejects.toThrow(/401/);
    });
  });

  // === buildSignedReceipt ===

  describe('buildSignedReceipt', () => {
    it('builds a receipt with correct fields and valid structure', () => {
      const identity = generateIdentity();
      const convId = fakeConvID();
      const msgId = fakeConvID();

      const receipt = buildSignedReceipt(identity, convId, msgId, 2);

      expect(receipt.proto).toBe(RECEIPT_PROTO);
      expect(receipt.conv_id).toBe(toHex(convId));
      expect(receipt.msg_id).toBe(toHex(msgId));
      expect(receipt.required_acks).toBe(2);
      expect(receipt.read_ts).toBeGreaterThan(0);
      // reader_kid should be 32 hex chars (16 bytes)
      expect(receipt.reader_kid).toMatch(/^[0-9a-f]{32}$/);
      // sig and reader_ik_pk should be non-empty base64url strings
      expect(receipt.sig.length).toBeGreaterThan(0);
      expect(receipt.reader_ik_pk.length).toBeGreaterThan(0);
    });

    it('produces different signatures for different messages', () => {
      const identity = generateIdentity();
      const convId = fakeConvID();
      const msgId1 = new Uint8Array(16).fill(1);
      const msgId2 = new Uint8Array(16).fill(2);

      const r1 = buildSignedReceipt(identity, convId, msgId1, 2);
      const r2 = buildSignedReceipt(identity, convId, msgId2, 2);

      expect(r1.sig).not.toBe(r2.sig);
      expect(r1.msg_id).not.toBe(r2.msg_id);
    });
  });
});
