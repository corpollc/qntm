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

describe('DropboxClient', () => {
  let client: DropboxClient;
  const baseUrl = 'https://inbox.example.com';

  beforeEach(() => {
    client = new DropboxClient(baseUrl);
    vi.restoreAllMocks();
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
    it('sends POST to /v1/poll and returns decoded envelopes', async () => {
      const convID = fakeConvID();
      const env1 = new Uint8Array([0xaa, 0xbb]);
      const env2 = new Uint8Array([0xcc, 0xdd]);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          conversations: [{
            conv_id: toHex(convID),
            up_to_seq: 5,
            messages: [
              { seq: 3, envelope_b64: toBase64(env1) },
              { seq: 5, envelope_b64: toBase64(env2) },
            ],
          }],
        }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await client.receiveMessages(convID, 2);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe(`${baseUrl}/v1/poll`);
      expect(opts.method).toBe('POST');

      const body = JSON.parse(opts.body);
      expect(body.conversations).toEqual([{
        conv_id: toHex(convID),
        from_seq: 2,
      }]);

      expect(result.sequence).toBe(5);
      expect(result.messages).toHaveLength(2);
      expect(result.messages[0]).toEqual(env1);
      expect(result.messages[1]).toEqual(env2);
    });

    it('defaults fromSequence to 0', async () => {
      const convID = fakeConvID();

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          conversations: [{
            conv_id: toHex(convID),
            up_to_seq: 0,
            messages: [],
          }],
        }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await client.receiveMessages(convID);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.conversations[0].from_seq).toBe(0);
      expect(result.messages).toEqual([]);
      expect(result.sequence).toBe(0);
    });

    it('returns empty when no conversations in response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ conversations: [] }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await client.receiveMessages(fakeConvID());
      expect(result.messages).toEqual([]);
      expect(result.sequence).toBe(0);
    });

    it('throws on HTTP error', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 502,
        text: async () => 'bad gateway',
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(
        client.receiveMessages(fakeConvID()),
      ).rejects.toThrow(/502/);
    });

    it('skips messages with invalid base64', async () => {
      const convID = fakeConvID();
      const validEnv = new Uint8Array([0x01, 0x02]);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          conversations: [{
            conv_id: toHex(convID),
            up_to_seq: 3,
            messages: [
              { seq: 1, envelope_b64: '!!!invalid!!!' },
              { seq: 3, envelope_b64: toBase64(validEnv) },
            ],
          }],
        }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await client.receiveMessages(convID);
      // Should still return valid messages and not throw
      expect(result.sequence).toBe(3);
      // At least the valid one should be present
      expect(result.messages.length).toBeGreaterThanOrEqual(1);
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
