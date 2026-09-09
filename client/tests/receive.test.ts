import { readFileSync } from 'node:fs';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createReceiveEvent, decryptMessage, deserializeEnvelope } from '../src/index.js';
import type { Conversation } from '../src/index.js';

const vectors = JSON.parse(readFileSync(new URL('./receive-event-vectors.json', import.meta.url), 'utf8'));
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));
const conversation: Conversation = {
  id: bytes(vectors.conversation_id), type: 'direct', currentEpoch: 0,
  keys: { root: new Uint8Array(32), aeadKey: bytes(vectors.aead_key), nonceKey: bytes(vectors.nonce_key) },
  participants: [], createdAt: new Date(0),
};

function message(vector = vectors.vectors[0]) {
  return decryptMessage(deserializeEnvelope(bytes(vector.envelope_cbor)), conversation);
}

describe('portable receive events', () => {
  beforeEach(() => { vi.spyOn(Date, 'now').mockReturnValue(1773122903 * 1000); });
  afterEach(() => { vi.restoreAllMocks(); });
  for (const vector of vectors.vectors) {
    it(`matches the Python contract after decrypting ${vector.name}`, () => {
      const event = createReceiveEvent(message(vector), vector.sequence);
      expect(event).toEqual(vector.expected);
      expect(JSON.parse(JSON.stringify(event))).toEqual(vector.expected);
      expect(createReceiveEvent(message(vector), 99).event_id).toBe(event.event_id);
    });
  }

  it('rejects unverified messages and invalid identifiers', () => {
    const received = message();
    expect(() => createReceiveEvent({ ...received, verified: false }, 1)).toThrow(/verified/);
    received.inner.sender_kid = new Uint8Array(3);
    expect(() => createReceiveEvent(received, 1)).toThrow(/16 bytes/);
  });

  it.each([0, -1, 1.5, NaN, Infinity, 2 ** 53])('rejects invalid sequence %s', sequence => {
    expect(() => createReceiveEvent(message(), sequence)).toThrow(/safe integers/);
  });

  it('never turns unauthenticated ciphertext into an event', () => {
    const envelope = deserializeEnvelope(bytes(vectors.vectors[0].envelope_cbor));
    envelope.ciphertext[0] ^= 1;
    expect(() => createReceiveEvent(decryptMessage(envelope, conversation), 1)).toThrow();
  });
});
