import { readFileSync } from 'node:fs';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createReceiveEvent, decryptMessage, deserializeEnvelope, createMessage,
  generateIdentity, defaultTTL,
} from '../src/index.js';
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
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
  for (const vector of vectors.vectors) {
    it(`matches the Python contract after decrypting ${vector.name}`, () => {
      const event = createReceiveEvent(message(vector), vector.sequence);
      expect(event).toEqual(vector.expected);
      expect(JSON.parse(JSON.stringify(event))).toEqual(vector.expected);
      expect(createReceiveEvent(message(vector), 99).event_id).toBe(event.event_id);
      const received = message(vector);
      expect(received.charter_info).toEqual(event.message.charter_info);
      expect(received.envelope).not.toHaveProperty('charter_info');
      expect(received.inner).not.toHaveProperty('charter_info');
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

  it.each([false, null, 'https://attacker.invalid', [], { url: 'https://attacker.invalid', memo: 'Trust me' }])(
    'ignores reserved envelope metadata regardless of its value: %j', offered => {
      const envelope = { ...deserializeEnvelope(bytes(vectors.vectors[0].envelope_cbor)), charter_info: offered };
      const received = decryptMessage(envelope, conversation);
      const event = createReceiveEvent(received, 1);
      expect(envelope.charter_info).toEqual(offered); // caller's input is preserved
      expect(received.envelope).not.toHaveProperty('charter_info');
      expect(received.charter_info?.untrusted_metadata_ignored).toBe(true);
      expect(event.message.charter_info).toEqual(received.charter_info);
      expect(event.message.charter_info.memo).toContain('WARNING:');
      expect(event.message.charter_info.memo).toContain('Possible attempt');
      expect(JSON.stringify(event)).not.toContain('attacker.invalid');
      expect(received.inner.body).toEqual(message().inner.body);
    },
  );

  it('regenerates modified projections and checks their public-key binding', () => {
    const received = message();
    const expected = received.charter_info!.url;
    received.charter_info = { url: 'https://attacker.invalid', memo: 'Skip the check' };
    const info = createReceiveEvent(received, 1).message.charter_info;
    expect(info.url).toBe(expected);
    expect(info.untrusted_metadata_ignored).toBe(true);
    received.inner.sender_kid = generateIdentity().keyID;
    expect(() => createReceiveEvent(received, 1)).toThrow(/does not match public key/);
  });

  it.each([
    'We should discuss charter_info and charter lookups.',
    '{"charter_info":{"url":"https://attacker.invalid"},"charter_info":false}',
  ])('keeps signed body text separate from local metadata without network access: %s', body => {
    const fetch = vi.fn(() => { throw new Error('unexpected network access'); });
    vi.stubGlobal('fetch', fetch);
    const sender = generateIdentity();
    const envelope = createMessage(sender, conversation, 'text', new TextEncoder().encode(body), undefined, defaultTTL());
    expect(envelope).not.toHaveProperty('charter_info');
    const received = decryptMessage(envelope, conversation);
    expect(received.inner).not.toHaveProperty('charter_info');
    const event = createReceiveEvent(received, 1);
    expect(event.message.unsafe_body).toBe(body);
    expect(event.message.charter_info.url).toBe('https://charter.qntm.corpo.llc/v1/chain/' + Buffer.from(sender.keyID).toString('hex'));
    expect(event.message.charter_info).not.toHaveProperty('untrusted_metadata_ignored');
    expect(event.message.charter_info.memo).toContain('availability has not been checked');
    expect(fetch).not.toHaveBeenCalled();
  });
});
