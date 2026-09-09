import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkExpiry, decryptMessage, unmarshalCanonical, validateEnvelope } from '../src/index.js';
import type { Conversation, OuterEnvelope } from '../src/index.js';

const fixture = JSON.parse(readFileSync(new URL('./receive-event-vectors.json', import.meta.url), 'utf8'));
const times = JSON.parse(readFileSync(new URL('./message-time-vectors.json', import.meta.url), 'utf8'));
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const envelope = (): OuterEnvelope => unmarshalCanonical(bytes(fixture.vectors[0].envelope_cbor));
const conversation: Conversation = {
  id: bytes(fixture.conversation_id), type: 'direct', currentEpoch: 0, participants: [], createdAt: new Date(0),
  keys: { root: new Uint8Array(32), aeadKey: bytes(fixture.aead_key), nonceKey: bytes(fixture.nonce_key) },
};
afterEach(() => vi.restoreAllMocks());

describe('Python/TypeScript expiry policy on identical encrypted bytes', () => {
  for (const test of times) {
    it(test.name, () => {
      const env = envelope();
      vi.spyOn(Date, 'now').mockReturnValue(((env as any)[test.relative_to] + test.offset) * 1000);
      expect(checkExpiry(env)).toBe(test.expired);
      for (const [allowExpired, accepted] of [[false, test.live], [true, test.history]]) {
        const decrypt = () => decryptMessage(env, conversation, { allowExpired });
        if (accepted) expect(decrypt().verified).toBe(true);
        else expect(decrypt).toThrow(/expired|future/);
      }
    });
  }

  it('historical decryption still authenticates ciphertext and signed metadata', () => {
    const env = envelope();
    vi.spyOn(Date, 'now').mockReturnValue((env.expiry_ts + 1) * 1000);
    env.ciphertext[0] ^= 1;
    expect(() => decryptMessage(env, conversation, { allowExpired: true })).toThrow();
    const altered = { ...envelope(), expiry_ts: env.expiry_ts + 1 };
    expect(() => decryptMessage(altered, conversation, { allowExpired: true })).toThrow(/AAD/);
    expect(() => decryptMessage(envelope(), { ...conversation, id: new Uint8Array(16) }, { allowExpired: true })).toThrow(/conversation/);
  });

  for (const field of ['created_ts', 'expiry_ts'] as const) {
    it.each([NaN, Infinity, 1.5, 2 ** 53, '1780000000', true, null])(`rejects non-integer ${field}: %s`, value => {
      expect(() => validateEnvelope({ ...envelope(), [field]: value } as OuterEnvelope)).toThrow(/timestamp/);
    });
  }
});
