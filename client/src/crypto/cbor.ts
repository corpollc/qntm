import { Encoder, Decoder } from 'cbor-x';

const encoder = new Encoder({
  useRecords: false,
  mapsAsObjects: false,
  tagUint8Array: false,
} as any);

const decoder = new Decoder({
  useRecords: false,
  mapsAsObjects: true,
} as any);

/**
 * Sort object keys for canonical CBOR (RFC 8949 §4.2.1).
 * Keys sorted by encoded byte length first, then lexicographic.
 * Convert objects to Maps so cbor-x uses minimal map headers.
 */
function toCanonicalMap(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) return obj;
  if (Array.isArray(obj)) return obj.map(toCanonicalMap);
  if (typeof obj === 'object') {
    const keys = Object.keys(obj as Record<string, unknown>);
    // RFC 8949 §4.2.1: sort by encoded key bytes (length-first for CBOR strings)
    keys.sort((a, b) => {
      if (a.length !== b.length) return a.length - b.length;
      return a < b ? -1 : a > b ? 1 : 0;
    });
    const map = new Map<string, unknown>();
    for (const key of keys) {
      map.set(key, toCanonicalMap((obj as Record<string, unknown>)[key]));
    }
    return map;
  }
  return obj;
}

export function marshalCanonical(value: unknown): Uint8Array {
  const canonical = toCanonicalMap(value);
  return encoder.encode(canonical);
}

export function unmarshalCanonical<T = unknown>(data: Uint8Array): T {
  return decoder.decode(data) as T;
}
