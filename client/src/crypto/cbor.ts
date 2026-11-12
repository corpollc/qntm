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

const utf8Encoder = new TextEncoder();

function isNodeBuffer(value: unknown): boolean {
  return typeof Buffer !== 'undefined' && Buffer.isBuffer(value);
}

/**
 * Sort object keys for canonical CBOR (RFC 8949 §4.2.1).
 * Keys sorted by encoded UTF-8 byte length first, then unsigned lexicographic bytes.
 * Convert objects to Maps so cbor-x uses minimal map headers.
 */
function toCanonicalMap(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (obj instanceof Uint8Array || isNodeBuffer(obj)) return obj;
  if (Array.isArray(obj)) return obj.map(toCanonicalMap);
  if (typeof obj === 'object') {
    const encodedKeys = Object.keys(obj as Record<string, unknown>).map(key => ({
      key,
      bytes: utf8Encoder.encode(key),
    }));
    // RFC 8949 §4.2.1: sort by encoded UTF-8 key byte length first, then unsigned byte order
    encodedKeys.sort((a, b) => {
      if (a.bytes.length !== b.bytes.length) return a.bytes.length - b.bytes.length;
      for (let i = 0; i < a.bytes.length; i++) {
        if (a.bytes[i] !== b.bytes[i]) return a.bytes[i] - b.bytes[i];
      }
      return 0;
    });
    const map = new Map<string, unknown>();
    for (const { key } of encodedKeys) {
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
