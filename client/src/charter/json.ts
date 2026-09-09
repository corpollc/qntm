/** RFC 8785 JCS. Object keys sort by UTF-16 code units, including integer-looking keys. */
export type CharterJson = null | boolean | number | string | CharterJson[] | { [key: string]: CharterJson };
const MAX_DEPTH = 128;

function validUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('JCS rejects lone surrogates');
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new Error('JCS rejects lone surrogates');
  }
}

export function canonicalizeCharterJson(value: unknown): string {
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): string => {
    if (depth > MAX_DEPTH) throw new Error('JSON nesting exceeds 128 levels');
    if (item === null || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new Error('JCS requires finite numbers');
      return JSON.stringify(item);
    }
    if (typeof item === 'string') { validUnicode(item); return JSON.stringify(item); }
    if (typeof item !== 'object') throw new Error('Value is not JSON');
    if (ancestors.has(item)) throw new Error('JSON must not contain cycles');
    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        const values: string[] = [];
        for (let i = 0; i < item.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
          if (!descriptor || !('value' in descriptor)) throw new Error('JSON arrays must contain data values');
          values.push(visit(descriptor.value, depth + 1));
        }
        if (Reflect.ownKeys(item).length !== item.length + 1) throw new Error('JSON arrays cannot have extra properties');
        return `[${values.join(',')}]`;
      }
      if (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null) throw new Error('JSON requires plain objects');
      const keys = Reflect.ownKeys(item);
      if (keys.some(key => typeof key !== 'string')) throw new Error('JSON object keys must be strings');
      return `{${(keys as string[]).sort().map(key => {
        validUnicode(key);
        const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
        if (!descriptor.enumerable || !('value' in descriptor)) throw new Error('JSON objects require enumerable data properties');
        return `${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`;
      }).join(',')}}`;
    } finally { ancestors.delete(item); }
  };
  return visit(value, 0);
}

export function charterJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeCharterJson(value));
}

/** Parse before canonicalizing so duplicate (including escaped-equivalent) keys cannot disappear. */
export function parseCharterJson(text: string): CharterJson {
  let position = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[position] ?? '\0')) position++; };
  const fail = (): never => { throw new Error(`Invalid or duplicate-key JSON at offset ${position}`); };
  const string = (): string => {
    const start = position++;
    while (position < text.length) {
      const char = text[position++];
      if (char === '\\') { position++; continue; }
      if (char === '"') {
        const result: string = JSON.parse(text.slice(start, position));
        validUnicode(result);
        return result;
      }
    }
    return fail();
  };
  const value = (depth: number): CharterJson => {
    if (depth > MAX_DEPTH) throw new Error('JSON nesting exceeds 128 levels');
    ws();
    const char = text[position];
    if (char === '"') return string();
    if (char === '[' || char === '{') {
      position++; ws();
      const isArray = char === '[';
      const end = isArray ? ']' : '}';
      const array: CharterJson[] = [];
      const object: Record<string, CharterJson> = Object.create(null);
      if (text[position] === end) { position++; return isArray ? array : object; }
      while (true) {
        if (isArray) array.push(value(depth + 1));
        else {
          ws(); if (text[position] !== '"') return fail();
          const key = string(); ws();
          if (Object.hasOwn(object, key) || text[position++] !== ':') return fail();
          object[key] = value(depth + 1);
        }
        ws();
        if (text[position] === end) { position++; return isArray ? array : object; }
        if (text[position++] !== ',') return fail();
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(position));
    if (!match) return fail();
    position += match[0].length;
    const result = JSON.parse(match[0]) as CharterJson;
    if (typeof result === 'number' && !Number.isFinite(result)) return fail();
    return result;
  };
  const result = value(0); ws();
  if (position !== text.length) return fail();
  return result;
}
