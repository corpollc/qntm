import { describe, it, expect } from 'vitest';
import { createGroupLink, parseGroupLink, generateIdentity, marshalCanonical, unmarshalCanonical,
  base64UrlDecode, base64UrlEncode } from '../src/index.js';

const locator = () => ({ conversationId: new Uint8Array(16).fill(9), inviterPublicKey: generateIdentity().publicKey,
  relayUrl: 'https://inbox.qntm.corpo.llc' });

describe('Group locator links', () => {
  it('contains only public routing and contact information in the fragment', () => {
    const value = locator();
    const link = createGroupLink(value, 'https://chat.corpo.llc/path?old=secret#old-secret');
    expect(parseGroupLink(link)).toEqual(value);
    const url = new URL(link);
    expect(url.pathname).toBe('/path');
    expect(url.search).toBe('');
    expect(url.hash.startsWith('#group=')).toBe(true);
    const body = unmarshalCanonical<any>(base64UrlDecode(url.hash.slice(7)));
    expect(Object.keys(body).sort()).toEqual(['conv_id', 'inviter_ik_pk', 'relay_url', 'type', 'v']);
    expect(link).not.toContain('secret');
  });
  it('preserves an explicitly configured local relay without performing I/O', () => {
    const value = { ...locator(), relayUrl: 'http://127.0.0.1:1234/' };
    expect(parseGroupLink(createGroupLink(value)).relayUrl).toBe('http://127.0.0.1:1234');
  });
  it.each(['file:///etc/passwd', 'https://user:pass@example.com', 'https://example.com/?secret=x',
    'https://example.com/#fragment', 'https:example.com', 'https://example.com:99999', 'https://example.com\\path'])
  ('rejects invalid relay %s', relayUrl => {
    expect(() => createGroupLink({ ...locator(), relayUrl })).toThrow();
  });
  it('rejects unknown fields, weak pins, malformed encodings and query-based locators', () => {
    const value = locator(), url = new URL(createGroupLink(value));
    const body = unmarshalCanonical<any>(base64UrlDecode(url.hash.slice(7)));
    for (const invalid of [{ ...body, group_key: new Uint8Array(32) }, { ...body, inviter_ik_pk: new Uint8Array(32) },
      { ...body, conv_id: new Uint8Array(15) }, { ...body, v: 2 }, { ...body, type: 'qntm.join' }]) {
      url.hash = `group=${base64UrlEncode(marshalCanonical(invalid))}`;
      expect(() => parseGroupLink(url.toString())).toThrow();
    }
    expect(() => parseGroupLink(createGroupLink(value).replace('#group=', '?group='))).toThrow();
    expect(() => parseGroupLink(`${createGroupLink(value)}=`)).toThrow();
    expect(() => parseGroupLink(`https://chat.corpo.llc/#group=${'a'.repeat(9000)}`)).toThrow();
  });
});
