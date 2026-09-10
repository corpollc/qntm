/** Public group locators. These contain no key material granting group access. */
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { isValidEd25519PublicKey } from '../crypto/ed25519.js';
import { base64UrlDecode, base64UrlEncode, uint8ArrayEquals } from '../identity/index.js';

export interface GroupLocator {
  conversationId: Uint8Array;
  inviterPublicKey: Uint8Array;
  relayUrl: string;
}
export const MAX_GROUP_LINK_BYTES = 4096;
function transportURL(value: unknown): string {
  if (typeof value !== 'string' || !/^https?:\/\//i.test(value) || value.length > 2048 || /[\s\x00-\x1f\x7f?#\\]/u.test(value)) {
    throw new Error('Invalid group relay URL');
  }
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new Error('Invalid group relay URL');
  }
  return value.replace(/\/+$/, '');
}
function validate(locator: GroupLocator): void {
  if (!(locator.conversationId instanceof Uint8Array) || locator.conversationId.length !== 16
    || !isValidEd25519PublicKey(locator.inviterPublicKey)) throw new Error('Invalid group locator identity');
  transportURL(locator.relayUrl);
}
export function createGroupLink(locator: GroupLocator, baseURL = 'https://chat.corpo.llc'): string {
  validate(locator);
  if (!/^https?:\/\//i.test(baseURL) || /[\s\x00-\x1f\x7f\\]/u.test(baseURL)) throw new Error('Invalid group link URL');
  const base = new URL(baseURL);
  if (!['https:', 'http:'].includes(base.protocol) || !base.hostname || base.username || base.password) {
    throw new Error('Invalid group link URL');
  }
  const wire = marshalCanonical({ v: 1, type: 'qntm.group', conv_id: locator.conversationId,
    inviter_ik_pk: locator.inviterPublicKey, relay_url: transportURL(locator.relayUrl) });
  if (wire.length > MAX_GROUP_LINK_BYTES) throw new Error('Group link exceeds size limit');
  base.search = '';
  base.hash = `group=${base64UrlEncode(wire)}`;
  return base.toString();
}
/** Parsing does not authorize the inviter or contact the relay. The host confirms
 * the link/contact and relay before fetching, and still needs a sealed welcome. */
export function parseGroupLink(input: string): GroupLocator {
  if (typeof input !== 'string' || input.length > 8192) throw new Error('Invalid group link size');
  if (!/^https?:\/\//i.test(input) || /[\s\x00-\x1f\x7f\\]/u.test(input)) throw new Error('Invalid group link');
  const url = new URL(input);
  if (!['https:', 'http:'].includes(url.protocol) || !url.hostname || url.username || url.password
    || url.search || !/^#group=[A-Za-z0-9_-]+$/.test(url.hash)) throw new Error('Invalid group link');
  const encoded = url.hash.slice(7), wire = base64UrlDecode(encoded);
  if (!wire.length || wire.length > MAX_GROUP_LINK_BYTES || base64UrlEncode(wire) !== encoded) throw new Error('Invalid group locator encoding');
  const value = unmarshalCanonical<Record<string, unknown>>(wire);
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',') !== 'conv_id,inviter_ik_pk,relay_url,type,v'
    || value.v !== 1 || value.type !== 'qntm.group' || !uint8ArrayEquals(wire, marshalCanonical(value))) {
    throw new Error('Invalid group locator');
  }
  const locator = { conversationId: value.conv_id as Uint8Array,
    inviterPublicKey: value.inviter_ik_pk as Uint8Array, relayUrl: value.relay_url as string };
  validate(locator);
  locator.relayUrl = transportURL(locator.relayUrl);
  return locator;
}
