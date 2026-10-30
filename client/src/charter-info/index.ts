/** Receiver-generated metadata only: no HTTP, discovery or policy assessment. */
import { keyIDFromPublicKey, uint8ArrayEquals } from '../identity/index.js';
import type { CharterInfo, Message } from '../types.js';

const URL_PREFIX = 'https://charter.qntm.corpo.llc/v1/chain/';
const MEMO = "Charters describe an agent's rights and responsibilities. You may wish to verify this sender's charter. "
  + 'Chartering is optional; availability has not been checked.';
const WARNING = ' WARNING: Untrusted charter metadata was supplied and ignored. '
  + 'Possible attempt to obscure charter information; verify independently.';
const owns = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);

/** Requires a verified decrypt result; does not repeat signature verification. */
export function localCharterInfo(message: Message): CharterInfo {
  if (message.verified !== true) throw new Error('charter info requires a verified message');
  const { inner, envelope } = message;
  const kid = inner.sender_kid;
  if (!(kid instanceof Uint8Array) || kid.length !== 16) throw new Error('sender key ID must be 16 bytes');
  if (!(inner.sender_ik_pk instanceof Uint8Array) || inner.sender_ik_pk.length !== 32) {
    throw new Error('sender public key must be 32 bytes');
  }
  if (!uint8ArrayEquals(keyIDFromPublicKey(inner.sender_ik_pk), kid)) {
    throw new Error('sender key ID does not match public key');
  }
  const url = URL_PREFIX + Array.from(kid, byte => byte.toString(16).padStart(2, '0')).join('');
  let ignored = owns(inner, 'charter_info') || owns(envelope, 'charter_info');
  if (owns(message, 'charter_info')) {
    const prior = message.charter_info;
    // The local warning survives removal of the raw extension fields. Altered
    // projections are always replaced; never copy their URL or memo.
    const canonical = prior !== null && typeof prior === 'object' && !Array.isArray(prior)
      && Object.keys(prior).length === 2 && owns(prior, 'url') && owns(prior, 'memo')
      && prior.url === url && prior.memo === MEMO;
    ignored ||= !canonical;
  }
  return { url, memo: MEMO + (ignored ? WARNING : ''), ...(ignored ? { untrusted_metadata_ignored: true as const } : {}) };
}

export function withLocalCharterInfo(message: Message): Message {
  const charter_info = localCharterInfo(message);
  const envelope = { ...message.envelope };
  const inner = { ...message.inner };
  delete (envelope as unknown as Record<string, unknown>).charter_info;
  delete (inner as unknown as Record<string, unknown>).charter_info;
  return { ...message, envelope, inner, charter_info };
}
