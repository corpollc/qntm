/** Recipient-sealed guidance intake over an otherwise public qntm conversation. */
import { createInvite, inviteFromURL, inviteToToken, createConversation, deriveConversationKeys, addParticipant } from '../invite/index.js';
import { createMessage, decryptMessage } from '../message/index.js';
import { sealSecret, openSecret } from '../crypto/naclbox.js';
import { keyIDFromPublicKey, base64UrlEncode, base64UrlDecode } from '../identity/index.js';
import type { Identity, OuterEnvelope } from '../types.js';
export { CORPO_GUIDANCE_PROVIDERS } from './providers.js';

export const GUIDANCE_INTAKE_TYPE = 'guidance.sealed.v1';
export const GUIDANCE_PROCESSING_NOTICE = 'Free guidance provided by Corpo. Requests are processed by Grok for triage and may be passed to the Corpo team. No automated substantive advice or response is promised.';
const DOMAIN = 'qntm.guidance.request.v1';
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = (value: string) => Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16));
export interface GuidanceProvider {
  id: string; category: 'legal' | 'ethical' | 'law_enforcement'; name: string;
  kind: 'organization'; offer: string; delivery: 'sealed_intake_v1';
  recipient_key_id: string; recipient_public_key: string; conversation_id: string;
  intake_invite: string; relay_url: string;
}

export function guidanceIntake(provider: GuidanceProvider) {
  if (!['legal', 'ethical', 'law_enforcement'].includes(provider.category) ||
      provider.delivery !== 'sealed_intake_v1' || !/^[0-9a-f]{64}$/.test(provider.recipient_public_key) ||
      !/^[0-9a-f]{32}$/.test(provider.recipient_key_id) || !/^[0-9a-f]{32}$/.test(provider.conversation_id)) throw new Error('Invalid guidance provider');
  const invite = inviteFromURL(provider.intake_invite);
  if (invite.type !== 'direct' || hex(invite.conv_id) !== provider.conversation_id ||
      hex(invite.inviter_ik_pk) !== provider.recipient_public_key ||
      hex(keyIDFromPublicKey(invite.inviter_ik_pk)) !== provider.recipient_key_id) throw new Error('Guidance provider key or intake mismatch');
  return createConversation(invite, deriveConversationKeys(invite));
}

function validateText(question: unknown, context: unknown): asserts question is string {
  if (typeof question !== 'string' || !question.trim() || [...question].length > 4000 ||
      typeof context !== 'string' || [...context].length > 8000) throw new Error('Guidance requires a question of 1–4,000 characters and context of at most 8,000 characters');
}

export function createGuidanceIntake(identity: Identity, provider: GuidanceProvider, question: string, context = '') {
  const intake = guidanceIntake(provider);
  question = question.trim(); context = context.trim(); validateText(question, context);
  const replyInvite = createInvite(identity, 'direct');
  const replyConversation = createConversation(replyInvite, deriveConversationKeys(replyInvite));
  addParticipant(replyConversation, unhex(provider.recipient_public_key));
  const payload = { domain: DOMAIN, category: provider.category, recipient_key_id: provider.recipient_key_id,
    request_id: hex(replyInvite.conv_id), reply_invite: inviteToToken(replyInvite), question, context };
  const sealed = sealSecret(identity.privateKey, unhex(provider.recipient_public_key), new TextEncoder().encode(JSON.stringify(payload)));
  const envelope = createMessage(identity, intake, GUIDANCE_INTAKE_TYPE, new TextEncoder().encode(base64UrlEncode(sealed)), undefined, 7 * 86400);
  return { envelope, replyInvite, replyConversation, requestId: payload.request_id };
}

export function openGuidanceIntake(identity: Identity, provider: GuidanceProvider, envelope: OuterEnvelope) {
  if (hex(identity.publicKey) !== provider.recipient_public_key || envelope.ciphertext.length > 100000) throw new Error('Invalid guidance recipient or request size');
  const message = decryptMessage(envelope, guidanceIntake(provider));
  if (message.inner.body_type !== GUIDANCE_INTAKE_TYPE) throw new Error('Expected a sealed guidance request');
  const raw = openSecret(identity.privateKey, message.inner.sender_ik_pk, base64UrlDecode(new TextDecoder('utf-8', { fatal: true }).decode(message.inner.body)));
  if (raw.length > 60000) throw new Error('Guidance request too large');
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  if (!value || Object.keys(value).sort().join(',') !== 'category,context,domain,question,recipient_key_id,reply_invite,request_id' ||
      value.domain !== DOMAIN || value.category !== provider.category || value.recipient_key_id !== provider.recipient_key_id ||
      typeof value.reply_invite !== 'string' || value.reply_invite.length > 2048) throw new Error('Invalid guidance payload');
  validateText(value.question, value.context);
  const replyInvite = inviteFromURL(value.reply_invite);
  if (replyInvite.type !== 'direct' || hex(replyInvite.inviter_ik_pk) !== hex(message.inner.sender_ik_pk) ||
      value.request_id !== hex(replyInvite.conv_id) || value.request_id === provider.conversation_id) throw new Error('Guidance reply destination does not match sender');
  return { requestId: value.request_id as string, question: value.question, context: value.context as string,
    senderPublicKey: message.inner.sender_ik_pk, senderKeyId: hex(message.inner.sender_kid), replyInvite, message };
}
