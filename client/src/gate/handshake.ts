/** Participant-initiated gateway invitations. The signed chat is the authority. */
import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical } from '../crypto/cbor.js';
import { sealSecret } from '../crypto/naclbox.js';
import { base64UrlDecode, base64UrlEncode, keyIDFromPublicKey } from '../identity/index.js';
import type { Conversation, Identity } from '../types.js';

export const GATE_INVITATION_TTL = 600;
export interface GatewayInvitation {
  invitation_id: string;
  inviter_public_key: string;
  gateway_public_key: string;
  gateway_kid: string;
  expires_at: number;
}
export interface GatewayAccess {
  conv_id: string;
  conv_aead_key: string;
  conv_nonce_key: string;
  conv_epoch: number;
}
export interface GatewayInviteBody {
  type: 'gate.promote';
  invitation_id: string;
  conv_id: string;
  conv_epoch: number;
  gateway_kid: string;
  gateway_public_key: string;
  expires_at: number;
  keys_hash: string;
  participants: Record<string, string>;
  rules: Array<{ service: string; endpoint: string; verb: string; m: number }>;
  floor: number;
}
export interface GatewayAcceptance {
  type: 'gate.accept';
  invitation_id: string;
  invitation_msg_id: string;
  invitation_hash: string;
  conv_id: string;
  conv_epoch: number;
  gateway_kid: string;
  gateway_public_key: string;
}
export interface GatewayBootstrapRequest {
  invitation_id: string;
  inviter_public_key: string;
  sealed: string;
}
const suite = new QSP1Suite();
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function gatewayAccess(conv: Conversation): GatewayAccess {
  return { conv_id: hex(conv.id), conv_aead_key: base64UrlEncode(conv.keys.aeadKey),
    conv_nonce_key: base64UrlEncode(conv.keys.nonceKey), conv_epoch: conv.currentEpoch };
}
export function gatewayAccessHash(access: GatewayAccess): string {
  return hex(suite.hash(marshalCanonical(access)));
}
/** Hash the exact signed UTF-8 body, avoiding JSON canonicalization differences. */
export function gatewayInvitationHash(body: string): string {
  return hex(suite.hash(new TextEncoder().encode(body)));
}
export function validateGatewayIdentity(publicKey: string, kid: string): boolean {
  try {
    const pk = base64UrlDecode(publicKey);
    return pk.length === 32 && base64UrlEncode(pk) === publicKey && base64UrlEncode(keyIDFromPublicKey(pk)) === kid;
  } catch { return false; }
}
export function createGatewayInviteBody(invite: GatewayInvitation, conv: Conversation, participants: Record<string, string>, floor: number): GatewayInviteBody {
  if (!validateGatewayIdentity(invite.gateway_public_key, invite.gateway_kid)) throw new Error('Invalid gateway identity');
  if (!Number.isSafeInteger(floor) || floor < 1 || floor > Object.keys(participants).length) throw new Error('Invalid gateway approval threshold');
  return { type: 'gate.promote', invitation_id: invite.invitation_id, conv_id: hex(conv.id),
    conv_epoch: conv.currentEpoch, gateway_kid: invite.gateway_kid, gateway_public_key: invite.gateway_public_key,
    expires_at: invite.expires_at, keys_hash: gatewayAccessHash(gatewayAccess(conv)), participants,
    rules: [{ service: '*', endpoint: '*', verb: '*', m: floor }], floor };
}
export function sealGatewayBootstrap(identity: Identity, invitation: GatewayInvitation, conv: Conversation, messageId: string, sequence: number): GatewayBootstrapRequest {
  const material = { ...gatewayAccess(conv), invitation_msg_id: messageId, invitation_seq: sequence };
  return { invitation_id: invitation.invitation_id, inviter_public_key: base64UrlEncode(identity.publicKey),
    sealed: base64UrlEncode(sealSecret(identity.privateKey, base64UrlDecode(invitation.gateway_public_key), new TextEncoder().encode(JSON.stringify(material)))) };
}
/** Only call with the authenticated envelope sender and a locally verified invitation. */
export function matchesGatewayAcceptance(acceptance: GatewayAcceptance, senderKid: string, invitationMsgId: string, invitationText: string): boolean {
  try {
    const invite = JSON.parse(invitationText) as GatewayInviteBody;
    return invite.type === 'gate.promote' && acceptance.type === 'gate.accept' &&
      validateGatewayIdentity(invite.gateway_public_key, invite.gateway_kid) &&
      senderKid === invite.gateway_kid && acceptance.gateway_kid === invite.gateway_kid &&
      acceptance.gateway_public_key === invite.gateway_public_key && acceptance.invitation_id === invite.invitation_id &&
      acceptance.invitation_msg_id === invitationMsgId && acceptance.invitation_hash === gatewayInvitationHash(invitationText) &&
      acceptance.conv_id === invite.conv_id && acceptance.conv_epoch === invite.conv_epoch;
  } catch { return false; }
}
