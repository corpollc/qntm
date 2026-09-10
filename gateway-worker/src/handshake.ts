/** Invitation admission is proved by the signed relay message, not an operator token. */
import {
  generateIdentity, base64UrlEncode, base64UrlDecode, keyIDFromPublicKey,
  DropboxClient, deserializeEnvelope, decryptMessage, createMessage, serializeEnvelope,
  defaultTTL, openSecret, gatewayAccessHash, gatewayInvitationHash, validateGatewayIdentity,
  GATE_INVITATION_TTL, isValidEd25519PublicKey,
} from '@corpollc/qntm';
import type { Conversation, GatewayInvitation, GatewayBootstrapRequest, GatewayAccess, GatewayInviteBody } from '@corpollc/qntm';
import type { ConversationState } from './types.js';

interface Candidate {
  invitation: GatewayInvitation;
  private_key: string;
  material_hash?: string;
  state?: ConversationState;
  acceptance?: string;
}
export type InvitationRequest = Pick<GatewayInvitation, 'invitation_id' | 'inviter_public_key'>;
const hex = (b: Uint8Array) => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => Uint8Array.from(s.match(/../g)!, x => parseInt(x, 16));
const bytes = (s: string) => new TextEncoder().encode(s);
export function canonicalKey(value: unknown): value is string {
  try { return typeof value === 'string' && base64UrlDecode(value).length === 32 && base64UrlEncode(base64UrlDecode(value)) === value; }
  catch { return false; }
}
export function validInvitationRequest(body: InvitationRequest): boolean {
  return !!body && typeof body.invitation_id === 'string' && /^[0-9a-f]{32}$/.test(body.invitation_id) &&
    canonicalKey(body.inviter_public_key) && isValidEd25519PublicKey(base64UrlDecode(body.inviter_public_key));
}
function conversation(s: ConversationState): Conversation {
  return { id: unhex(s.conv_id), type: 'group', keys: { root: new Uint8Array(32), aeadKey: base64UrlDecode(s.conv_aead_key), nonceKey: base64UrlDecode(s.conv_nonce_key) },
    participants: Object.keys(s.participants).map(base64UrlDecode), createdAt: new Date(s.promoted_at), currentEpoch: s.conv_epoch };
}

export async function createInvitation(storage: DurableObjectStorage, body: InvitationRequest): Promise<Response> {
  if (!validInvitationRequest(body)) return Response.json({ error: 'invalid invitation identity' }, { status: 400 });
  let candidate = await storage.get<Candidate>('handshake');
  if (candidate && !candidate.state && candidate.invitation.expires_at * 1000 <= Date.now()) candidate = undefined;
  if (!candidate) {
    const identity = generateIdentity();
    candidate = { private_key: base64UrlEncode(identity.privateKey), invitation: { ...body,
      gateway_public_key: base64UrlEncode(identity.publicKey), gateway_kid: base64UrlEncode(identity.keyID),
      expires_at: Math.floor(Date.now() / 1000) + GATE_INVITATION_TTL } };
    await storage.put('handshake', candidate);
    await storage.setAlarm(candidate.invitation.expires_at * 1000);
  }
  return Response.json(candidate.invitation);
}

export async function acceptInvitation(storage: DurableObjectStorage, relayUrl: string, body: GatewayBootstrapRequest): Promise<Response> {
  if (!validInvitationRequest(body) || typeof body.sealed !== 'string') return Response.json({ error: 'encrypted invitation required' }, { status: 400 });
  const candidate = await storage.get<Candidate>('handshake');
  if (!candidate || candidate.invitation.invitation_id !== body.invitation_id || candidate.invitation.inviter_public_key !== body.inviter_public_key) {
    return Response.json({ error: 'gateway invitation expired or unavailable; invite again' }, { status: 410 });
  }
  let material: GatewayAccess & { invitation_msg_id: string; invitation_seq: number };
  let materialText: string;
  try {
    materialText = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(openSecret(base64UrlDecode(candidate.private_key), base64UrlDecode(body.inviter_public_key), base64UrlDecode(body.sealed)));
    material = JSON.parse(materialText);
    if (!material || !/^[0-9a-f]{32}$/.test(material.conv_id) || !canonicalKey(material.conv_aead_key) || !canonicalKey(material.conv_nonce_key) ||
      !Number.isSafeInteger(material.conv_epoch) || material.conv_epoch < 0 || !/^[0-9a-f]{32}$/.test(material.invitation_msg_id) ||
      !Number.isSafeInteger(material.invitation_seq) || material.invitation_seq < 1) throw new Error('invalid material');
  } catch { return Response.json({ error: 'invalid encrypted invitation material' }, { status: 400 }); }
  const materialHash = gatewayInvitationHash(materialText);
  if (candidate.material_hash && candidate.material_hash !== materialHash) return Response.json({ error: 'invitation material cannot be replaced' }, { status: 409 });
  if (!candidate.state) {
    if (candidate.invitation.expires_at * 1000 <= Date.now()) return Response.json({ error: 'gateway invitation expired; invite again' }, { status: 410 });
    const { invitation } = candidate;
    const state: ConversationState = {
      conv_id: material.conv_id, private_key: candidate.private_key, public_key: invitation.gateway_public_key, kid: invitation.gateway_kid,
      conv_aead_key: material.conv_aead_key, conv_nonce_key: material.conv_nonce_key, conv_epoch: material.conv_epoch,
      poll_cursor: material.invitation_seq, promoted_at: new Date().toISOString(), gate_promoted: false, rules: [], participants: {}, promotion_floor: 1,
      invitation_id: invitation.invitation_id,
    };
    const conv = conversation(state);
    let invitationText: string;
    let invite: GatewayInviteBody;
    try {
      const replay = await new DropboxClient(relayUrl).receiveMessages(conv.id, material.invitation_seq - 1);
      const envelope = replay.messages.map(deserializeEnvelope).find(e => hex(e.msg_id) === material.invitation_msg_id);
      if (!envelope || envelope.conv_epoch !== material.conv_epoch) throw new Error('invitation not found');
      const message = decryptMessage(envelope, conv);
      if (!message.verified || message.inner.body_type !== 'gate.promote' || base64UrlEncode(message.inner.sender_ik_pk) !== body.inviter_public_key) throw new Error('inviter signature mismatch');
      invitationText = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(message.inner.body);
      invite = JSON.parse(invitationText);
      const access: GatewayAccess = { conv_id: material.conv_id, conv_aead_key: material.conv_aead_key, conv_nonce_key: material.conv_nonce_key, conv_epoch: material.conv_epoch };
      if (invite.type !== 'gate.promote' || invite.invitation_id !== invitation.invitation_id || invite.gateway_kid !== invitation.gateway_kid || invite.gateway_public_key !== invitation.gateway_public_key ||
        invite.conv_id !== material.conv_id || invite.conv_epoch !== material.conv_epoch || invite.expires_at !== invitation.expires_at || invite.keys_hash !== gatewayAccessHash(access)) throw new Error('invitation mismatch');
      const entries = Object.entries(invite.participants);
      const inviterKid = base64UrlEncode(keyIDFromPublicKey(base64UrlDecode(body.inviter_public_key)));
      if (entries.length < 1 || entries.length > 256 || invite.participants[inviterKid] !== body.inviter_public_key || invitation.gateway_kid in invite.participants ||
        entries.some(([kid, pk]) => !validateGatewayIdentity(pk, kid))) throw new Error('invalid invitation participants');
      if (!Number.isSafeInteger(invite.floor) || invite.floor < 1 || invite.floor > entries.length || !Array.isArray(invite.rules) || invite.rules.length > 256 ||
        invite.rules.some(r => typeof r.service !== 'string' || typeof r.endpoint !== 'string' || typeof r.verb !== 'string' || !Number.isSafeInteger(r.m) || r.m < invite.floor || r.m > entries.length)) throw new Error('invalid invitation policy');
      // Check again after relay IO. An unverified candidate never becomes conversation state.
      if (invitation.expires_at * 1000 <= Date.now()) throw new Error('invitation expired');
    } catch { return Response.json({ error: 'signed invitation could not be verified in the conversation' }, { status: 403 }); }
    state.rules = invite.rules;
    state.participants = invite.participants;
    state.promotion_floor = invite.floor;
    const identity = { privateKey: base64UrlDecode(candidate.private_key), publicKey: base64UrlDecode(state.public_key), keyID: base64UrlDecode(state.kid) };
    const acceptance = createMessage(identity, conv, 'gate.accept', bytes(JSON.stringify({
      type: 'gate.accept', invitation_id: invitation.invitation_id, invitation_msg_id: material.invitation_msg_id,
      invitation_hash: gatewayInvitationHash(invitationText), conv_id: state.conv_id, conv_epoch: state.conv_epoch,
      gateway_kid: state.kid, gateway_public_key: state.public_key,
    })), undefined, defaultTTL());
    candidate.material_hash = materialHash;
    candidate.state = state;
    candidate.acceptance = base64UrlEncode(serializeEnvelope(acceptance));
    // The exact signed envelope is the durable outbox; every retry has the same msg_id.
    await storage.put('handshake', candidate);
  }
  const joined = await finishAcceptance(storage, relayUrl);
  return Response.json({ status: joined ? 'joined' : 'waiting', gateway_public_key: candidate.invitation.gateway_public_key,
    gateway_kid: candidate.invitation.gateway_kid, invitation_id: candidate.invitation.invitation_id }, { status: joined ? 200 : 202 });
}

export async function finishAcceptance(storage: DurableObjectStorage, relayUrl: string): Promise<boolean> {
  const active = await storage.get<ConversationState>('conv_state');
  if (active?.gate_promoted) return true;
  const candidate = await storage.get<Candidate>('handshake');
  if (!candidate) return false;
  if (!candidate.state || !candidate.acceptance) {
    if (candidate.invitation.expires_at * 1000 <= Date.now()) await storage.delete('handshake');
    return false;
  }
  if (deserializeEnvelope(base64UrlDecode(candidate.acceptance)).expiry_ts * 1000 <= Date.now()) {
    await storage.delete('handshake');
    return false;
  }
  await storage.setAlarm(Date.now() + 5000);
  try {
    await new DropboxClient(relayUrl).postMessage(unhex(candidate.state.conv_id), base64UrlDecode(candidate.acceptance));
  } catch { return false; }
  await storage.put('conv_state', { ...candidate.state, gate_promoted: true });
  return true;
}
