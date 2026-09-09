/** Authenticated conversation state shared by local hosts. No I/O or permissions. */
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlDecode, base64UrlEncode, keyIDFromPublicKey } from '../identity/index.js';
import { decryptMessage, serializeEnvelope } from '../message/index.js';
import { parseGroupGenesisBody, parseGroupAddBody, parseGroupRemoveBody, parseGroupRekeyBody } from '../group/index.js';
import type { Conversation, Identity, Message, OuterEnvelope } from '../types.js';
import { gatewayAccess, gatewayAccessHash } from './handshake.js';
import type { GatewayInviteBody } from './handshake.js';
import { parseGatewayBody, requireGateway, validateGatewayContext, gatewayParticipants } from './workflow-parse.js';
import { verifyGatewayMessage } from './workflow-message.js';
import type { VerifiedGatewayEvent, GatewayReferences } from './workflow-message.js';
import { findGateRequest, findGatewayProposal } from './workflow-history.js';
import type { GatewayContext } from './workflow-types.js';

const suite = new QSP1Suite();
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const groupTypes = new Set(['group_genesis', 'group_add', 'group_remove', 'group_rekey']);
export interface GatewaySessionState {
  version: 1;
  /** Public keys learned from an invite, authenticated messages, or gateway membership. */
  participants: Record<string, string>;
  gateway?: {
    accepted: boolean;
    context: GatewayContext;
    invitation: { messageId: string; text: string; body: GatewayInviteBody };
  };
  removed: boolean;
  events: VerifiedGatewayEvent[];
  seen: Record<string, string>;
}
interface ConversationEventBase {
  conversation: Conversation;
  state: GatewaySessionState;
  /** Display text; group CBOR is converted to JSON with base64url byte fields. */
  text: string;
}
export type ConversationEvent = ConversationEventBase & (
  { duplicate: true } | { duplicate: false; message: Message; gatewayEvent?: VerifiedGatewayEvent }
);

/** Hosts must persist the returned state and updated conversation keys together.
 * A saved state is a trusted local checkpoint, not evidence to accept over a network. */
export function createGatewaySession(conversation: Conversation, publicKeys: Uint8Array[]): GatewaySessionState {
  const known = new Set(conversation.participants.map(hex));
  const participants: Record<string, string> = {};
  for (const pk of publicKeys) {
    requireGateway(pk.length === 32, 'Invalid participant public key');
    const kid = keyIDFromPublicKey(pk);
    requireGateway(known.has(hex(kid)), 'Public key is not a known conversation participant');
    participants[base64UrlEncode(kid)] = base64UrlEncode(pk);
  }
  return { version: 1, participants, removed: false, events: [], seen: {} };
}

export function sessionGatewayContext(state: GatewaySessionState): GatewayContext {
  requireGateway(!state.removed, 'You have been removed from this conversation');
  requireGateway(state.gateway?.accepted, 'No accepted gateway in this conversation');
  validateGatewayContext(state.gateway.context);
  return structuredClone(state.gateway.context);
}

/** Process in relay order, after deduplicating transport sequences. Expiry and
 * AEAD verification are mandatory. Invalid input never mutates the supplied state.
 * Caller decides whether to display/dispatch the result and owns cursor commits. */
export function receiveConversationEvent(envelope: OuterEnvelope, conversation: Conversation,
  identity: Identity, previous: GatewaySessionState): ConversationEvent {
  requireGateway(previous.version === 1, 'Unsupported conversation state version');
  const id = hex(envelope.msg_id), digest = hex(suite.hash(serializeEnvelope(envelope)));
  if (previous.seen[id]) {
    requireGateway(previous.seen[id] === digest, 'Conflicting message ID');
    // Exact previously authenticated bytes need no old key and produce no event.
    return { conversation, state: previous, text: '', duplicate: true };
  }
  requireGateway(envelope.conv_epoch === conversation.currentEpoch, 'Envelope epoch differs from current conversation');
  const message = decryptMessage(envelope, conversation);
  const sender = base64UrlEncode(message.inner.sender_kid), pk = base64UrlEncode(message.inner.sender_ik_pk);
  const bodyType = message.inner.body_type, bodyBytes = new Uint8Array(message.inner.body);
  let text = new TextDecoder().decode(bodyBytes);
  const state = structuredClone(previous);
  const next = { ...conversation, keys: { ...conversation.keys }, participants: [...conversation.participants] };
  if (!state.gateway?.accepted && next.participants.some(kid => base64UrlEncode(kid) === sender)) state.participants[sender] = pk;
  let gatewayEvent: VerifiedGatewayEvent | undefined;
  if (bodyType === 'gate.promote') {
    const body = parseGatewayBody(bodyType, bodyBytes) as GatewayInviteBody;
    requireGateway(!state.gateway?.accepted, 'Gateway is already accepted');
    requireGateway(state.participants[sender] === pk, 'Gateway inviter is not a known participant');
    requireGateway(body.keys_hash === gatewayAccessHash(gatewayAccess(next)), 'Invitation keys differ from this conversation');
    for (const [kid, key] of Object.entries(state.participants)) requireGateway(body.participants[kid] === key, 'Invitation changes a known participant');
    for (const kid of next.participants) requireGateway(Object.hasOwn(body.participants, base64UrlEncode(kid)), 'Invitation omits a known participant');
    const context: GatewayContext = { conversationId: hex(next.id), epoch: next.currentEpoch,
      gateway: { kid: body.gateway_kid, publicKey: body.gateway_public_key },
      participants: body.participants, floor: body.floor, rules: body.rules };
    gatewayEvent = verifyGatewayMessage(message, context);
    state.gateway = { accepted: false, context, invitation: { messageId: id, text, body } };
  } else if (bodyType.startsWith('gate.') || bodyType.startsWith('gov.')) {
    requireGateway(state.gateway, 'Gateway event has no verified invitation');
    requireGateway(bodyType === 'gate.accept' || state.gateway.accepted, 'Gateway has not accepted its invitation');
    const body = parseGatewayBody(bodyType, bodyBytes);
    const context = state.gateway.context;
    const references: GatewayReferences = {
      invitation: state.gateway.invitation,
      request: 'request_id' in body ? findGateRequest(state.events, context.conversationId, body.request_id) : undefined,
      proposal: 'proposal_id' in body ? findGatewayProposal(state.events, context.conversationId, body.proposal_id) : undefined,
    };
    gatewayEvent = verifyGatewayMessage(message, context, references);
    if (body.type === 'gate.accept') {
      requireGateway(envelope.created_ts <= state.gateway.invitation.body.expires_at, 'Gateway acceptance follows invitation expiry');
      state.gateway.accepted = true;
      state.participants = { ...context.participants };
    } else if (body.type === 'gov.applied') {
      if (body.proposal_type === 'floor_change') context.floor = body.applied_floor!;
      if (body.proposal_type === 'rules_change') context.rules = body.applied_rules!;
      if (body.proposal_type === 'member_add') for (const member of body.applied_members!) {
        requireGateway(member.kid !== context.gateway.kid, 'Gateway cannot join signer roster');
        state.participants[member.kid] = member.public_key;
      }
      if (body.proposal_type === 'member_remove') for (const kid of body.removed_member_kids!) delete state.participants[kid];
      context.participants = { ...state.participants };
      validateGatewayContext(context);
    }
  } else if (groupTypes.has(bodyType)) {
    const authority = state.gateway?.accepted ? state.gateway.context.gateway : null;
    requireGateway(authority ? sender === authority.kid && pk === authority.publicKey : state.participants[sender] === pk,
      'Group control is not from the configured authority');
    let body: unknown;
    if (bodyType === 'group_genesis' || bodyType === 'group_add') {
      const members = bodyType === 'group_genesis'
        ? (body = parseGroupGenesisBody(bodyBytes), (body as ReturnType<typeof parseGroupGenesisBody>).founding_members)
        : (body = parseGroupAddBody(bodyBytes), (body as ReturnType<typeof parseGroupAddBody>).new_members);
      requireGateway(Array.isArray(members) && members.length > 0 && members.length <= 1000, 'Invalid group members');
      for (const member of members) {
        const memberKey = base64UrlEncode(new Uint8Array(member.public_key));
        const memberKid = base64UrlEncode(new Uint8Array(member.key_id));
        gatewayParticipants({ [memberKid]: memberKey });
        requireGateway(memberKid !== authority?.kid, 'Gateway cannot join signer roster');
        state.participants[memberKid] = memberKey;
      }
    } else if (bodyType === 'group_remove') {
      const removed = parseGroupRemoveBody(bodyBytes); body = removed;
      requireGateway(Array.isArray(removed.removed_members) && removed.removed_members.length <= 1000, 'Invalid removed members');
      for (const kid of removed.removed_members) {
        requireGateway(kid instanceof Uint8Array && kid.length === 16, 'Invalid removed member ID');
        delete state.participants[base64UrlEncode(kid)];
      }
    } else {
      const rekey = parseGroupRekeyBody(bodyBytes); body = rekey;
      requireGateway(Number.isSafeInteger(rekey.new_conv_epoch) && rekey.new_conv_epoch === next.currentEpoch + 1, 'Rekey must advance exactly one epoch');
      requireGateway(rekey.wrapped_keys && typeof rekey.wrapped_keys === 'object' && !Array.isArray(rekey.wrapped_keys), 'Invalid wrapped keys');
      const wrapped = rekey.wrapped_keys[base64UrlEncode(identity.keyID)];
      if (wrapped) {
        requireGateway(Object.hasOwn(state.participants, base64UrlEncode(identity.keyID)), 'Removed identity cannot accept a rekey');
        requireGateway(wrapped instanceof Uint8Array, 'Invalid wrapped key');
        const root = suite.unwrapKeyForRecipient(wrapped, identity.privateKey, identity.keyID, next.id);
        next.keys = { root, ...suite.deriveEpochKeys(root, next.id, rekey.new_conv_epoch) };
        next.currentEpoch = rekey.new_conv_epoch;
      } else state.removed = true;
    }
    text = JSON.stringify(body, (_key, value) => value instanceof Uint8Array ? base64UrlEncode(value) : value);
    if (state.gateway?.accepted) {
      state.gateway.context.participants = { ...state.participants };
      state.gateway.context.epoch = next.currentEpoch;
    }
    if (!Object.hasOwn(state.participants, base64UrlEncode(identity.keyID))) state.removed = true;
  } else if (!state.gateway?.accepted) {
    // Before gateway admission, ordinary authenticated chat discovers peers.
    state.participants[sender] = pk;
  }
  if (state.gateway?.accepted && !Object.hasOwn(state.participants, base64UrlEncode(identity.keyID))) state.removed = true;
  next.participants = state.gateway?.accepted || groupTypes.has(bodyType)
    ? Object.keys(state.participants).map(base64UrlDecode)
    : [...new Set([...next.participants.map(base64UrlEncode), ...Object.keys(state.participants)])].map(base64UrlDecode);
  if (gatewayEvent) state.events = [...state.events, gatewayEvent].slice(-4096);
  state.seen[id] = digest;
  if (Object.keys(state.seen).length > 8192) delete state.seen[Object.keys(state.seen)[0]];
  return { conversation: next, state, message, gatewayEvent, text, duplicate: false };
}
