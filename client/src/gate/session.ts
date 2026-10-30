/** Authenticated conversation state shared by local hosts. No I/O or permissions. */
import { applyAuthenticatedGroupControl, type GroupControlState } from '../group/control.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlDecode, base64UrlEncode, keyIDFromPublicKey } from '../identity/index.js';
import { decryptMessage, serializeEnvelope } from '../message/index.js';
import { parseGroupGenesisBody, parseGroupAddBody, parseGroupRemoveBody, parseGroupRekeyBody } from '../group/index.js';
import type { Conversation, Identity, Message, OuterEnvelope } from '../types.js';
import { gatewayAccess, gatewayAccessHash } from './handshake.js';
import type { GatewayInviteBody } from './handshake.js';
import { parseGatewayBody, requireGateway, validateGatewayContext } from './workflow-parse.js';
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
    membershipAuthority?: boolean;
    context: GatewayContext;
    invitation: { messageId: string; text: string; body: GatewayInviteBody };
  };
  removed: boolean;
  needsRekey?: boolean;
  groupControl?: GroupControlState;
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
  return { version: 1, participants, removed: false, events: [], seen: {},
    ...(conversation.type === 'group' && conversation.participants[0] ? { groupControl: { creator: base64UrlEncode(conversation.participants[0]), needsRekey: false, removed: false } } : {}) };
}

export function sessionGatewayContext(state: GatewaySessionState): GatewayContext {
  requireGateway(!state.removed, 'You have been removed from this conversation');
  requireGateway(!state.needsRekey, 'Complete the pending group rekey before sending');
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
    const creator = state.groupControl?.creator;
    requireGateway(body.conversation_type === undefined || body.conversation_type === next.type, 'Invitation changes conversation type');
    requireGateway(body.group_creator_kid === undefined || body.group_creator_kid === creator, 'Invitation changes group creator');
    state.gateway = { accepted: false, membershipAuthority: next.type === 'direct' || sender === creator, context, invitation: { messageId: id, text, body } };
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
      requireGateway(!state.needsRekey && !state.removed && state.gateway.invitation.body.keys_hash === gatewayAccessHash(gatewayAccess(next)), 'Gateway invitation is stale');
      for (const [kid, key] of Object.entries(state.participants)) requireGateway(context.participants[kid] === key, 'Gateway invitation changes current membership');
      if (state.groupControl?.roster && next.currentEpoch > 0) requireGateway(Object.keys(context.participants).length === Object.keys(state.participants).length, 'Gateway invitation changes current membership');
      state.gateway.accepted = true;
      if (state.groupControl) delete state.groupControl.roster;
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
    const authority = state.gateway?.accepted ? state.gateway.context.gateway : undefined;
    if (authority) {
      requireGateway(state.gateway?.membershipAuthority && sender === authority.kid && pk === authority.publicKey, 'Group control is not from the configured authority');
    } else requireGateway(next.type === 'group', 'Group control requires a group conversation');
    const control = state.groupControl ?? { creator: base64UrlEncode(conversation.participants[0]), needsRekey: false, removed: false };
    const applied = applyAuthenticatedGroupControl(envelope, message, next, identity, control, state.participants,
      authority ? base64UrlDecode(authority.publicKey) : undefined);
    Object.assign(next, applied.conversation);
    state.groupControl = applied.state;
    state.participants = applied.participants;
    state.removed = applied.state.removed;
    state.needsRekey = applied.state.needsRekey;
    const parsed = bodyType === 'group_genesis' ? parseGroupGenesisBody(bodyBytes) : bodyType === 'group_add' ? parseGroupAddBody(bodyBytes)
      : bodyType === 'group_remove' ? parseGroupRemoveBody(bodyBytes) : parseGroupRekeyBody(bodyBytes);
    text = JSON.stringify(parsed, (_key, value) => value instanceof Uint8Array ? base64UrlEncode(value) : value);
    if (state.gateway?.accepted) {
      state.gateway.context.participants = { ...state.participants };
      state.gateway.context.epoch = next.currentEpoch;
    }
  } else if (!state.gateway?.accepted && !(next.type === 'group' && state.groupControl?.roster)) {
    // Bearer chat can discover peers only before an authenticated group roster.
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
