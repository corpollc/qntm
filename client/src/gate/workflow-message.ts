import { base64UrlEncode, base64UrlDecode, keyIDFromPublicKey } from '../identity/index.js';
import { createMessage, decryptMessage, defaultTTL, verifyMessageSignature } from '../message/index.js';
import type { Conversation, Identity, Message, OuterEnvelope } from '../types.js';
import { hashRequest, verifyApproval } from './index.js';
import { hashProposal, verifyGovApproval } from '../governance/index.js';
import { matchesGatewayAcceptance } from './handshake.js';
import { assertGateRequest, assertGatewayBinding, assertGatewayProposal, assertGatewayRoster,
  gateRequestSignable, gatewayProposalSignable } from './workflow-build.js';
import { parseGatewayBody, requireGateway, validateGatewayContext } from './workflow-parse.js';
import type { GatewayBody, GatewayContext, GateRequestBody, GatewayProposalBody } from './workflow-types.js';

const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const gatewayEvents = new Set(['gate.accept', 'gate.executed', 'gate.result', 'gate.expired', 'gate.invalidated', 'gov.applied', 'gov.invalidated']);
export interface GatewayReferences {
  request?: GateRequestBody;
  proposal?: GatewayProposalBody;
  invitation?: { messageId: string; text: string };
}
/** Produced from an authenticated qntm Message, in the context current at receipt.
 * Store the original envelope if verification after reload is required. */
export interface VerifiedGatewayEvent {
  body: GatewayBody;
  senderKid: string;
  conversationId: string;
  epoch: number;
  messageId: string;
  createdAt: number;
}

/** Takes an unmodified result of decryptMessage; validates envelope identity,
 * context and nested request/vote signatures. For untrusted ciphertext use
 * decryptGatewayMessage, which authenticates the AEAD envelope itself.
 * This does not grant permission to execute a request or install a policy. */
export function verifyGatewayMessage(message: Message, context: GatewayContext, references: GatewayReferences = {}): VerifiedGatewayEvent {
  validateGatewayContext(context);
  requireGateway(message.verified && verifyMessageSignature(message.envelope, message.inner), 'Unauthenticated gateway message');
  requireGateway(hex(message.envelope.conv_id) === context.conversationId, 'Envelope conversation mismatch');
  requireGateway(message.envelope.conv_epoch === context.epoch, 'Envelope epoch mismatch');
  const senderKid = base64UrlEncode(keyIDFromPublicKey(message.inner.sender_ik_pk));
  requireGateway(base64UrlEncode(message.inner.sender_kid) === senderKid, 'Envelope sender key ID mismatch');
  const body = parseGatewayBody(message.inner.body_type, message.inner.body);
  const senderKey = base64UrlEncode(message.inner.sender_ik_pk);
  if (gatewayEvents.has(body.type)) {
    requireGateway(senderKid === context.gateway.kid && senderKey === context.gateway.publicKey, 'Event is not from the configured gateway');
  } else {
    requireGateway(context.participants[senderKid] === senderKey, 'Sender is not a current participant');
  }
  if ('conv_id' in body) assertGatewayBinding(body, context);
  if ('gateway_kid' in body && body.gateway_kid !== undefined) requireGateway(body.gateway_kid === context.gateway.kid, 'Gateway ID mismatch');
  if ('signer_kid' in body) requireGateway(body.signer_kid === senderKid, 'Body signer differs from envelope sender');
  if ('sender_kid' in body) requireGateway(body.sender_kid === senderKid, 'Body sender differs from envelope sender');
  switch (body.type) {
    case 'gate.request': assertGateRequest(body, context); break;
    case 'gov.propose': assertGatewayProposal(body, context); break;
    case 'gate.approval': case 'gate.disapproval': {
      const request = references.request;
      requireGateway(request && request.request_id === body.request_id, 'Matching request required');
      assertGateRequest(request, context);
      requireGateway(request.eligible_signer_kids.includes(senderKid), 'Ineligible request voter');
      if (body.type === 'gate.approval') requireGateway(verifyApproval(message.inner.sender_ik_pk, {
        conv_id: body.conv_id, request_id: body.request_id, request_hash: hashRequest(gateRequestSignable(request)),
      }, base64UrlDecode(body.signature)), 'Invalid approval signature');
      break;
    }
    case 'gov.approve': case 'gov.disapprove': {
      const proposal = references.proposal;
      requireGateway(proposal && proposal.proposal_id === body.proposal_id, 'Matching proposal required');
      assertGatewayProposal(proposal, context);
      requireGateway(proposal.eligible_signer_kids.includes(senderKid), 'Ineligible proposal voter');
      if (body.type === 'gov.approve') requireGateway(verifyGovApproval(message.inner.sender_ik_pk, {
        conv_id: body.conv_id, proposal_id: body.proposal_id, proposal_hash: hashProposal(gatewayProposalSignable(proposal)),
      }, base64UrlDecode(body.signature)), 'Invalid governance approval signature');
      break;
    }
    case 'gate.promote':
      requireGateway(body.conv_epoch === context.epoch, 'Invitation epoch mismatch');
      assertGatewayRoster(Object.keys(body.participants), context);
      requireGateway(Object.entries(body.participants).every(([kid, key]) => context.participants[kid] === key), 'Invitation participant key mismatch');
      break;
    case 'gate.accept': {
      const invitation = references.invitation;
      requireGateway(invitation && matchesGatewayAcceptance(body, senderKid, invitation.messageId, invitation.text), 'Acceptance does not match the verified invitation');
      break;
    }
  }
  return { body, senderKid, conversationId: context.conversationId, epoch: context.epoch,
    messageId: hex(message.envelope.msg_id), createdAt: message.envelope.created_ts * 1000 };
}

/** Preferred entry point for received wire envelopes. Authenticates ciphertext
 * and its AAD (including epoch) before applying gateway-specific verification. */
export function decryptGatewayMessage(envelope: OuterEnvelope, conversation: Conversation,
  context: GatewayContext, references: GatewayReferences = {}): VerifiedGatewayEvent {
  requireGateway(hex(conversation.id) === context.conversationId && conversation.currentEpoch === context.epoch, 'Conversation state differs from gateway context');
  return verifyGatewayMessage(decryptMessage(envelope, conversation), context, references);
}

/** Encrypt a validated body using its own body_type. Queue/persist the exact
 * returned envelope before sending if the host needs safe delivery retries. */
export function createGatewayMessage(identity: Identity, conversation: Conversation, body: GatewayBody,
  context: GatewayContext, references: GatewayReferences = {}, ttl = defaultTTL()): OuterEnvelope {
  requireGateway(hex(conversation.id) === context.conversationId && conversation.currentEpoch === context.epoch, 'Conversation state differs from gateway context');
  const envelope = createMessage(identity, conversation, body.type, new TextEncoder().encode(JSON.stringify(body)), undefined, ttl);
  verifyGatewayMessage(decryptMessage(envelope, conversation), context, references);
  return envelope;
}
