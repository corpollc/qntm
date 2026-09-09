import { base64UrlEncode, base64UrlDecode, keyIDFromPublicKey } from '../identity/index.js';
import { sealSecret } from '../crypto/naclbox.js';
import { createProposalBody, hashProposal, signGovApproval, verifyProposal } from '../governance/index.js';
import type { GovProposalSignable, CreateProposalOptions } from '../governance/index.js';
import type { Identity, GateSignable } from '../types.js';
import { computePayloadHash, hashRequest, lookupThreshold, signApproval, signRequest, verifyRequest } from './index.js';
import {
  gatewayInteger, gatewayTime, parseGatewayBody, requireGateway, validateGatewayContext,
} from './workflow-parse.js';
import type {
  GatewayContext, GateRequestBody, GateApprovalBody, GateDisapprovalBody, GateSecretBody,
  GatewayProposalBody, GatewayProposalApprovalBody, GatewayProposalDisapprovalBody,
} from './workflow-types.js';

export function gateRequestSignable(body: GateRequestBody): GateSignable {
  return {
    ...(body.gateway_kid ? { gateway_kid: body.gateway_kid } : {}),
    conv_id: body.conv_id, request_id: body.request_id, verb: body.verb,
    target_endpoint: body.target_endpoint, target_service: body.target_service, target_url: body.target_url,
    expires_at_unix: Math.floor(gatewayTime(body.expires_at) / 1000),
    payload_hash: computePayloadHash(body.payload ?? null),
    eligible_signer_kids: body.eligible_signer_kids, required_approvals: body.required_approvals,
  };
}
/** Preserve absent versus null fields: both occur in existing clients' signatures. */
export function gatewayProposalSignable(body: GatewayProposalBody): GovProposalSignable {
  return {
    ...(body.gateway_kid ? { gateway_kid: body.gateway_kid } : {}),
    conv_id: body.conv_id, proposal_id: body.proposal_id, proposal_type: body.proposal_type,
    proposed_floor: body.proposed_floor, proposed_rules: body.proposed_rules,
    proposed_members: body.proposed_members, removed_member_kids: body.removed_member_kids,
    eligible_signer_kids: body.eligible_signer_kids, required_approvals: body.required_approvals,
    expires_at_unix: Math.floor(gatewayTime(body.expires_at) / 1000),
  } as GovProposalSignable;
}
export function gatewaySigner(identity: Identity, context: GatewayContext): string {
  validateGatewayContext(context);
  const kid = base64UrlEncode(keyIDFromPublicKey(identity.publicKey));
  requireGateway(context.participants[kid] === base64UrlEncode(identity.publicKey), 'Signer is not a current participant');
  return kid;
}
export function assertGatewayBinding(body: { conv_id: string; gateway_kid?: string }, context: GatewayContext): void {
  requireGateway(body.conv_id === context.conversationId, 'Conversation ID mismatch');
  requireGateway(body.gateway_kid === context.gateway.kid || (!body.gateway_kid && context.allowLegacyUnbound), 'Gateway ID mismatch');
}
export function assertGatewayRoster(roster: string[], context: GatewayContext): void {
  const current = Object.keys(context.participants);
  requireGateway(roster.length === current.length && new Set(roster).size === current.length && current.every(kid => roster.includes(kid)), 'Signer roster differs from current participants');
}
export function gatewayRequestThreshold(context: GatewayContext, request: Pick<GateRequestBody, 'target_service' | 'target_endpoint' | 'verb'>): number {
  return Math.max(context.floor, lookupThreshold(context.rules, request.target_service, request.target_endpoint, request.verb)?.m ?? 1);
}
export function gatewayGovernanceQuorum(context: GatewayContext): number {
  validateGatewayContext(context);
  return Math.floor(Object.keys(context.participants).length / 2) + 1;
}
function validated<T extends GateRequestBody | GatewayProposalBody | GateApprovalBody | GateDisapprovalBody | GateSecretBody | GatewayProposalApprovalBody | GatewayProposalDisapprovalBody>(body: T): T {
  // JSON roundtrip freezes the exact payload that is signed and later sent.
  return parseGatewayBody(body.type, JSON.stringify(body)) as T;
}
export function assertGateRequest(body: GateRequestBody, context: GatewayContext): void {
  validateGatewayContext(context);
  parseGatewayBody(body.type, JSON.stringify(body));
  assertGatewayBinding(body, context);
  assertGatewayRoster(body.eligible_signer_kids, context);
  requireGateway(body.required_approvals >= gatewayRequestThreshold(context, body), 'Request threshold below current policy');
  const pk = context.participants[body.signer_kid];
  requireGateway(pk && verifyRequest(base64UrlDecode(pk), gateRequestSignable(body), base64UrlDecode(body.signature)), 'Invalid request signature or author');
}
export function assertGatewayProposal(body: GatewayProposalBody, context: GatewayContext): void {
  validateGatewayContext(context);
  parseGatewayBody(body.type, JSON.stringify(body));
  assertGatewayBinding(body, context);
  assertGatewayRoster(body.eligible_signer_kids, context);
  requireGateway(body.required_approvals >= gatewayGovernanceQuorum(context), 'Proposal threshold below current majority');
  const pk = context.participants[body.signer_kid];
  requireGateway(pk && verifyProposal(base64UrlDecode(pk), gatewayProposalSignable(body), base64UrlDecode(body.signature)), 'Invalid proposal signature or author');
}
export interface CreateGateRequestOptions {
  service: string;
  endpoint: string;
  verb: string;
  targetUrl: string;
  payload?: unknown;
  recipeName?: string;
  arguments?: Record<string, string>;
  /** May raise, never lower, the threshold derived from current policy. */
  requiredApprovals?: number;
  expiresInSeconds?: number;
  requestId?: string;
  now?: number;
}
export function createGateRequestBody(identity: Identity, context: GatewayContext, options: CreateGateRequestOptions): GateRequestBody {
  const signer = gatewaySigner(identity, context);
  const lifetime = gatewayInteger(options.expiresInSeconds ?? 3600, 'request lifetime', 1);
  const now = gatewayInteger(options.now ?? Date.now(), 'current time');
  let body: GateRequestBody = {
    type: 'gate.request', gateway_kid: context.gateway.kid, conv_id: context.conversationId,
    request_id: options.requestId ?? crypto.randomUUID(), verb: options.verb,
    target_endpoint: options.endpoint, target_service: options.service, target_url: options.targetUrl,
    expires_at: new Date((Math.floor(now / 1000) + lifetime) * 1000).toISOString(),
    signer_kid: signer, signature: base64UrlEncode(new Uint8Array(64)),
    eligible_signer_kids: Object.keys(context.participants).sort(), required_approvals: 1,
    payload: options.payload, recipe_name: options.recipeName, arguments: options.arguments,
  };
  body.required_approvals = Math.max(gatewayRequestThreshold(context, body), gatewayInteger(options.requiredApprovals ?? 1, 'required approvals', 1));
  body = validated(body);
  body.signature = base64UrlEncode(signRequest(identity.privateKey, gateRequestSignable(body)));
  assertGateRequest(body, context);
  return body;
}
export function createGateApprovalBody(identity: Identity, context: GatewayContext, request: GateRequestBody, now = Date.now()): GateApprovalBody {
  const kid = gatewaySigner(identity, context);
  assertGateRequest(request, context);
  requireGateway(now < gatewayTime(request.expires_at), 'Request expired');
  return validated({ type: 'gate.approval', gateway_kid: context.gateway.kid,
    conv_id: context.conversationId, request_id: request.request_id, signer_kid: kid,
    signature: base64UrlEncode(signApproval(identity.privateKey, {
      conv_id: context.conversationId, request_id: request.request_id, request_hash: hashRequest(gateRequestSignable(request)),
    })),
  });
}
/** Disapproval is authenticated by the enclosing signed qntm message. */
export function createGateDisapprovalBody(identity: Identity, context: GatewayContext, request: GateRequestBody): GateDisapprovalBody {
  const kid = gatewaySigner(identity, context);
  assertGateRequest(request, context);
  return { type: 'gate.disapproval', gateway_kid: context.gateway.kid,
    conv_id: context.conversationId, request_id: request.request_id, signer_kid: kid };
}
export interface CreateGateSecretOptions {
  service: string;
  value: string | Uint8Array;
  headerName?: string;
  headerTemplate?: string;
  secretId?: string;
  ttl?: number;
}
export function createGateSecretBody(identity: Identity, context: GatewayContext, options: CreateGateSecretOptions): GateSecretBody {
  const kid = gatewaySigner(identity, context);
  const plaintext = typeof options.value === 'string' ? new TextEncoder().encode(options.value) : new Uint8Array(options.value);
  try {
    const sealed = sealSecret(identity.privateKey, base64UrlDecode(context.gateway.publicKey), plaintext);
    return validated({ type: 'gate.secret', gateway_kid: context.gateway.kid,
      secret_id: options.secretId ?? crypto.randomUUID(), service: options.service,
      header_name: options.headerName ?? 'Authorization', header_template: options.headerTemplate ?? 'Bearer {value}',
      encrypted_blob: base64UrlEncode(sealed), sender_kid: kid, ttl: options.ttl });
  } finally { plaintext.fill(0); }
}
export type CreateGatewayProposalOptions = Omit<CreateProposalOptions, 'gatewayKid' | 'convId' | 'eligibleSignerKids' | 'requiredApprovals' | 'expiresInSeconds'> & {
  requiredApprovals?: number;
  expiresInSeconds?: number;
};
export function createGatewayProposalBody(identity: Identity, context: GatewayContext, options: CreateGatewayProposalOptions): GatewayProposalBody {
  gatewaySigner(identity, context);
  const proposal = validated(createProposalBody(identity, {
    ...options, gatewayKid: context.gateway.kid, convId: context.conversationId,
    eligibleSignerKids: Object.keys(context.participants).sort(),
    requiredApprovals: Math.max(gatewayGovernanceQuorum(context), gatewayInteger(options.requiredApprovals ?? 1, 'required approvals', 1)),
    expiresInSeconds: gatewayInteger(options.expiresInSeconds ?? 3600, 'proposal lifetime', 1),
  }));
  if (proposal.proposed_members) for (const member of proposal.proposed_members) {
    requireGateway(!Object.hasOwn(context.participants, member.kid) && member.kid !== context.gateway.kid, 'Proposed member already exists or is gateway');
  }
  if (proposal.removed_member_kids) {
    requireGateway(proposal.removed_member_kids.every(kid => Object.hasOwn(context.participants, kid)), 'Removed member is not a current participant');
    requireGateway(proposal.removed_member_kids.length < Object.keys(context.participants).length, 'Cannot remove every participant');
  }
  assertGatewayProposal(proposal, context);
  return proposal;
}
export function createGatewayProposalApprovalBody(identity: Identity, context: GatewayContext, proposal: GatewayProposalBody, now = Date.now()): GatewayProposalApprovalBody {
  const kid = gatewaySigner(identity, context);
  assertGatewayProposal(proposal, context);
  requireGateway(now < gatewayTime(proposal.expires_at), 'Proposal expired');
  return validated({ type: 'gov.approve', gateway_kid: context.gateway.kid,
    conv_id: context.conversationId, proposal_id: proposal.proposal_id, signer_kid: kid,
    signature: base64UrlEncode(signGovApproval(identity.privateKey, {
      conv_id: context.conversationId, proposal_id: proposal.proposal_id, proposal_hash: hashProposal(gatewayProposalSignable(proposal)),
    })),
  });
}
export function createGatewayProposalDisapprovalBody(identity: Identity, context: GatewayContext, proposal: GatewayProposalBody): GatewayProposalDisapprovalBody {
  const kid = gatewaySigner(identity, context);
  assertGatewayProposal(proposal, context);
  return { type: 'gov.disapprove', gateway_kid: context.gateway.kid,
    conv_id: context.conversationId, proposal_id: proposal.proposal_id, signer_kid: kid };
}
