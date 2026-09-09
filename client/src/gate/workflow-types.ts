import type { ThresholdRule } from '../types.js';
import type { GovProposalType, ProposedMember } from '../governance/index.js';
import type { GatewayAcceptance, GatewayInviteBody } from './handshake.js';

/** Caller-owned, verified current state. Gateway identity must come from accepted
 * admission or an explicitly trusted legacy configuration, never from a request. */
export interface GatewayContext {
  conversationId: string;
  epoch: number;
  gateway: { kid: string; publicKey: string };
  participants: Record<string, string>;
  floor: number;
  rules: ThresholdRule[];
  /** Explicit compatibility with conversations created before signed admission.
   * New builders always bind the configured gateway. */
  allowLegacyUnbound?: boolean;
}

export interface GateRequestBody {
  type: 'gate.request';
  gateway_kid?: string;
  conv_id: string;
  request_id: string;
  verb: string;
  target_endpoint: string;
  target_service: string;
  target_url: string;
  expires_at: string;
  signer_kid: string;
  signature: string;
  eligible_signer_kids: string[];
  required_approvals: number;
  payload?: unknown;
  recipe_name?: string;
  arguments?: Record<string, string> | null;
}

export interface GateApprovalBody {
  type: 'gate.approval';
  gateway_kid?: string;
  conv_id: string;
  request_id: string;
  signer_kid: string;
  signature: string;
}
export interface GateDisapprovalBody extends Omit<GateApprovalBody, 'type' | 'signature'> {
  type: 'gate.disapproval';
}
/** JSON wire representation; encrypted_blob is base64url, not Uint8Array. */
export interface GateSecretBody {
  type: 'gate.secret';
  gateway_kid?: string;
  secret_id: string;
  service: string;
  header_name: string;
  header_template: string;
  encrypted_blob: string;
  sender_kid: string;
  ttl?: number;
}
export interface GateExecutedBody {
  type: 'gate.executed';
  request_id: string;
  executed_at: string;
  execution_status_code: number;
}
export interface GateResultBody {
  type: 'gate.result';
  request_id: string;
  status_code: number;
  content_type?: string;
  body?: string;
}
export interface GateExpiredBody {
  type: 'gate.expired';
  secret_id: string;
  service: string;
  expired_at: string;
  message: string;
}
export interface GateInvalidatedBody {
  type: 'gate.invalidated';
  request_id: string;
  invalidated_at: string;
  message: string;
}
export interface GatewayProposalInvalidatedBody {
  type: 'gov.invalidated';
  proposal_id: string;
  invalidated_at: string;
  message: string;
}

/** Python includes null for unused branches; retain these values when hashing. */
export interface GatewayProposalBody {
  type: 'gov.propose';
  gateway_kid?: string;
  conv_id: string;
  proposal_id: string;
  proposal_type: GovProposalType;
  proposed_floor?: number | null;
  proposed_rules?: ThresholdRule[] | null;
  proposed_members?: ProposedMember[] | null;
  removed_member_kids?: string[] | null;
  eligible_signer_kids: string[];
  required_approvals: number;
  expires_at: string;
  signer_kid: string;
  signature: string;
}
export interface GatewayProposalApprovalBody {
  type: 'gov.approve';
  gateway_kid?: string;
  conv_id: string;
  proposal_id: string;
  signer_kid: string;
  signature: string;
}
export interface GatewayProposalDisapprovalBody extends Omit<GatewayProposalApprovalBody, 'type' | 'signature'> {
  type: 'gov.disapprove';
}
export interface GatewayAppliedBody {
  type: 'gov.applied';
  proposal_id: string;
  proposal_type: GovProposalType;
  applied_at: string;
  applied_floor?: number | null;
  applied_rules?: ThresholdRule[] | null;
  applied_members?: ProposedMember[] | null;
  removed_member_kids?: string[] | null;
}
export type GatewayBody = GateRequestBody | GateApprovalBody | GateDisapprovalBody
  | GateSecretBody | GateExecutedBody | GateResultBody | GateExpiredBody | GateInvalidatedBody
  | GatewayProposalBody | GatewayProposalApprovalBody | GatewayProposalDisapprovalBody
  | GatewayAppliedBody | GatewayProposalInvalidatedBody | GatewayInviteBody | GatewayAcceptance;
export type GatewayBodyType = GatewayBody['type'];
