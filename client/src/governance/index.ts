/**
 * Governance proposal system for promoted gateway conversations.
 *
 * Provides a governed way to change thresholds and policy after promotion,
 * without allowing direct gate.config or re-promotion.
 *
 * Proposal types:
 * - floor_change: adjust the conversation-wide minimum approval floor
 * - rules_change: update threshold rules for specific services/endpoints
 *
 * Flow: propose → approve/disapprove → applied (system event)
 */

import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical } from '../crypto/cbor.js';
import { keyIDFromPublicKey, base64UrlEncode } from '../identity/index.js';
import type { Identity, ThresholdRule } from '../types.js';

const suite = new QSP1Suite();

// Message type constants
export const GovMessagePropose = 'gov.propose' as const;
export const GovMessageApprove = 'gov.approve' as const;
export const GovMessageDisapprove = 'gov.disapprove' as const;
export const GovMessageApplied = 'gov.applied' as const;

// Signable types

export type GovProposalType = 'floor_change' | 'rules_change' | 'member_add' | 'member_remove';

export interface ProposedMember {
  kid: string;
  public_key: string;
}

export interface GovProposalSignable {
  conv_id: string;
  proposal_id: string;
  proposal_type: GovProposalType;
  proposed_floor: number | undefined;
  proposed_rules: ThresholdRule[] | undefined;
  proposed_members?: ProposedMember[];
  removed_member_kids?: string[];
  eligible_signer_kids: string[];
  required_approvals: number;
  expires_at_unix: number;
}

export interface GovApprovalSignable {
  conv_id: string;
  proposal_id: string;
  proposal_hash: Uint8Array;
}

// Proposal body (JSON message body sent in conversation)

export interface GovProposalBody {
  type: typeof GovMessagePropose;
  conv_id: string;
  proposal_id: string;
  proposal_type: GovProposalType;
  proposed_floor?: number;
  proposed_rules?: ThresholdRule[];
  proposed_members?: ProposedMember[];
  removed_member_kids?: string[];
  eligible_signer_kids: string[];
  required_approvals: number;
  expires_at: string;
  signer_kid: string;
  signature: string;
}

export interface GovApprovalBody {
  type: typeof GovMessageApprove;
  conv_id: string;
  proposal_id: string;
  signer_kid: string;
  signature: string;
}

export interface GovDisapprovalBody {
  type: typeof GovMessageDisapprove;
  conv_id: string;
  proposal_id: string;
  signer_kid: string;
}

export interface GovAppliedBody {
  type: typeof GovMessageApplied;
  proposal_id: string;
  proposal_type: 'floor_change' | 'rules_change';
  applied_floor?: number;
  applied_rules?: ThresholdRule[];
  applied_at: string;
}

// Signing functions

export function signProposal(
  privateKey: Uint8Array,
  signable: GovProposalSignable,
): Uint8Array {
  const data = marshalCanonical(signable);
  return suite.sign(privateKey, data);
}

export function verifyProposal(
  publicKey: Uint8Array,
  signable: GovProposalSignable,
  signature: Uint8Array,
): boolean {
  const data = marshalCanonical(signable);
  return suite.verify(publicKey, data, signature);
}

export function hashProposal(signable: GovProposalSignable): Uint8Array {
  const data = marshalCanonical(signable);
  return suite.hash(data);
}

export function signGovApproval(
  privateKey: Uint8Array,
  approval: GovApprovalSignable,
): Uint8Array {
  const data = marshalCanonical(approval);
  return suite.sign(privateKey, data);
}

export function verifyGovApproval(
  publicKey: Uint8Array,
  approval: GovApprovalSignable,
  signature: Uint8Array,
): boolean {
  const data = marshalCanonical(approval);
  return suite.verify(publicKey, data, signature);
}

// High-level helpers

export interface CreateProposalOptions {
  convId: string;
  proposalType: GovProposalType;
  proposedFloor?: number;
  proposedRules?: ThresholdRule[];
  proposedMembers?: Array<{ kid: string; publicKey: string }>;
  removedMemberKids?: string[];
  eligibleSignerKids: string[];
  requiredApprovals: number;
  expiresInSeconds: number;
}

/**
 * Create a signed governance proposal body ready to send as a conversation message.
 */
export function createProposalBody(
  identity: Identity,
  options: CreateProposalOptions,
): GovProposalBody {
  const proposalId = crypto.randomUUID();
  const expiresAtUnix = Math.floor(Date.now() / 1000) + options.expiresInSeconds;
  const expiresAt = new Date(expiresAtUnix * 1000).toISOString();
  const kidB64 = base64UrlEncode(keyIDFromPublicKey(identity.publicKey));

  const proposedMembers = options.proposedMembers?.map(m => ({ kid: m.kid, public_key: m.publicKey }));

  const signable: GovProposalSignable = {
    conv_id: options.convId,
    proposal_id: proposalId,
    proposal_type: options.proposalType,
    proposed_floor: options.proposedFloor,
    proposed_rules: options.proposedRules,
    proposed_members: proposedMembers,
    removed_member_kids: options.removedMemberKids,
    eligible_signer_kids: options.eligibleSignerKids,
    required_approvals: options.requiredApprovals,
    expires_at_unix: expiresAtUnix,
  };

  const sig = signProposal(identity.privateKey, signable);

  return {
    type: GovMessagePropose,
    conv_id: options.convId,
    proposal_id: proposalId,
    proposal_type: options.proposalType,
    proposed_floor: options.proposedFloor,
    proposed_rules: options.proposedRules,
    proposed_members: proposedMembers,
    removed_member_kids: options.removedMemberKids,
    eligible_signer_kids: options.eligibleSignerKids,
    required_approvals: options.requiredApprovals,
    expires_at: expiresAt,
    signer_kid: kidB64,
    signature: base64UrlEncode(sig),
  };
}
