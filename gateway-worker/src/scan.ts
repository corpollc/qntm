import {
  verifyRequest, verifyApproval, hashRequest, computePayloadHash,
  lookupThreshold, base64UrlDecode,
} from '@corpollc/qntm';
import type { GateSignable, ApprovalSignable } from '@corpollc/qntm';
import type { StoredGateMessage, ThresholdRuleState, GateRequestMessage } from './types.js';

export type RequestStatus = 'pending' | 'approved' | 'executed' | 'expired' | 'invalidated';

export interface ScanResult {
  request_id: string;
  status: RequestStatus;
  threshold: number;
  approvals: number;
  /** signer_kid → 'approve' | 'disapprove' (last vote wins) */
  votes: Record<string, 'approve' | 'disapprove'>;
  request?: GateRequestMessage;
}

/**
 * Derive approval state for a request by scanning conversation history.
 *
 * Rules:
 * - One effective vote per signer per request (last-vote-wins in conversation order)
 * - Gateway participant (gatewayKid) is excluded from threshold counts
 * - gate.executed markers are canonical: once executed, no further counting
 * - Expired requests are marked as such
 *
 * This is a pure function over the message history — no mutable state.
 */
export function scanRequestApprovals(
  messages: StoredGateMessage[],
  requestId: string,
  gatewayKid: string,
  rules: ThresholdRuleState[],
  now: number = Date.now(),
): ScanResult | null {
  // Find the original request (stored message + parsed body)
  let requestMsg: GateRequestMessage | undefined;
  let storedReq: StoredGateMessage | undefined;
  for (const msg of messages) {
    if (msg.type === 'gate.request' && msg.request_id === requestId && msg.body) {
      storedReq = msg;
      requestMsg = JSON.parse(msg.body) as GateRequestMessage;
      break;
    }
  }

  if (!requestMsg) return null;

  // Check for terminal state markers (executed / invalidated)
  for (const msg of messages) {
    if (msg.request_id !== requestId) continue;
    if (msg.type === 'gate.executed') {
      return {
        request_id: requestId,
        status: 'executed',
        threshold: 0,
        approvals: 0,
        votes: {},
        request: requestMsg,
      };
    }
    if (msg.type === 'gate.invalidated') {
      return {
        request_id: requestId,
        status: 'invalidated',
        threshold: 0,
        approvals: 0,
        votes: {},
        request: requestMsg,
      };
    }
  }

  // Check expiry
  const expiresAtMs = new Date(requestMsg.expires_at).getTime();
  if (now > expiresAtMs) {
    return {
      request_id: requestId,
      status: 'expired',
      threshold: 0,
      approvals: 0,
      votes: {},
      request: requestMsg,
    };
  }

  // Determine threshold: prefer frozen required_approvals, fall back to rules
  const threshold = requestMsg.required_approvals ?? (
    lookupThreshold(rules, requestMsg.target_service, requestMsg.target_endpoint, requestMsg.verb)?.m ?? 1
  );

  // Determine eligible signers roster (null = legacy mode, accept any non-gateway signer)
  const hasRoster = Array.isArray(requestMsg.eligible_signer_kids) && requestMsg.eligible_signer_kids.length > 0;
  const eligibleSigners = hasRoster ? new Set(requestMsg.eligible_signer_kids) : null;

  // Build votes: last-vote-wins per signer, gateway excluded
  const votes: Record<string, 'approve' | 'disapprove'> = {};

  // The request submitter's authenticated signature counts as first approval.
  // Use the stored message's signer_kid (envelope-authenticated), not the JSON body field.
  const submitterKid = storedReq?.signer_kid;
  if (submitterKid && submitterKid !== gatewayKid && (eligibleSigners === null || eligibleSigners.has(submitterKid))) {
    votes[submitterKid] = 'approve';
  }

  // Process approvals and disapprovals in conversation order
  for (const msg of messages) {
    if (msg.request_id !== requestId) continue;
    if (!msg.signer_kid || msg.signer_kid === gatewayKid) continue;
    // Skip signers not in the eligible roster (when roster is present)
    if (eligibleSigners !== null && !eligibleSigners.has(msg.signer_kid)) continue;

    if (msg.type === 'gate.approval') {
      votes[msg.signer_kid] = 'approve';
    } else if (msg.type === 'gate.disapproval') {
      votes[msg.signer_kid] = 'disapprove';
    }
  }

  // Count net approvals
  const approvals = Object.values(votes).filter(v => v === 'approve').length;

  return {
    request_id: requestId,
    status: approvals >= threshold ? 'approved' : 'pending',
    threshold,
    approvals,
    votes,
    request: requestMsg,
  };
}

/**
 * Scan all pending requests and return those that have met their threshold.
 */
export function findExecutableRequests(
  messages: StoredGateMessage[],
  gatewayKid: string,
  rules: ThresholdRuleState[],
): ScanResult[] {
  // Collect unique request IDs
  const requestIds = new Set<string>();
  for (const msg of messages) {
    if (msg.type === 'gate.request' && msg.request_id) {
      requestIds.add(msg.request_id);
    }
  }

  const results: ScanResult[] = [];
  for (const reqId of requestIds) {
    const scan = scanRequestApprovals(messages, reqId, gatewayKid, rules);
    if (scan && scan.status === 'approved') {
      results.push(scan);
    }
  }
  return results;
}

function buildSignable(req: GateRequestMessage): GateSignable {
  const payloadHash = computePayloadHash(req.payload ?? null);
  return {
    conv_id: req.conv_id,
    request_id: req.request_id,
    verb: req.verb,
    target_endpoint: req.target_endpoint,
    target_service: req.target_service,
    target_url: req.target_url,
    expires_at_unix: Math.floor(new Date(req.expires_at).getTime() / 1000),
    payload_hash: payloadHash,
    eligible_signer_kids: req.eligible_signer_kids,
    required_approvals: req.required_approvals,
  };
}
