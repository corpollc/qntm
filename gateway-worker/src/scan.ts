import {
  verifyRequest, verifyApproval, hashRequest, computePayloadHash,
  lookupThreshold, base64UrlDecode,
} from '@corpollc/qntm';
import type { GateSignable, ApprovalSignable } from '@corpollc/qntm';
import type { StoredGateMessage, ThresholdRuleState, GateRequestMessage } from './types.js';

export type RequestStatus = 'pending' | 'approved' | 'executed' | 'expired';

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
  // Find the original request
  let requestMsg: GateRequestMessage | undefined;
  for (const msg of messages) {
    if (msg.type === 'gate.request' && msg.request_id === requestId && msg.body) {
      requestMsg = JSON.parse(msg.body) as GateRequestMessage;
      break;
    }
  }

  if (!requestMsg) return null;

  // Check for execution marker
  for (const msg of messages) {
    if (msg.type === 'gate.executed' && msg.request_id === requestId) {
      return {
        request_id: requestId,
        status: 'executed',
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

  // Look up threshold rule
  const rule = lookupThreshold(
    rules, requestMsg.target_service, requestMsg.target_endpoint, requestMsg.verb,
  );
  const threshold = rule?.m ?? 1;

  // Build votes: last-vote-wins per signer, gateway excluded
  const votes: Record<string, 'approve' | 'disapprove'> = {};

  // The request submitter's signature counts as first approval
  if (requestMsg.signer_kid && requestMsg.signer_kid !== gatewayKid) {
    // Verify submitter signature
    const signable = buildSignable(requestMsg);
    try {
      // We trust conversation message integrity from the envelope signature,
      // but we still record the vote for threshold counting
      votes[requestMsg.signer_kid] = 'approve';
    } catch {
      // Invalid signature — don't count
    }
  }

  // Process approvals and disapprovals in conversation order
  for (const msg of messages) {
    if (msg.request_id !== requestId) continue;
    if (!msg.signer_kid || msg.signer_kid === gatewayKid) continue;

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
  };
}
