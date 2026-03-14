import { describe, it, expect } from 'vitest';
import { scanRequestApprovals, findExecutableRequests } from './scan.js';
import type { StoredGateMessage, ThresholdRuleState } from './types.js';

const gatewayKid = 'gateway-kid-abc';
const signerA = 'signer-a-kid';
const signerB = 'signer-b-kid';
const signerC = 'signer-c-kid';

function makeRequest(overrides: Partial<{
  request_id: string;
  signer_kid: string;
  eligible_signer_kids: string[];
  required_approvals: number;
  expires_at: string;
}>): StoredGateMessage {
  const reqId = overrides.request_id ?? 'req-1';
  const body = JSON.stringify({
    type: 'gate.request',
    conv_id: 'conv-1',
    request_id: reqId,
    verb: 'GET',
    target_endpoint: '/api/test',
    target_service: 'test-svc',
    target_url: 'https://api.example.com/test',
    expires_at: overrides.expires_at ?? '2099-01-01T00:00:00Z',
    signer_kid: overrides.signer_kid ?? signerA,
    signature: 'sig-placeholder',
    eligible_signer_kids: overrides.eligible_signer_kids ?? [signerA, signerB],
    required_approvals: overrides.required_approvals ?? 2,
  });
  return {
    seq: 1,
    type: 'gate.request',
    request_id: reqId,
    signer_kid: overrides.signer_kid ?? signerA,
    signature: 'sig-placeholder',
    body,
  };
}

function makeApproval(requestId: string, signerKid: string, seq: number): StoredGateMessage {
  return { seq, type: 'gate.approval', request_id: requestId, signer_kid: signerKid, signature: 'sig-placeholder' };
}

function makeDisapproval(requestId: string, signerKid: string, seq: number): StoredGateMessage {
  return { seq, type: 'gate.disapproval', request_id: requestId, signer_kid: signerKid };
}

const defaultRules: ThresholdRuleState[] = [
  { service: '*', endpoint: '', verb: '', m: 1 },
];

describe('scanRequestApprovals', () => {
  it('uses required_approvals from request, not rules lookup', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ required_approvals: 2 }),
      makeApproval('req-1', signerB, 2),
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.threshold).toBe(2);
    expect(result!.approvals).toBe(2);
    expect(result!.status).toBe('approved');
  });

  it('rejects votes from signers NOT in eligible_signer_kids', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ eligible_signer_kids: [signerA, signerB], required_approvals: 2 }),
      makeApproval('req-1', signerC, 2),
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.approvals).toBe(1);
    expect(result!.status).toBe('pending');
    expect(result!.votes).not.toHaveProperty(signerC);
  });

  it('excludes gateway from eligible votes', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ eligible_signer_kids: [signerA, gatewayKid], required_approvals: 2 }),
      makeApproval('req-1', gatewayKid, 2),
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.approvals).toBe(1);
    expect(result!.status).toBe('pending');
  });

  it('last-vote-wins for same signer', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ eligible_signer_kids: [signerA, signerB], required_approvals: 1 }),
      makeApproval('req-1', signerA, 2),
      makeDisapproval('req-1', signerA, 3),
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.approvals).toBe(0);
    expect(result!.votes[signerA]).toBe('disapprove');
    expect(result!.status).toBe('pending');
  });

  it('marks expired requests', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ expires_at: '2020-01-01T00:00:00Z' }),
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.status).toBe('expired');
  });

  it('marks executed requests', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({}),
      { seq: 2, type: 'gate.executed', request_id: 'req-1' },
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.status).toBe('executed');
  });

  it('marks invalidated requests', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({}),
      { seq: 2, type: 'gate.invalidated', request_id: 'req-1' },
    ];
    const result = scanRequestApprovals(messages, 'req-1', gatewayKid, defaultRules);
    expect(result).not.toBeNull();
    expect(result!.status).toBe('invalidated');
  });

  it('returns null for unknown request', () => {
    const result = scanRequestApprovals([], 'nonexistent', gatewayKid, defaultRules);
    expect(result).toBeNull();
  });

  it('falls back to rules lookup when eligible_signer_kids absent (backward compat)', () => {
    const reqBody = JSON.stringify({
      type: 'gate.request',
      conv_id: 'conv-1',
      request_id: 'req-legacy',
      verb: 'GET',
      target_endpoint: '/api/test',
      target_service: 'test-svc',
      target_url: 'https://api.example.com/test',
      expires_at: '2099-01-01T00:00:00Z',
      signer_kid: signerA,
      signature: 'sig-placeholder',
      // no eligible_signer_kids or required_approvals
    });
    const messages: StoredGateMessage[] = [
      { seq: 1, type: 'gate.request', request_id: 'req-legacy', signer_kid: signerA, signature: 'sig', body: reqBody },
    ];
    const rules: ThresholdRuleState[] = [{ service: '*', endpoint: '', verb: '', m: 1 }];
    const result = scanRequestApprovals(messages, 'req-legacy', gatewayKid, rules);
    expect(result).not.toBeNull();
    expect(result!.threshold).toBe(1);
    expect(result!.status).toBe('approved'); // signerA's submission counts
  });
});

describe('findExecutableRequests', () => {
  it('returns only approved requests', () => {
    const messages: StoredGateMessage[] = [
      makeRequest({ request_id: 'req-1', eligible_signer_kids: [signerA], required_approvals: 1 }),
      makeRequest({ request_id: 'req-2', eligible_signer_kids: [signerA, signerB], required_approvals: 2 }),
    ];
    const results = findExecutableRequests(messages, gatewayKid, defaultRules);
    expect(results).toHaveLength(1);
    expect(results[0].request_id).toBe('req-1');
  });
});
