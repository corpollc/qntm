import { describe, expect, it } from 'vitest';
import { generateIdentity, base64UrlEncode as b64, base64UrlDecode as bytes, openSecret, verifyApproval,
  hashRequest, signRequest, signProposal, verifyGovApproval, hashProposal,
  createInvite, createConversation, deriveConversationKeys, createMessage, decryptMessage, serializeEnvelope, deserializeEnvelope,
  createGatewayMessage, verifyGatewayMessage, scanGateRequest, scanGatewayProposal } from '../src/index.js';
import { createGateRequestBody, createGateApprovalBody, createGateSecretBody, createGateDisapprovalBody,
  createGatewayProposalBody, createGatewayProposalApprovalBody, gateRequestSignable, gatewayProposalSignable,
  assertGateRequest, assertGatewayProposal } from '../src/gate/workflow-build.js';
import { parseGatewayBody } from '../src/gate/workflow-parse.js';
import type { GatewayContext, GatewayProposalBody } from '../src/gate/workflow-types.js';

const alice = generateIdentity(), bob = generateIdentity(), gateway = generateIdentity(), outsider = generateIdentity();
const context: GatewayContext = {
  conversationId: 'ab'.repeat(16), epoch: 3,
  gateway: { kid: b64(gateway.keyID), publicKey: b64(gateway.publicKey) },
  participants: { [b64(alice.keyID)]: b64(alice.publicKey), [b64(bob.keyID)]: b64(bob.publicKey) },
  floor: 1, rules: [{ service: '*', endpoint: '*', verb: '*', m: 2 }],
};
const options = { service: 'counter', endpoint: '/bump', verb: 'POST', targetUrl: 'https://api.example.test/bump', payload: { increment: 1 } };
const request = () => createGateRequestBody(alice, context, options);
const invite = createInvite(alice, 'group');
const conversation = createConversation(invite, deriveConversationKeys(invite));
conversation.id = Uint8Array.from(Buffer.from(context.conversationId, 'hex'));
conversation.currentEpoch = context.epoch;

describe('gateway workflow payloads', () => {
  it('derives a complete current roster and binds the gateway, target and JSON payload', () => {
    const req = request();
    expect(req.required_approvals).toBe(2);
    expect(req.eligible_signer_kids.sort()).toEqual(Object.keys(context.participants).sort());
    expect(req.gateway_kid).toBe(context.gateway.kid);
    expect(() => assertGateRequest(req, context)).not.toThrow();
    const vote = createGateApprovalBody(bob, context, req);
    expect(verifyApproval(bob.publicKey, { conv_id: req.conv_id, request_id: req.request_id,
      request_hash: hashRequest(gateRequestSignable(req)) }, bytes(vote.signature))).toBe(true);
    expect(() => assertGateRequest({ ...req, payload: { increment: 99 } }, context)).toThrow('signature');
    expect(createGateDisapprovalBody(bob, context, req).signer_kid).toBe(b64(bob.keyID));
  });
  it('refuses removed signers, duplicate rosters, different conversations and gateways', () => {
    const req = request();
    expect(() => createGateApprovalBody(outsider, context, req)).toThrow('current participant');
    expect(() => createGateApprovalBody(bob, { ...context, participants: { [b64(alice.keyID)]: b64(alice.publicKey) } }, req)).toThrow();
    expect(() => assertGateRequest({ ...req, conv_id: 'cd'.repeat(16) }, context)).toThrow('Conversation');
    expect(() => assertGateRequest({ ...req, gateway_kid: b64(outsider.keyID) }, context)).toThrow('Gateway');
    expect(() => assertGateRequest({ ...req, eligible_signer_kids: [b64(alice.keyID), b64(alice.keyID)] }, context)).toThrow('Duplicate');
  });
  it('does not approve expired requests or policies exceeding available signers', () => {
    const req = createGateRequestBody(alice, context, { ...options, now: 1000, expiresInSeconds: 1 });
    expect(() => createGateApprovalBody(bob, context, req, 2000)).toThrow('expired');
    expect(() => createGateRequestBody(alice, { ...context, floor: 3 }, options)).toThrow('signer count');
    const lowered = request();
    lowered.required_approvals = 1;
    lowered.signature = b64(signRequest(alice.privateKey, gateRequestSignable(lowered)));
    expect(() => assertGateRequest(lowered, context)).toThrow('policy');
  });
  it('seals credentials only to the configured key and leaves caller bytes intact', () => {
    const value = new TextEncoder().encode('demo credential');
    const secret = createGateSecretBody(alice, context, { service: 'counter', value, ttl: 60 });
    expect(secret.gateway_kid).toBe(context.gateway.kid);
    expect(openSecret(gateway.privateKey, alice.publicKey, bytes(secret.encrypted_blob))).toEqual(value);
    expect(new TextDecoder().decode(value)).toBe('demo credential');
    expect(() => openSecret(bob.privateKey, alice.publicKey, bytes(secret.encrypted_blob))).toThrow();
    expect(() => createGateSecretBody(alice, context, { service: 'counter', value, headerName: 'Bad\r\nHeader' })).toThrow('header');
    expect(() => createGateSecretBody(alice, { ...context, gateway: { ...context.gateway, publicKey: b64(bob.publicKey) } }, { service: 'counter', value })).toThrow('key ID');
  });
  it.each(['floor_change', 'rules_change', 'member_add', 'member_remove'] as const)('builds and approves %s under current majority', proposalType => {
    const body = createGatewayProposalBody(alice, context, {
      proposalType, requiredApprovals: 1,
      ...(proposalType === 'floor_change' ? { proposedFloor: 2 } : {}),
      ...(proposalType === 'rules_change' ? { proposedRules: context.rules } : {}),
      ...(proposalType === 'member_add' ? { proposedMembers: [{ kid: b64(outsider.keyID), publicKey: b64(outsider.publicKey) }] } : {}),
      ...(proposalType === 'member_remove' ? { removedMemberKids: [b64(bob.keyID)] } : {}),
    });
    expect(body.required_approvals).toBe(2);
    const vote = createGatewayProposalApprovalBody(bob, context, body);
    expect(verifyGovApproval(bob.publicKey, { conv_id: body.conv_id, proposal_id: body.proposal_id,
      proposal_hash: hashProposal(gatewayProposalSignable(body)) }, bytes(vote.signature))).toBe(true);
  });
  it('preserves nullable Python governance fields and their signing hash', () => {
    const body: GatewayProposalBody = { ...createGatewayProposalBody(alice, context, { proposalType: 'floor_change', proposedFloor: 2 }),
      proposed_rules: null, proposed_members: null, removed_member_kids: null };
    body.signature = b64(signProposal(alice.privateKey, gatewayProposalSignable(body)));
    const parsed = parseGatewayBody('gov.propose', JSON.stringify(body)) as GatewayProposalBody;
    expect(parsed.proposed_rules).toBeNull();
    expect(() => assertGatewayProposal(parsed, context)).not.toThrow();
    expect(() => createGatewayProposalApprovalBody(bob, context, parsed)).not.toThrow();
    expect(() => assertGatewayProposal({ ...parsed, proposed_rules: undefined }, context)).toThrow('signature');
  });
  it('rejects mismatched body types, unsupported config mutations and noncanonical IDs', () => {
    expect(() => parseGatewayBody('gate.approval', JSON.stringify(request()))).toThrow('type mismatch');
    expect(() => parseGatewayBody('gate.config', '{"type":"gate.config","rules":[]}')).toThrow('Unsupported');
    expect(() => parseGatewayBody('gate.request', JSON.stringify({ ...request(), signer_kid: b64(alice.keyID) + '=' }))).toThrow('signer kid');
    expect(() => parseGatewayBody('gate.request', new Uint8Array([255]))).toThrow('JSON');
  });
  it('verifies encrypted messages after serialization and rejects forged terminal events', () => {
    const req = request();
    const envelope = createGatewayMessage(alice, conversation, req, context);
    const restored = decryptMessage(deserializeEnvelope(serializeEnvelope(envelope)), conversation);
    expect(verifyGatewayMessage(restored, context).body).toEqual(req);
    expect(() => verifyGatewayMessage(restored, { ...context, epoch: 4 })).toThrow('epoch');
    const terminal = { type: 'gate.executed' as const, request_id: req.request_id,
      executed_at: new Date().toISOString(), execution_status_code: 200 };
    expect(() => createGatewayMessage(bob, conversation, terminal, context)).toThrow('configured gateway');
    const genuine = createGatewayMessage(gateway, conversation, terminal, context);
    expect(verifyGatewayMessage(decryptMessage(genuine, conversation), context).senderKid).toBe(context.gateway.kid);
    restored.inner.body = new TextEncoder().encode(JSON.stringify({ ...req, target_url: 'https://attacker.test' }));
    expect(() => verifyGatewayMessage(restored, context)).toThrow('Unauthenticated');
  });
  it('requires the actual request before verifying a vote, even with a valid envelope', () => {
    const req = request(), other = request();
    const approval = createGateApprovalBody(bob, context, req);
    const envelope = createGatewayMessage(bob, conversation, approval, context, { request: req });
    const message = decryptMessage(envelope, conversation);
    expect(() => verifyGatewayMessage(message, context)).toThrow('Matching request');
    expect(() => verifyGatewayMessage(message, context, { request: other })).toThrow('Matching request');
    const forged = createMessage(bob, conversation, 'gate.approval', new TextEncoder().encode(JSON.stringify({ ...approval, signature: b64(new Uint8Array(64)) })));
    expect(() => verifyGatewayMessage(decryptMessage(forged, conversation), context, { request: req })).toThrow('approval signature');
  });
  it('summarizes unique last votes and keeps approved distinct from executed', () => {
    const req = request();
    const event = (identity: typeof alice, body: Parameters<typeof createGatewayMessage>[2]) => verifyGatewayMessage(
      decryptMessage(createGatewayMessage(identity, conversation, body, context, { request: req }), conversation), context, { request: req });
    const sent = event(alice, req);
    const approval = event(bob, createGateApprovalBody(bob, context, req));
    const refusal = event(bob, createGateDisapprovalBody(bob, context, req));
    expect(scanGateRequest([sent], context, req.request_id)?.approvals).toBe(1);
    expect(scanGateRequest([sent, approval, approval], context, req.request_id)).toMatchObject({ status: 'approved', approvals: 2 });
    expect(scanGateRequest([sent, approval, refusal], context, req.request_id)).toMatchObject({ status: 'pending', approvals: 1 });
    const second = event(bob, createGateApprovalBody(bob, context, req));
    expect(scanGateRequest([sent, approval, refusal, second], context, req.request_id)?.status).toBe('approved');
    expect(scanGateRequest([sent, approval], context, req.request_id, Date.parse(req.expires_at))?.status).toBe('expired');
    const executed = event(gateway, { type: 'gate.executed', request_id: req.request_id, executed_at: new Date().toISOString(), execution_status_code: 200 });
    const result = event(gateway, { type: 'gate.result', request_id: req.request_id, status_code: 200, body: 'done' });
    expect(scanGateRequest([sent, approval, executed, result], context, req.request_id)).toMatchObject({ status: 'executed', result: { body: 'done' } });
    expect(scanGateRequest([sent, approval], { ...context, participants: { [b64(alice.keyID)]: b64(alice.publicKey) } }, req.request_id)?.status).toBe('invalidated');
  });
  it('recognizes governance approval and a gateway-authored invalidation after policy changes', () => {
    const proposal = createGatewayProposalBody(alice, context, { proposalType: 'floor_change', proposedFloor: 2 });
    const event = (identity: typeof alice, body: Parameters<typeof createGatewayMessage>[2]) => verifyGatewayMessage(
      decryptMessage(createGatewayMessage(identity, conversation, body, context, { proposal }), conversation), context, { proposal });
    const first = event(alice, proposal);
    const approval = event(bob, createGatewayProposalApprovalBody(bob, context, proposal));
    expect(scanGatewayProposal([first, approval], context, proposal.proposal_id)?.status).toBe('approved');
    const invalidated = event(gateway, { type: 'gov.invalidated', proposal_id: proposal.proposal_id, invalidated_at: new Date().toISOString(), message: 'Policy changed' });
    expect(scanGatewayProposal([first, approval, invalidated], context, proposal.proposal_id)?.status).toBe('invalidated');
  });
});
