/**
 * Phase 1 long integration: 2 participants, 2-of-2 promotion, HN request result in chat.
 *
 * Tests the baseline expensive path:
 * - Two-person conversation
 * - Gateway promotion to 2-of-2
 * - Gate request with deterministic fixture
 * - Threshold met with both approvals
 * - Result visible in transcript
 *
 * Opt-in: run with `npm run test:long`
 */

import { describe, it, expect, afterEach } from 'vitest';
import { InMemoryRelay, CLIAgent, APIFixture } from './src/harness.js';
import {
  base64UrlEncode,
  keyIDFromPublicKey,
  signRequest,
  signApproval,
  hashRequest,
  computePayloadHash,
} from '@corpollc/qntm';

describe('Phase 1: 2-of-2 promotion, request, and result', () => {
  const agents: CLIAgent[] = [];
  const relay = new InMemoryRelay();
  const fixture = new APIFixture();

  afterEach(() => {
    for (const agent of agents) agent.cleanup();
    agents.length = 0;
    relay.clear();
  });

  it('full lifecycle: promote → request → approve → executed → result', () => {
    // Setup: two participants
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    // Create shared conversation
    const { convIdHex, conversation } = alice.createConversation('Ops');
    bob.joinConversation(convIdHex, { ...conversation });

    // Register deterministic API fixture
    fixture.register('GET', '/v1/top-stories', {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([1, 2, 3, 4, 5]),
    });

    // Step 1: Promote conversation to 2-of-2
    const gatewayKid = 'gateway-test-kid';
    const promoteBody = JSON.stringify({
      type: 'gate.promote',
      conv_id: convIdHex,
      gateway_kid: gatewayKid,
      participants: {
        [alice.kidB64]: base64UrlEncode(alice.identity.publicKey),
        [bob.kidB64]: base64UrlEncode(bob.identity.publicKey),
      },
      rules: [{ service: '*', endpoint: '*', verb: '*', m: 2 }],
      floor: 2,
    });
    alice.sendMessage(relay, convIdHex, 'gate.promote', new TextEncoder().encode(promoteBody));

    // Bob receives promote
    const bobPromo = bob.receiveMessages(relay, convIdHex);
    expect(bobPromo).toHaveLength(1);
    expect(bobPromo[0].bodyType).toBe('gate.promote');

    // Step 2: Alice submits a gate request
    const requestId = 'req-phase1-001';
    const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600;
    const payloadHash = computePayloadHash(null);

    const signable = {
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/v1/top-stories',
      target_service: 'hackernews',
      target_url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
      expires_at_unix: expiresAtUnix,
      payload_hash: payloadHash,
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    };

    const requestSig = signRequest(alice.identity.privateKey, signable);
    const requestBody = JSON.stringify({
      type: 'gate.request',
      recipe_name: 'hn.top',
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/v1/top-stories',
      target_service: 'hackernews',
      target_url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
      expires_at: new Date(expiresAtUnix * 1000).toISOString(),
      signer_kid: alice.kidB64,
      signature: base64UrlEncode(requestSig),
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    });
    alice.sendMessage(relay, convIdHex, 'gate.request', new TextEncoder().encode(requestBody));

    // Bob receives request
    const bobReq = bob.receiveMessages(relay, convIdHex);
    expect(bobReq).toHaveLength(1);
    expect(bobReq[0].bodyType).toBe('gate.request');
    const parsedReq = JSON.parse(new TextDecoder().decode(bobReq[0].body));
    expect(parsedReq.request_id).toBe(requestId);

    // Step 3: Bob approves
    const reqHash = hashRequest(signable);
    const approvalSignable = {
      conv_id: convIdHex,
      request_id: requestId,
      request_hash: reqHash,
    };
    const approvalSig = signApproval(bob.identity.privateKey, approvalSignable);
    const approvalBody = JSON.stringify({
      type: 'gate.approval',
      conv_id: convIdHex,
      request_id: requestId,
      signer_kid: bob.kidB64,
      signature: base64UrlEncode(approvalSig),
    });
    bob.sendMessage(relay, convIdHex, 'gate.approval', new TextEncoder().encode(approvalBody));

    // Alice receives approval
    const aliceApproval = alice.receiveMessages(relay, convIdHex);
    expect(aliceApproval).toHaveLength(1);
    expect(aliceApproval[0].bodyType).toBe('gate.approval');

    // Step 4: Simulate gateway execution (in a real test, the gateway worker would do this)
    // The gateway posts gate.executed and gate.result
    const fixtureResponse = fixture.handle('GET', '/v1/top-stories');
    expect(fixtureResponse.status).toBe(200);

    const executedBody = JSON.stringify({
      type: 'gate.executed',
      request_id: requestId,
      executed_at: new Date().toISOString(),
      execution_status_code: fixtureResponse.status,
    });
    // Use alice to post the executed marker (simulating gateway)
    alice.sendMessage(relay, convIdHex, 'gate.executed', new TextEncoder().encode(executedBody));

    const resultBody = JSON.stringify({
      type: 'gate.result',
      request_id: requestId,
      status_code: fixtureResponse.status,
      content_type: fixtureResponse.contentType,
      body: fixtureResponse.body,
    });
    alice.sendMessage(relay, convIdHex, 'gate.result', new TextEncoder().encode(resultBody));

    // Step 5: Bob receives execution and result
    const bobResult = bob.receiveMessages(relay, convIdHex);
    expect(bobResult).toHaveLength(2);

    // Verify transcript order: executed then result
    expect(bobResult[0].bodyType).toBe('gate.executed');
    expect(bobResult[1].bodyType).toBe('gate.result');

    // Verify result content
    const parsedResult = JSON.parse(new TextDecoder().decode(bobResult[1].body));
    expect(parsedResult.status_code).toBe(200);
    expect(parsedResult.body).toBe(JSON.stringify([1, 2, 3, 4, 5]));

    // Verify full transcript order by replaying all messages
    const allMessages = relay.poll(convIdHex, 0);
    expect(allMessages.messages.length).toBe(5); // promote, request, approval, executed, result
  });

  it('request is visible in both participants transcript', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Visible');
    bob.joinConversation(convIdHex, { ...conversation });

    // Alice sends a text and a request
    alice.sendText(relay, convIdHex, 'about to request');

    const requestBody = JSON.stringify({
      type: 'gate.request',
      request_id: 'vis-001',
      verb: 'GET',
      target_url: 'https://example.com/api',
    });
    alice.sendMessage(relay, convIdHex, 'gate.request', new TextEncoder().encode(requestBody));

    // Bob sees both
    const bobMsgs = bob.receiveMessages(relay, convIdHex);
    expect(bobMsgs).toHaveLength(2);
    expect(bobMsgs[0].bodyType).toBe('text');
    expect(bobMsgs[1].bodyType).toBe('gate.request');
  });
});
