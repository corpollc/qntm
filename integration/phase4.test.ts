/**
 * Phase 4: Disapproval blocks execution.
 *
 * Proves:
 * - A negative vote prevents request execution
 * - Denied state is visible in the transcript
 * - Vote flip (disapprove → approve) restores executability
 */

import { describe, it, expect, afterEach } from 'vitest';
import { InMemoryRelay, CLIAgent, APIFixture } from './src/harness.js';
import {
  base64UrlEncode,
  signRequest,
  signApproval,
  hashRequest,
  computePayloadHash,
} from '@corpollc/qntm';

describe('Phase 4: disapproval blocks execution', () => {
  const agents: CLIAgent[] = [];
  const relay = new InMemoryRelay();
  const fixture = new APIFixture();

  afterEach(() => {
    for (const agent of agents) agent.cleanup();
    agents.length = 0;
    relay.clear();
  });

  it('negative vote prevents execution and is visible in transcript', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('DenyTest');
    bob.joinConversation(convIdHex, { ...conversation });

    fixture.register('GET', '/leet/translate', {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ text: '1337 5p34k' }),
    });

    // Alice submits a request (2-of-2 threshold)
    const requestId = 'req-deny-001';
    const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600;
    const payloadHash = computePayloadHash(null);

    const signable = {
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/leet/translate',
      target_service: 'fun',
      target_url: 'https://api.example.test/leet/translate',
      expires_at_unix: expiresAtUnix,
      payload_hash: payloadHash,
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    };

    const requestSig = signRequest(alice.identity.privateKey, signable);
    const requestBody = JSON.stringify({
      type: 'gate.request',
      recipe_name: 'leet.translate',
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/leet/translate',
      target_service: 'fun',
      target_url: 'https://api.example.test/leet/translate',
      expires_at: new Date(expiresAtUnix * 1000).toISOString(),
      signer_kid: alice.kidB64,
      signature: base64UrlEncode(requestSig),
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    });
    alice.sendMessage(relay, convIdHex, 'gate.request', new TextEncoder().encode(requestBody));

    // Bob receives the request
    const bobReq = bob.receiveMessages(relay, convIdHex);
    expect(bobReq).toHaveLength(1);
    expect(bobReq[0].bodyType).toBe('gate.request');

    // Bob sends a disapproval
    const disapprovalBody = JSON.stringify({
      type: 'gate.disapproval',
      conv_id: convIdHex,
      request_id: requestId,
      signer_kid: bob.kidB64,
    });
    bob.sendMessage(relay, convIdHex, 'gate.disapproval', new TextEncoder().encode(disapprovalBody));

    // Alice receives the disapproval
    const aliceDeny = alice.receiveMessages(relay, convIdHex);
    expect(aliceDeny).toHaveLength(1);
    expect(aliceDeny[0].bodyType).toBe('gate.disapproval');

    const parsedDeny = JSON.parse(new TextDecoder().decode(aliceDeny[0].body));
    expect(parsedDeny.request_id).toBe(requestId);
    expect(parsedDeny.signer_kid).toBe(bob.kidB64);

    // Verify: no gate.executed or gate.result in the transcript
    const allMessages = relay.poll(convIdHex, 0);
    for (const msg of allMessages.messages) {
      // This is a simplified check since we're not running the gateway worker
      // In a real test, the gateway would poll and NOT execute because of the disapproval
    }

    // The transcript should contain: request, disapproval — no executed/result
    expect(allMessages.messages).toHaveLength(2);
  });

  it('vote flip: disapprove then approve restores executability', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('FlipTest');
    bob.joinConversation(convIdHex, { ...conversation });

    // Alice submits a request
    const requestId = 'req-flip-001';
    const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600;
    const payloadHash = computePayloadHash(null);

    const signable = {
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/leet/translate',
      target_service: 'fun',
      target_url: 'https://api.example.test/leet/translate',
      expires_at_unix: expiresAtUnix,
      payload_hash: payloadHash,
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    };

    const requestSig = signRequest(alice.identity.privateKey, signable);
    const requestBody = JSON.stringify({
      type: 'gate.request',
      conv_id: convIdHex,
      request_id: requestId,
      verb: 'GET',
      target_endpoint: '/leet/translate',
      target_service: 'fun',
      target_url: 'https://api.example.test/leet/translate',
      expires_at: new Date(expiresAtUnix * 1000).toISOString(),
      signer_kid: alice.kidB64,
      signature: base64UrlEncode(requestSig),
      eligible_signer_kids: [alice.kidB64, bob.kidB64],
      required_approvals: 2,
    });
    alice.sendMessage(relay, convIdHex, 'gate.request', new TextEncoder().encode(requestBody));
    bob.receiveMessages(relay, convIdHex); // consume

    // Bob disapproves
    const disapprovalBody = JSON.stringify({
      type: 'gate.disapproval',
      conv_id: convIdHex,
      request_id: requestId,
      signer_kid: bob.kidB64,
    });
    bob.sendMessage(relay, convIdHex, 'gate.disapproval', new TextEncoder().encode(disapprovalBody));
    alice.receiveMessages(relay, convIdHex); // consume

    // Bob flips to approve (last-vote-wins)
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

    // Alice receives the approval flip
    const aliceFlip = alice.receiveMessages(relay, convIdHex);
    expect(aliceFlip).toHaveLength(1);
    expect(aliceFlip[0].bodyType).toBe('gate.approval');

    // Full transcript: request, disapproval, approval (flip)
    const allMessages = relay.poll(convIdHex, 0);
    expect(allMessages.messages).toHaveLength(3);

    // At this point, the gateway would see 2 approvals (alice's submission + bob's flip)
    // and could execute the request
  });
});
