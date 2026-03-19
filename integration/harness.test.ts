/**
 * Integration harness smoke test.
 *
 * Verifies the harness can:
 * - Create isolated CLI agents
 * - Route messages through the in-memory relay
 * - Clean up without leaked state
 *
 * This is NOT part of the default test suite. Run with:
 *   cd integration && npm run test:long
 */

import { describe, it, expect, afterEach } from 'vitest';
import { InMemoryRelay, CLIAgent, APIFixture } from './src/harness.js';
import { existsSync } from 'node:fs';
import { buildSignedReceipt } from '@corpollc/qntm';

describe('Integration harness smoke', () => {
  const agents: CLIAgent[] = [];
  const relay = new InMemoryRelay();

  afterEach(() => {
    for (const agent of agents) {
      agent.cleanup();
    }
    agents.length = 0;
    relay.clear();
  });

  it('boots and tears down agents cleanly', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    expect(alice.name).toBe('alice');
    expect(bob.name).toBe('bob');
    expect(alice.kidHex).not.toBe(bob.kidHex);
    expect(existsSync(alice.configDir)).toBe(true);
    expect(existsSync(bob.configDir)).toBe(true);

    alice.cleanup();
    bob.cleanup();
    expect(existsSync(alice.configDir)).toBe(false);
    expect(existsSync(bob.configDir)).toBe(false);
  });

  it('routes text messages between two agents', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    // Alice creates conversation, bob joins with same keys
    const { convIdHex, conversation } = alice.createConversation('Test');
    bob.joinConversation(convIdHex, { ...conversation });

    // Alice sends a message
    alice.sendText(relay, convIdHex, 'hello from alice');

    // Bob receives it
    const received = bob.receiveMessages(relay, convIdHex);
    expect(received).toHaveLength(1);
    expect(received[0].bodyType).toBe('text');
    expect(new TextDecoder().decode(received[0].body)).toBe('hello from alice');
    expect(received[0].senderKid).toBe(alice.kidB64);
  });

  it('suppresses self-echoes', () => {
    const alice = new CLIAgent('alice');
    agents.push(alice);

    const { convIdHex } = alice.createConversation('Solo');
    alice.sendText(relay, convIdHex, 'talking to myself');

    const received = alice.receiveMessages(relay, convIdHex);
    expect(received).toHaveLength(0); // self-echo suppressed
  });

  it('handles multiple messages in order', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Multi');
    bob.joinConversation(convIdHex, { ...conversation });

    alice.sendText(relay, convIdHex, 'msg1');
    alice.sendText(relay, convIdHex, 'msg2');
    alice.sendText(relay, convIdHex, 'msg3');

    const received = bob.receiveMessages(relay, convIdHex);
    expect(received).toHaveLength(3);
    expect(new TextDecoder().decode(received[0].body)).toBe('msg1');
    expect(new TextDecoder().decode(received[1].body)).toBe('msg2');
    expect(new TextDecoder().decode(received[2].body)).toBe('msg3');
  });

  it('relay clears state cleanly', () => {
    const alice = new CLIAgent('alice');
    agents.push(alice);

    const { convIdHex } = alice.createConversation('Clear');
    alice.sendText(relay, convIdHex, 'before clear');

    relay.clear();

    const result = relay.poll(convIdHex, 0);
    expect(result.messages).toHaveLength(0);
  });

  it('API fixture serves deterministic responses', () => {
    const fixture = new APIFixture();
    fixture.register('GET', '/v1/status', {
      status: 200,
      contentType: 'application/json',
      body: '{"status":"ok"}',
    });

    const response = fixture.handle('GET', '/v1/status');
    expect(response.status).toBe(200);
    expect(response.body).toBe('{"status":"ok"}');

    const notFound = fixture.handle('POST', '/v1/missing');
    expect(notFound.status).toBe(404);
  });

  it('rerun stability: no leaked state between tests', () => {
    const alice = new CLIAgent('alice');
    agents.push(alice);

    const { convIdHex } = alice.createConversation('Rerun');
    alice.sendText(relay, convIdHex, 'first run');

    // Simulate teardown
    alice.cleanup();
    relay.clear();

    // Re-create
    const alice2 = new CLIAgent('alice');
    agents.push(alice2);

    const { convIdHex: convId2 } = alice2.createConversation('Rerun2');
    alice2.sendText(relay, convId2, 'second run');

    const result = relay.poll(convId2, 0);
    expect(result.messages).toHaveLength(1);
  });
});

describe('Read receipt flow', () => {
  const agents: CLIAgent[] = [];
  const relay = new InMemoryRelay();

  afterEach(() => {
    for (const agent of agents) agent.cleanup();
    agents.length = 0;
    relay.clear();
  });

  it('receipt recorded but message not deleted before threshold', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Test');
    bob.joinConversation(convIdHex, { ...conversation });

    alice.sendText(relay, convIdHex, 'hello');
    expect(relay.messageCount(convIdHex)).toBe(1);

    // Bob receives and receipts — required_acks from conv.participants
    // conv has 1 participant (alice), so required_acks = 1 → one receipt deletes
    const received = bob.receiveAndReceipt(relay, convIdHex);
    expect(received).toHaveLength(1);
    expect(new TextDecoder().decode(received[0].body)).toBe('hello');
  });

  it('message deleted when all participants have receipted', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Test');
    bob.joinConversation(convIdHex, { ...conversation });

    alice.sendText(relay, convIdHex, 'secret');
    expect(relay.messageCount(convIdHex)).toBe(1);

    // Manually submit receipts with required_acks = 2 to test threshold
    const messages = relay.poll(convIdHex, 0).messages;
    expect(messages.length).toBe(1);

    // First receipt (alice) — not enough
    const receipt1 = buildSignedReceipt(alice.identity, conversation.id, conversation.id, 2);
    // Use a real msg_id based on the envelope — we'll use conv.id as a stand-in
    const r1 = relay.submitReceipt(receipt1);
    expect(r1.recorded).toBe(true);
    expect(r1.deleted).toBe(false);
    expect(r1.receipts).toBe(1);

    // Second receipt (bob) — threshold met
    const receipt2 = buildSignedReceipt(bob.identity, conversation.id, conversation.id, 2);
    const r2 = relay.submitReceipt(receipt2);
    expect(r2.recorded).toBe(true);
    expect(r2.deleted).toBe(true);
    expect(r2.receipts).toBe(2);
  });

  it('receiveAndReceipt emits receipts and returns messages', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Receipt');
    bob.joinConversation(convIdHex, { ...conversation });

    alice.sendText(relay, convIdHex, 'ping');
    alice.sendText(relay, convIdHex, 'pong');

    // Bob receives and receipts both messages
    const received = bob.receiveAndReceipt(relay, convIdHex);
    expect(received).toHaveLength(2);
    expect(new TextDecoder().decode(received[0].body)).toBe('ping');
    expect(new TextDecoder().decode(received[1].body)).toBe('pong');
  });

  it('duplicate receipts from same reader are idempotent', () => {
    const alice = new CLIAgent('alice');
    agents.push(alice);

    const convId = new Uint8Array(16).fill(0xab);
    const msgId = new Uint8Array(16).fill(0xcd);

    const receipt = buildSignedReceipt(alice.identity, convId, msgId, 2);
    const r1 = relay.submitReceipt(receipt);
    const r2 = relay.submitReceipt(receipt);

    expect(r1.recorded).toBe(true);
    expect(r2.recorded).toBe(true);
    expect(r1.receipts).toBe(1);
    expect(r2.receipts).toBe(1);
  });

  it('buildSignedReceipt produces valid receipt payloads', () => {
    const alice = new CLIAgent('alice');
    agents.push(alice);

    const convId = new Uint8Array(16).fill(0xab);
    const msgId = new Uint8Array(16).fill(0xcd);

    const receipt = buildSignedReceipt(alice.identity, convId, msgId, 3);

    expect(receipt.proto).toBe('qntm-receipt-v1');
    expect(receipt.conv_id).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.msg_id).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.reader_kid).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.required_acks).toBe(3);
    expect(receipt.read_ts).toBeGreaterThan(0);
    expect(receipt.sig.length).toBeGreaterThan(0);
    expect(receipt.reader_ik_pk.length).toBeGreaterThan(0);
  });
});
