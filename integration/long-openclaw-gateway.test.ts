import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { OpenClawAgent } from './src/openclaw-agent.js';
import { createLongHarness, waitForCliHistory, waitForUiStoredHistory, type LongHarness } from './src/runtime.js';
import { LONG_TIMEOUT, historyMatchesRequest, historyMatchesProposal, requireUi, printDiagnostics } from './long-helpers.js';
import type { ToolResult } from '../openclaw-qntm/tests/support/tool-provider.mjs';

describe.sequential('native OpenClaw gateway tools with Python, TypeScript and browser peers', () => {
  let h: LongHarness, host: OpenClawAgent, convId: string;
  const last = (results: ToolResult[]) => results.at(-1)!;
  const receiveHost = async (type: string, id?: string) => host.waitFor(async () => {
    const state = await host.checkpoint();
    return Boolean(state?.session.events.some(event => event.body.type === type && (!id || JSON.stringify(event.body).includes(id))));
  }, `OpenClaw verified ${type}`);
  const action = async (id: string, action: string, options?: Record<string, unknown>) => last(await host.journey(h.alice, { id, action, options }));
  beforeAll(async () => {
    h = await createLongHarness({ withUi: true });
    await h.alice.run(['identity', 'generate']); await h.charlie.run(['identity', 'generate']);
    const created = await h.alice.run(['group', 'create', 'OpenClaw gateway acceptance']);
    convId = String(created.data!.conversation_id); const token = String(created.data!.invite_token);
    host = new OpenClawAgent(join(h.rootDir, 'openclaw'), convId); await host.configure(h.relayUrl, token); await host.start();
    await requireUi(h).joinConversation(token, 'OpenClaw gateway acceptance');
    await requireUi(h).sendText('browser joins native tool test');
    await h.charlie.run(['group', 'join', '--', token]); await h.charlie.run(['send', convId, 'typescript joins native tool test']);
    await h.alice.run(['send', convId, 'python joins native tool test']);
    await host.waitFor(async () => Object.keys((await host.checkpoint())?.session.participants ?? {}).length === 4, 'all participants known to OpenClaw');
  }, LONG_TIMEOUT);
  afterAll(async () => {
    if (h && host) { mkdirSync(h.artifactDir, { recursive: true }); writeFileSync(join(h.artifactDir, 'openclaw.log'), host.log); }
    await host?.close(); await h?.stop();
  }, LONG_TIMEOUT);

  it('admits the real gateway through the native agent tool and verifies signed acceptance on every client', async () => {
    try {
      const result = last(await host.journey(h.alice, { id: 'admit', action: 'invite', options: { gatewayUrl: h.gatewayUrl, floor: 2 },
        initialStatus: 'no_invitation', expectedStatus: 'awaiting_signed_acceptance' }));
      expect(result.messageId).toMatch(/^[a-f0-9]{32}$/);
      await host.waitFor(async () => Boolean((await host.checkpoint())?.session.gateway?.accepted), 'gateway accepts native invitation');
      await waitForCliHistory(h.alice, convId, e => e.body_type === 'gate.accept', 'native admission visible to Python');
      await waitForCliHistory(h.charlie, convId, e => e.body_type === 'gate.accept', 'native admission visible to TypeScript');
      await waitForUiStoredHistory(requireUi(h), convId, e => e.bodyType === 'gate.accept', 'native admission visible in browser');
    } catch (error) { await printDiagnostics(h, convId); throw error; }
  }, LONG_TIMEOUT);

  it('provisions a sealed credential and approves a Python request that executes exactly once', async () => {
    await action('secret', 'secret', { service: 'fun', value: 'test-key' }); await receiveHost('gate.secret');
    const requested = await h.alice.run(['gate-run', 'counter.bump', '-c', convId]);
    expect(requested.ok).toBe(true); const id = String(requested.data!.request_id); await receiveHost('gate.request', id);
    const result = await action('approve-python', 'approve', { id }); expect(result.status).toBe('submitted');
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.result', id), 'native approval executes Python request');
    await waitForCliHistory(h.charlie, convId, historyMatchesRequest('gate.result', id), 'native execution verified by TypeScript');
    await waitForUiStoredHistory(requireUi(h), convId, e => e.bodyType === 'gate.result' && String(e.text).includes(id), 'native execution visible in browser');
    expect(h.getCounterExecutions()).toBe(1);
    await host.journey(h.alice, { id: 'reject-terminal', single: { operation: 'prepare', action: 'approve', options: { id } },
      expectedStatus: 'error', expectedCode: 'subject_unavailable' });
    expect(h.getCounterExecutions()).toBe(1);
  }, LONG_TIMEOUT);

  it('withdraws its request vote and requires the browser/Python/native quorum before execution', async () => {
    const results = await host.journey(h.alice, { id: 'request-native', action: 'request', options: {
      service: 'fun', endpoint: '/counter', verb: 'POST', targetUrl: `${h.fixture.baseUrl}/counter`, requiredApprovals: 3, payload: { source: 'openclaw' },
    } });
    const id = String(results[1].review!.body!.request_id); await receiveHost('gate.request', id);
    await action('withdraw-native', 'disapprove', { id }); await receiveHost('gate.disapproval', id);
    await requireUi(h).approveLatestRequest(); await h.alice.run(['gate-approve', id, '-c', convId]);
    await receiveHost('gate.approval', id); expect(h.getCounterExecutions()).toBe(1);
    await action('restore-native', 'approve', { id });
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.result', id), 'native request reaches quorum');
    expect(h.getCounterExecutions()).toBe(2);
  }, LONG_TIMEOUT);

  it('governs policy, rejects a stale review after membership rekey, and restores protocol state after host restart', async () => {
    const proposed = await host.journey(h.alice, { id: 'rules-native', action: 'propose', options: {
      proposalType: 'rules_change', proposedRules: [{ service: '*', endpoint: '*', verb: '*', m: 2 }],
    } });
    const proposalId = String(proposed[1].review!.body!.proposal_id); await receiveHost('gov.propose', proposalId);
    await action('rules-withdraw', 'gov-disapprove', { id: proposalId });
    await requireUi(h).approveLatestProposal(); await h.alice.run(['gov', 'approve', proposalId, '-c', convId]);
    await action('rules-restore', 'gov-approve', { id: proposalId });
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', proposalId), 'native governance application');
    await receiveHost('gov.applied', proposalId);
    const pending = await h.charlie.sendGatewayRequest(convId, { service: 'fun', endpoint: '/counter', verb: 'POST', targetUrl: `${h.fixture.baseUrl}/counter`, requiredApprovals: 4 });
    await receiveHost('gate.request', pending);
    const review = last(await host.journey(h.alice, { id: 'prepare-stale', single: { operation: 'prepare', action: 'approve', options: { id: pending } }, expectedStatus: 'review_required' }));
    await host.journey(h.charlie, { id: 'reject-other-requester', single: { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash },
      expectedStatus: 'error', expectedCode: 'review_unavailable' });
    const removed = await h.alice.run(['gov', 'propose-remove', '-c', convId, '--required-approvals', '3', '--', h.charlie.readIdentity().key_id]);
    const removeId = String(removed.data!.proposal_id);
    await requireUi(h).approveLatestProposal(); await h.charlie.run(['recv', convId]); await h.charlie.run(['gov', 'approve', removeId, '-c', convId]);
    await host.waitFor(async () => (await host.checkpoint())?.conversation.currentEpoch === 1, 'native membership rekey');
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', removeId), 'Python receives membership rekey before its next send');
    await host.journey(h.alice, { id: 'reject-stale', single: { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }, expectedStatus: 'error', expectedCode: 'review_stale' });
    expect(h.getCounterExecutions()).toBe(2);
    const beforeRestart = last(await host.journey(h.alice, { id: 'prepare-before-restart', single: { operation: 'prepare', action: 'request', options: {
      service: 'fun', endpoint: '/counter', verb: 'POST', targetUrl: `${h.fixture.baseUrl}/counter`,
    } }, expectedStatus: 'review_required' }));
    await host.stop('SIGKILL'); await host.start();
    expect((await host.checkpoint())?.conversation.currentEpoch).toBe(1);
    await host.journey(h.alice, { id: 'reject-after-restart', single: { operation: 'commit', reviewToken: beforeRestart.reviewToken, reviewHash: beforeRestart.reviewHash },
      expectedStatus: 'error', expectedCode: 'review_unavailable' });
    const fresh = await h.alice.run(['gate-run', 'counter.bump', '-c', convId]); const freshId = String(fresh.data!.request_id);
    await receiveHost('gate.request', freshId); await action('approve-after-restart', 'approve', { id: freshId });
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.result', freshId), 'native execution after restart and rekey');
    expect(h.getCounterExecutions()).toBe(3);
    const removeHost = await h.alice.run(['gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', Buffer.from(host.identity.keyID).toString('hex')]);
    await requireUi(h).approveLatestProposal();
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', String(removeHost.data!.proposal_id)), 'native identity removal');
    await host.waitFor(async () => Boolean((await host.checkpoint())?.session.removed), 'native removed state');
    await host.stop(); await host.start();
    expect((await host.checkpoint())?.session.removed).toBe(true);
  }, LONG_TIMEOUT);
});
