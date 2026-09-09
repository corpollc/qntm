import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createLongHarness, waitForCliHistory, waitForUiStoredHistory, type LongHarness } from './src/runtime.js';
import { TuiAgent } from './src/tui-agent.js';
import { LONG_TIMEOUT, historyMatchesRequest, historyMatchesProposal, requireUi, printDiagnostics } from './long-helpers.js';

describe.sequential('real terminal gateway actions with Python, TypeScript and browser peers', () => {
  let h: LongHarness, tui: TuiAgent, convId: string;
  const file = (name: string, options: unknown) => {
    const path = join(h.rootDir, name); writeFileSync(path, JSON.stringify(options), { mode: 0o600 }); return path;
  };
  const receiveTui = async (type: string, id?: string) => {
    await expect.poll(() => tui.history(convId).some(m => m.bodyType === type && (!id || m.text.includes(id))), { timeout: 30000 }).toBe(true);
  };
  beforeAll(async () => {
    h = await createLongHarness({ withUi: true });
    await h.alice.run(['identity', 'generate']); await h.charlie.run(['identity', 'generate']);
    const created = await h.alice.run(['group', 'create', 'Terminal gateway acceptance']);
    convId = String(created.data!.conversation_id); const token = String(created.data!.invite_token);
    await requireUi(h).joinConversation(token, 'Terminal gateway acceptance');
    await requireUi(h).sendText('hello from browser');
    await h.charlie.run(['group', 'join', '--', token]);
    await h.charlie.run(['send', convId, 'hello from typescript']);
    tui = new TuiAgent(join(h.rootDir, 'terminal'), h.relayUrl);
    await tui.start();
    const joined = await tui.command(`/join ${token}`); await tui.waitFor('Joined conversation', joined);
    await tui.command('hello from terminal');
    await waitForCliHistory(h.alice, convId, e => e.unsafe_body === 'hello from terminal', 'terminal participant discovery');
    await h.alice.run(['send', convId, 'hello from python']);
  }, LONG_TIMEOUT);
  afterAll(async () => {
    if (h && tui) { mkdirSync(h.artifactDir, { recursive: true }); writeFileSync(join(h.artifactDir, 'terminal.ansi'), tui.output); }
    await tui?.stop(); await h?.stop();
  }, LONG_TIMEOUT);

  it('invites the gateway from a real PTY and waits for its signed acceptance on all four clients', async () => {
    try {
    await expect.poll(() => Object.keys(tui.conversation(convId)?.session?.participants ?? {}).length, { timeout: 20000 }).toBe(4);
      const shown = await tui.review(`/gate invite ${h.gatewayUrl} 2`);
      expect(shown).toContain('receive the current conversation keys');
      await receiveTui('gate.accept');
      expect(tui.conversation(convId).session.gateway.accepted).toBe(true);
      await waitForCliHistory(h.alice, convId, e => e.body_type === 'gate.accept', 'terminal gateway accepted by Python');
      await waitForCliHistory(h.charlie, convId, e => e.body_type === 'gate.accept', 'terminal gateway accepted by TypeScript');
      await waitForUiStoredHistory(requireUi(h), convId, e => e.bodyType === 'gate.accept', 'terminal gateway accepted by browser');
    } catch (error) { await printDiagnostics(h, convId); throw error; }
  }, LONG_TIMEOUT);

  it('sends a sealed credential, then approves a Python request and observes real execution in browser and TypeScript', async () => {
    const secret = file('terminal-secret.json', { service: 'fun', value: 'test-key' });
    const review = await tui.review(`/secret ${secret}`);
    expect(review).not.toContain('test-key'); expect(review).toContain('secret_sha256');
    await receiveTui('gate.secret');
    const request = await h.alice.run(['gate-run', 'counter.bump', '-c', convId]);
    const id = String(request.data!.request_id); await receiveTui('gate.request', id);
    const approved = await tui.review(`/approve ${id.slice(0, 8)}`);
    expect(approved).toContain('/counter');
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.result', id), 'terminal approval execution');
    await waitForUiStoredHistory(requireUi(h), convId, e => e.bodyType === 'gate.result' && String(e.text).includes(id), 'terminal execution visible in browser');
    await waitForCliHistory(h.charlie, convId, historyMatchesRequest('gate.result', id), 'terminal execution visible in TypeScript');
    expect(h.getCounterExecutions()).toBe(1);
  }, LONG_TIMEOUT);

  it('withdraws a terminal vote, then accepts a browser approval of a terminal-authored request', async () => {
    const options = file('terminal-request.json', { service: 'fun', endpoint: '/counter', verb: 'POST', targetUrl: `${h.fixture.baseUrl}/counter`, requiredApprovals: 3, payload: { source: 'terminal' } });
    await tui.review(`/request ${options}`);
    await receiveTui('gate.request');
    const req = JSON.parse(tui.history(convId).filter(m => m.bodyType === 'gate.request' && m.direction === 'outgoing').at(-1).text);
    await tui.review(`/disapprove ${req.request_id}`);
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.disapproval', req.request_id), 'terminal disapproval');
    await requireUi(h).approveLatestRequest();
    await h.alice.run(['gate-approve', req.request_id, '-c', convId]);
    await receiveTui('gate.approval', req.request_id);
    expect(h.getCounterExecutions()).toBe(1); // terminal withdrew its initial vote
    await tui.review(`/approve ${req.request_id}`);
    await waitForCliHistory(h.alice, convId, historyMatchesRequest('gate.result', req.request_id), 'terminal-authored request execution');
    expect(h.getCounterExecutions()).toBe(2);
  }, LONG_TIMEOUT);

  it('reviews governance, withdraws and restores its vote, and rejects the old review after a membership rekey', async () => {
    const proposal = file('terminal-rules.json', { proposalType: 'rules_change', proposedRules: [{ service: '*', endpoint: '*', verb: '*', m: 2 }] });
    await tui.review(`/propose ${proposal}`);
    await receiveTui('gov.propose');
    const id = JSON.parse(tui.history(convId).filter(m => m.bodyType === 'gov.propose' && m.direction === 'outgoing').at(-1).text).proposal_id;
    await tui.review(`/gov-disapprove ${id}`);
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.disapprove', id), 'terminal governance disapproval');
    await requireUi(h).approveLatestProposal();
    await h.alice.run(['gov', 'approve', id, '-c', convId]);
    await tui.review(`/gov-approve ${id}`);
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', id), 'terminal governance application');
    const pending = await h.charlie.sendGatewayRequest(convId, { service: 'fun', endpoint: '/counter', verb: 'POST', targetUrl: `${h.fixture.baseUrl}/counter`, requiredApprovals: 4 });
    await receiveTui('gate.request', pending);
    await tui.review(`/approve ${pending}`, false);
    const removedKid = h.charlie.readIdentity().key_id;
    const removed = await h.alice.run(['gov', 'propose-remove', '-c', convId, '--required-approvals', '3', '--', removedKid]);
    const removeId = String(removed.data!.proposal_id);
    // This membership change needs three of the four current members.
    await requireUi(h).approveLatestProposal();
    await h.charlie.run(['recv', convId]); await h.charlie.run(['gov', 'approve', removeId, '-c', convId]);
    await expect.poll(() => tui.conversation(convId).currentEpoch, { timeout: 30000 }).toBe(1);
    const from = await tui.command('/confirm'); await tui.waitFor('changed since review', from);
    await tui.stop(); await tui.start();
    expect(tui.conversation(convId).session.gateway.context.epoch).toBe(1);
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', removeId), 'Python catches up to the new epoch');
    await h.alice.run(['send', convId, 'after terminal restart and rekey']);
    await expect.poll(() => tui.history(convId).some(m => m.text === 'after terminal restart and rekey'), { timeout: 20000 }).toBe(true);
    const removeTerminal = await h.alice.run(['gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', tui.readIdentity().key_id]);
    await requireUi(h).approveLatestProposal();
    await waitForCliHistory(h.alice, convId, historyMatchesProposal('gov.applied', String(removeTerminal.data!.proposal_id)), 'terminal removal');
    await expect.poll(() => tui.conversation(convId).session.removed, { timeout: 20000 }).toBe(true);
    const denied = await tui.command(`/approve ${pending}`); await tui.waitFor('removed from this conversation', denied);
  }, LONG_TIMEOUT);
});
