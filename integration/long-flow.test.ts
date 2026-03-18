import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { LongHarness } from './src/runtime.js';
import {
  assertNoCliHistory,
  createLongHarness,
  waitForCliHistory,
  waitForUiStoredHistory,
  waitForUiText,
} from './src/runtime.js';

const LONG_TIMEOUT = 300_000;
const UI_LABEL = 'Long Run';

function parseUnsafeBody(entry: Record<string, unknown>): Record<string, unknown> {
  const raw = entry.unsafe_body;
  if (typeof raw !== 'string') {
    throw new Error(`Missing unsafe_body on history entry: ${JSON.stringify(entry)}`);
  }
  return JSON.parse(raw) as Record<string, unknown>;
}

function historyMatchesRequest(bodyType: string, requestId: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).request_id === requestId;
    } catch {
      return false;
    }
  };
}

function historyContainsText(text: string) {
  return (entry: Record<string, unknown>): boolean => (
    entry.body_type === 'text' && entry.unsafe_body === text
  );
}

function uiHistoryMatchesRequest(bodyType: string, requestId: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.bodyType !== bodyType) return false;
    const text = entry.text;
    if (typeof text !== 'string') return false;
    try {
      return (JSON.parse(text) as Record<string, unknown>).request_id === requestId;
    } catch {
      return false;
    }
  };
}

function summarizeHistory(entries: Array<Record<string, unknown>>): string {
  return entries.map((entry) => {
    const bodyType = String(entry.body_type ?? 'unknown');
    const body = typeof entry.unsafe_body === 'string' ? entry.unsafe_body : '';
    return `${bodyType}: ${body.slice(0, 240)}`;
  }).join('\n');
}

async function printDiagnostics(harness: LongHarness, convId: string): Promise<void> {
  try {
    await harness.alice.run(['recv', convId]);
  } catch {
    // Best-effort only.
  }

  console.error('\n=== Alice History ===');
  console.error(summarizeHistory(harness.alice.readHistory(convId)));

  for (const process of harness.processes) {
    console.error(`\n=== Process: ${process.name} stderr ===`);
    console.error(process.stderr.slice(-8000));
    console.error(`\n=== Process: ${process.name} stdout ===`);
    console.error(process.stdout.slice(-8000));
  }
}

function traceGateResultDelivery(
  label: string,
  cliBody: Record<string, unknown>,
  uiBody: Record<string, unknown>,
  detailLines: string[] = [],
): void {
  if (process.env.QNTM_LONG_TRACE_RESULTS !== '1') {
    return;
  }
  console.error(`\n=== ${label} gate.result delivery ===`);
  for (const detailLine of detailLines) {
    console.error(detailLine);
  }
  console.error(`CLI: ${JSON.stringify(cliBody)}`);
  console.error(`AIM: ${JSON.stringify(uiBody)}`);
}

function assertLiveHnTopStoriesPayload(resultBody: Record<string, unknown>): number[] {
  expect(resultBody.status_code).toBe(200);
  expect(resultBody.content_type).toContain('application/json');
  expect(typeof resultBody.body).toBe('string');

  const parsed = JSON.parse(String(resultBody.body)) as unknown;
  expect(Array.isArray(parsed)).toBe(true);
  const storyIds = parsed as unknown[];
  expect(storyIds.length).toBeGreaterThan(10);
  for (const storyId of storyIds.slice(0, 10)) {
    expect(typeof storyId).toBe('number');
    expect(Number.isInteger(storyId)).toBe(true);
    expect(Number(storyId)).toBeGreaterThan(0);
  }
  return storyIds as number[];
}

function assertLiveHnItemPayload(resultBody: Record<string, unknown>, expectedId: number): string {
  expect(resultBody.status_code).toBe(200);
  expect(resultBody.content_type).toContain('application/json');
  expect(typeof resultBody.body).toBe('string');

  const parsed = JSON.parse(String(resultBody.body)) as Record<string, unknown>;
  expect(parsed.id).toBe(expectedId);
  expect(typeof parsed.title).toBe('string');
  const title = String(parsed.title).trim();
  expect(title.length).toBeGreaterThan(0);
  return title;
}

describe.sequential('real long-running gateway integration flow', () => {
  let harness: LongHarness;
  let convId = '';
  let inviteToken = '';
  let gatewayPublicKey = '';
  let gatewayKid = '';
  let charlieKeyId = '';
  let charliePublicKey = '';
  let phase1TopStoriesRequestId = '';
  let phase1TopStoryItemRequestId = '';
  let staleRequestId = '';
  let strictRequestId = '';
  let leetRequestId = '';

  beforeAll(async () => {
    harness = await createLongHarness();

    await harness.alice.run(['identity', 'generate']);
    await harness.charlie.run(['identity', 'generate']);
    await harness.ui.generateIdentity();

    const group = await harness.alice.run(['group', 'create', UI_LABEL]);
    convId = String(group.data?.conversation_id);
    inviteToken = String(group.data?.invite_token);

    const charlieIdentity = harness.charlie.readIdentity();
    charlieKeyId = charlieIdentity.key_id;
    charliePublicKey = charlieIdentity.public_key;

    await harness.ui.joinConversation(inviteToken, UI_LABEL);
    await harness.ui.sendText('hello from bob');
    await waitForCliHistory(
      harness.alice,
      convId,
      historyContainsText('hello from bob'),
      'initial UI hello',
    );
  }, LONG_TIMEOUT);

  afterAll(async () => {
    await harness.stop();
  }, LONG_TIMEOUT);

  it('phase 1: bootstraps the gateway and stores a successful API result in chat', async () => {
    try {
      const bootstrap = await harness.bootstrapGateway(convId, harness.alice);
      gatewayPublicKey = bootstrap.gateway_public_key;
      gatewayKid = bootstrap.gateway_kid;

      await harness.alice.run(['gate-promote', '-c', convId, '--threshold', '2', `--gateway-kid=${gatewayKid}`]);
      await harness.alice.run([
        'gate-secret', '-c', convId,
        '--service', 'hackernews',
        `--gateway-pubkey=${gatewayPublicKey}`,
        '--value', 'dummy-hackernews-token',
        '--header-name', 'X-Test',
        '--header-template', '{value}',
      ]);
      await harness.alice.run([
        'gate-secret', '-c', convId,
        '--service', 'fun',
        `--gateway-pubkey=${gatewayPublicKey}`,
        '--value', 'dummy-fun-token',
        '--header-name', 'X-Test',
        '--header-template', '{value}',
      ]);

      const request = await harness.alice.run(['gate-run', 'hn.top-stories', '-c', convId]);
      phase1TopStoriesRequestId = String(request.data?.request_id);

      await waitForUiText(harness.ui, 'hn.top-stories');
      await harness.ui.approveLatestRequest();
      await harness.pumpGateway(convId);

      const resultEntry = await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', phase1TopStoriesRequestId),
        'phase 1 gate.result',
        30_000,
      );
      const resultBody = parseUnsafeBody(resultEntry);
      const storyIds = assertLiveHnTopStoriesPayload(resultBody);
      const uiResultEntry = await waitForUiStoredHistory(
        harness.ui,
        convId,
        uiHistoryMatchesRequest('gate.result', phase1TopStoriesRequestId),
        'phase 1 UI gate.result',
        30_000,
      );
      const uiText = uiResultEntry.text;
      expect(typeof uiText).toBe('string');
      const uiResultBody = JSON.parse(String(uiText)) as Record<string, unknown>;
      expect(uiResultBody).toEqual(resultBody);
      const topStoryId = storyIds[0];
      await waitForUiText(harness.ui, String(topStoryId));
      traceGateResultDelivery('hn.top-stories', resultBody, uiResultBody, [
        `Top story ID selected for follow-up: ${topStoryId}`,
      ]);

      const itemRequest = await harness.alice.run([
        'gate-run',
        'hn.get-item',
        '-c',
        convId,
        '--arg',
        `id=${topStoryId}`,
      ]);
      phase1TopStoryItemRequestId = String(itemRequest.data?.request_id);

      await waitForUiText(harness.ui, 'hn.get-item');
      await harness.ui.approveLatestRequest();
      await harness.pumpGateway(convId);

      const itemResultEntry = await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', phase1TopStoryItemRequestId),
        'phase 1 hn.get-item gate.result',
        30_000,
      );
      const itemResultBody = parseUnsafeBody(itemResultEntry);
      const topStoryTitle = assertLiveHnItemPayload(itemResultBody, topStoryId);
      const uiItemResultEntry = await waitForUiStoredHistory(
        harness.ui,
        convId,
        uiHistoryMatchesRequest('gate.result', phase1TopStoryItemRequestId),
        'phase 1 UI hn.get-item gate.result',
        30_000,
      );
      const uiItemText = uiItemResultEntry.text;
      expect(typeof uiItemText).toBe('string');
      const uiItemResultBody = JSON.parse(String(uiItemText)) as Record<string, unknown>;
      expect(uiItemResultBody).toEqual(itemResultBody);
      await waitForUiText(harness.ui, topStoryTitle);
      traceGateResultDelivery('hn.get-item', itemResultBody, uiItemResultBody, [
        `Top story title: ${topStoryTitle}`,
      ]);
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 2: raises the threshold, adds Charlie, invalidates the stale request, and executes a strict request', async () => {
    try {
      await harness.charlie.run(['group', 'join', '--name', UI_LABEL, '--', inviteToken]);

      const stale = await harness.alice.run(['gate-run', 'hn.top-stories', '-c', convId]);
      staleRequestId = String(stale.data?.request_id);

      const floorProposal = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '3', '--required-approvals', '2',
      ]);
      const floorProposalId = String(floorProposal.data?.proposal_id);
      await waitForUiText(harness.ui, 'proposed floor to 3');
      await harness.ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        (entry) => entry.body_type === 'gov.applied' && parseUnsafeBody(entry).proposal_id === floorProposalId,
        'floor change application',
      );

      const addProposal = await harness.alice.run([
        'gov', 'propose-add', '-c', convId, '--required-approvals', '2', '--', charliePublicKey,
      ]);
      const addProposalId = String(addProposal.data?.proposal_id);
      await waitForUiText(harness.ui, 'adding 1 member');
      await harness.ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        (entry) => entry.body_type === 'gov.applied' && parseUnsafeBody(entry).proposal_id === addProposalId,
        'member add application',
      );
      await waitForCliHistory(
        harness.charlie,
        convId,
        (entry) => entry.body_type === 'group_rekey',
        'charlie rekey',
        30_000,
      );

      await harness.alice.run(['send', convId, 'welcome charlie']);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyContainsText('welcome charlie'),
        'post-add text for charlie',
        20_000,
      );

      await harness.ui.approveLatestRequest();
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', staleRequestId),
        6_000,
      );

      const strict = await harness.alice.run(['gate-run', 'hn.top-stories.strict', '-c', convId]);
      strictRequestId = String(strict.data?.request_id);
      await waitForUiText(harness.ui, 'hn.top-stories.strict');
      await harness.ui.approveLatestRequest();
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesRequest('gate.request', strictRequestId),
        'charlie strict gate.request',
        30_000,
      );
      await harness.charlie.run(['gate-approve', strictRequestId, '-c', convId]);
      await harness.pumpGateway(convId);
      const strictResult = await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', strictRequestId),
        'strict gate.result',
        30_000,
      );
      assertLiveHnTopStoriesPayload(parseUnsafeBody(strictResult));
      await waitForUiText(harness.ui, '1 member added');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 3: removes Charlie, rotates keys, and excludes him from future chat traffic', async () => {
    try {
      const removeProposal = await harness.alice.run([
        'gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', charlieKeyId,
      ]);
      const removeProposalId = String(removeProposal.data?.proposal_id);
      await waitForUiText(harness.ui, 'removing 1 member');
      await harness.ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        (entry) => entry.body_type === 'gov.applied' && parseUnsafeBody(entry).proposal_id === removeProposalId,
        'member removal application',
        30_000,
      );

      await harness.alice.run(['send', convId, 'after charlie removal']);
      await assertNoCliHistory(
        harness.charlie,
        convId,
        historyContainsText('after charlie removal'),
        6_000,
      );
      await waitForUiText(harness.ui, '1 member removed');
      await waitForUiText(harness.ui, 'Security keys rotated');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 4: lowers the threshold back to 2 and blocks leet.translate with a UI disapproval', async () => {
    try {
      const floorProposal = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '2', '--required-approvals', '2',
      ]);
      const floorProposalId = String(floorProposal.data?.proposal_id);
      await waitForUiText(harness.ui, 'proposed floor to 2');
      await harness.ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        (entry) => entry.body_type === 'gov.applied' && parseUnsafeBody(entry).proposal_id === floorProposalId,
        'return to floor 2',
        30_000,
      );

      const leet = await harness.alice.run(['gate-run', 'leet.translate', '-c', convId, '--arg', 'text=hello agent']);
      leetRequestId = String(leet.data?.request_id);
      await waitForUiText(harness.ui, 'leet.translate');
      await harness.ui.rejectLatestRequest();
      await harness.pumpGateway(convId);

      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.disapproval', leetRequestId),
        'leet disapproval',
        20_000,
      );
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', leetRequestId),
        6_000,
      );
      await waitForUiText(harness.ui, 'Request Denied');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
