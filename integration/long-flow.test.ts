import { setTimeout as delay } from 'node:timers/promises';
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

function historyMatchesRequestSigner(bodyType: string, requestId: string, signerKid: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      const body = parseUnsafeBody(entry);
      return body.request_id === requestId && body.signer_kid === signerKid;
    } catch {
      return false;
    }
  };
}

function historyMatchesProposal(bodyType: string, proposalId: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).proposal_id === proposalId;
    } catch {
      return false;
    }
  };
}

function historyMatchesProposalSigner(bodyType: string, proposalId: string, signerKid: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      const body = parseUnsafeBody(entry);
      return body.proposal_id === proposalId && body.signer_kid === signerKid;
    } catch {
      return false;
    }
  };
}

function historyMatchesService(bodyType: string, service: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).service === service;
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

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function countHistoryMatches(
  entries: Array<Record<string, unknown>>,
  predicate: (entry: Record<string, unknown>) => boolean,
): number {
  return entries.filter(predicate).length;
}

function historyIndex(
  entries: Array<Record<string, unknown>>,
  predicate: (entry: Record<string, unknown>) => boolean,
): number {
  return entries.findIndex(predicate);
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

function assertCounterResultPayload(resultBody: Record<string, unknown>, expectedCount: number): void {
  expect(resultBody.status_code).toBe(200);
  expect(resultBody.content_type).toContain('application/json');
  expect(typeof resultBody.body).toBe('string');

  const parsed = JSON.parse(String(resultBody.body)) as Record<string, unknown>;
  expect(parsed.count).toBe(expectedCount);
}

describe.sequential('real long-running gateway integration flow', () => {
  let harness: LongHarness;
  let convId = '';
  let inviteToken = '';
  let gatewayPublicKey = '';
  let gatewayKid = '';
  let charlieKeyId = '';
  let charliePublicKey = '';
  let daveKeyId = '';
  let daveKeyIdWire = '';
  let davePublicKey = '';
  let phase2FloorProposalId = '';
  let phase1TopStoriesRequestId = '';
  let phase1TopStoryItemRequestId = '';
  let staleRequestId = '';
  let strictRequestId = '';
  let leetRequestId = '';
  let cliConvId = '';
  let cliInviteToken = '';
  let cliGatewayPublicKey = '';
  let cliGatewayKid = '';
  let cliKeepFloorProposalId = '';
  let cliInvalidatedFloorProposalId = '';
  let cliRestartRequestId = '';
  let cliExpiredRequestId = '';
  let cliFloorThreeProposalId = '';
  let cliAddDaveProposalId = '';
  let cliRemoveDaveProposalId = '';

  beforeAll(async () => {
    harness = await createLongHarness();

    await harness.alice.run(['identity', 'generate']);
    await harness.charlie.run(['identity', 'generate']);
    await harness.dave.run(['identity', 'generate']);
    await harness.ui.generateIdentity();

    const group = await harness.alice.run(['group', 'create', UI_LABEL]);
    convId = String(group.data?.conversation_id);
    inviteToken = String(group.data?.invite_token);

    const charlieIdentity = harness.charlie.readIdentity();
    charlieKeyId = charlieIdentity.key_id;
    charliePublicKey = charlieIdentity.public_key;

    const daveIdentity = harness.dave.readIdentity();
    daveKeyId = daveIdentity.key_id;
    daveKeyIdWire = hexToBase64Url(daveKeyId);
    davePublicKey = daveIdentity.public_key;

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
      phase2FloorProposalId = String(floorProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', phase2FloorProposalId),
        'charlie floor proposal',
        30_000,
      );
      await waitForUiText(harness.ui, 'proposed floor to 3');
      await harness.ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', phase2FloorProposalId),
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
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.invalidated', staleRequestId),
        'stale request invalidated',
        30_000,
      );
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', staleRequestId),
        6_000,
      );
      await waitForUiText(harness.ui, 'Pending request invalidated');

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

  it('phase 5: boots a CLI-first conversation and invalidates a conflicting proposal in transcript', async () => {
    try {
      const cliGroup = await harness.alice.run(['group', 'create', 'Long CLI']);
      cliConvId = String(cliGroup.data?.conversation_id);
      cliInviteToken = String(cliGroup.data?.invite_token);

      await harness.charlie.run(['group', 'join', '--name', 'Long CLI', '--', cliInviteToken]);
      await harness.charlie.run(['send', cliConvId, 'hello from charlie cli']);
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyContainsText('hello from charlie cli'),
        'charlie cli hello',
        30_000,
      );

      await harness.dave.run(['group', 'join', '--name', 'Long CLI', '--', cliInviteToken]);

      const cliBootstrap = await harness.bootstrapGateway(cliConvId, harness.alice);
      cliGatewayPublicKey = cliBootstrap.gateway_public_key;
      cliGatewayKid = cliBootstrap.gateway_kid;

      await harness.alice.run([
        'gate-promote',
        '-c',
        cliConvId,
        '--threshold',
        '2',
        `--gateway-kid=${cliGatewayKid}`,
      ]);
      await harness.alice.run([
        'gate-secret',
        '-c',
        cliConvId,
        '--service',
        'fun',
        `--gateway-pubkey=${cliGatewayPublicKey}`,
        '--value',
        'dummy-fun-token',
        '--header-name',
        'X-Test',
        '--header-template',
        '{value}',
      ]);
      await harness.pumpGateway(cliConvId);

      const keepFloor = await harness.alice.run([
        'gov', 'propose-floor', '-c', cliConvId, '--floor', '2', '--required-approvals', '2',
      ]);
      cliKeepFloorProposalId = String(keepFloor.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.propose', cliKeepFloorProposalId),
        'charlie keep-floor proposal',
        30_000,
      );

      const staleFloor = await harness.alice.run([
        'gov', 'propose-floor', '-c', cliConvId, '--floor', '3', '--required-approvals', '2',
      ]);
      cliInvalidatedFloorProposalId = String(staleFloor.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.propose', cliInvalidatedFloorProposalId),
        'charlie stale floor proposal',
        30_000,
      );

      await harness.charlie.run(['gov', 'approve', cliKeepFloorProposalId, '-c', cliConvId]);
      await harness.pumpGateway(cliConvId);

      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.applied', cliKeepFloorProposalId),
        'cli keep-floor application',
        30_000,
      );
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.invalidated', cliInvalidatedFloorProposalId),
        'cli conflicting proposal invalidation',
        30_000,
      );
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.invalidated', cliInvalidatedFloorProposalId),
        'charlie conflicting proposal invalidation',
        30_000,
      );
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.applied', cliInvalidatedFloorProposalId),
        6_000,
      );
    } catch (error) {
      await printDiagnostics(harness, cliConvId || convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 6: restarts the gateway around an approved request and executes it once', async () => {
    try {
      harness.resetCounterExecutions();

      const request = await harness.alice.run(['gate-run', 'counter.bump', '-c', cliConvId]);
      cliRestartRequestId = String(request.data?.request_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesRequest('gate.request', cliRestartRequestId),
        'charlie counter.bump request',
        30_000,
      );
      await harness.charlie.run(['gate-approve', cliRestartRequestId, '-c', cliConvId]);
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.approval', cliRestartRequestId),
        'counter approval before restart',
        30_000,
      );

      await harness.restartGateway();
      await harness.pumpGateway(cliConvId);

      const resultEntry = await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.result', cliRestartRequestId),
        'counter result after gateway restart',
        30_000,
      );
      assertCounterResultPayload(parseUnsafeBody(resultEntry), 1);
      expect(harness.getCounterExecutions()).toBe(1);

      const aliceHistory = harness.alice.readHistory(cliConvId);
      expect(countHistoryMatches(aliceHistory, historyMatchesRequest('gate.executed', cliRestartRequestId))).toBe(1);
      expect(countHistoryMatches(aliceHistory, historyMatchesRequest('gate.result', cliRestartRequestId))).toBe(1);
    } catch (error) {
      await printDiagnostics(harness, cliConvId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 7: blocks execution after secret expiry and resumes it after reprovision', async () => {
    try {
      harness.resetCounterExecutions();

      await harness.alice.run([
        'gate-secret',
        '-c',
        cliConvId,
        '--service',
        'fun',
        `--gateway-pubkey=${cliGatewayPublicKey}`,
        '--value',
        'short-lived-fun-token',
        '--header-name',
        'X-Test',
        '--header-template',
        '{value}',
        '--ttl',
        '1',
      ]);
      await harness.pumpGateway(cliConvId);
      await delay(2_000);
      await harness.pumpGateway(cliConvId);

      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesService('gate.expired', 'fun'),
        'fun secret expiry marker',
        30_000,
      );

      const blocked = await harness.alice.run(['gate-run', 'counter.bump', '-c', cliConvId]);
      cliExpiredRequestId = String(blocked.data?.request_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesRequest('gate.request', cliExpiredRequestId),
        'charlie blocked counter request',
        30_000,
      );
      await harness.charlie.run(['gate-approve', cliExpiredRequestId, '-c', cliConvId]);
      await harness.pumpGateway(cliConvId);

      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.result', cliExpiredRequestId),
        6_000,
      );
      expect(harness.getCounterExecutions()).toBe(0);

      await harness.alice.run([
        'gate-secret',
        '-c',
        cliConvId,
        '--service',
        'fun',
        `--gateway-pubkey=${cliGatewayPublicKey}`,
        '--value',
        'restored-fun-token',
        '--header-name',
        'X-Test',
        '--header-template',
        '{value}',
      ]);
      await harness.pumpGateway(cliConvId);

      const recovered = await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.result', cliExpiredRequestId),
        'counter result after secret reprovision',
        30_000,
      );
      assertCounterResultPayload(parseUnsafeBody(recovered), 1);
      expect(harness.getCounterExecutions()).toBe(1);
    } catch (error) {
      await printDiagnostics(harness, cliConvId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 8: lets an offline prejoined member catch up through add and removal rekeys', async () => {
    try {
      const floorProposal = await harness.alice.run([
        'gov', 'propose-floor', '-c', cliConvId, '--floor', '3', '--required-approvals', '2',
      ]);
      cliFloorThreeProposalId = String(floorProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.propose', cliFloorThreeProposalId),
        'charlie floor-3 proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', cliFloorThreeProposalId, '-c', cliConvId]);
      await harness.pumpGateway(cliConvId);
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.applied', cliFloorThreeProposalId),
        'floor-3 application',
        30_000,
      );

      const addProposal = await harness.alice.run([
        'gov', 'propose-add', '-c', cliConvId, '--required-approvals', '2', '--', davePublicKey,
      ]);
      cliAddDaveProposalId = String(addProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.propose', cliAddDaveProposalId),
        'charlie add-dave proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', cliAddDaveProposalId, '-c', cliConvId]);
      await harness.pumpGateway(cliConvId);
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.applied', cliAddDaveProposalId),
        'dave add application',
        30_000,
      );

      await harness.alice.run(['send', cliConvId, 'after dave add']);

      const removeProposal = await harness.alice.run([
        'gov', 'propose-remove', '-c', cliConvId, '--required-approvals', '2', '--', daveKeyId,
      ]);
      cliRemoveDaveProposalId = String(removeProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        cliConvId,
        historyMatchesProposal('gov.propose', cliRemoveDaveProposalId),
        'charlie remove-dave proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', cliRemoveDaveProposalId, '-c', cliConvId]);
      await harness.pumpGateway(cliConvId);
      await waitForCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposal('gov.applied', cliRemoveDaveProposalId),
        'dave removal application',
        30_000,
      );

      await harness.alice.run(['send', cliConvId, 'after dave remove']);

      await waitForCliHistory(
        harness.dave,
        cliConvId,
        historyContainsText('after dave add'),
        'dave catch-up through add rekey',
        30_000,
      );
      await waitForCliHistory(
        harness.dave,
        cliConvId,
        (entry) => entry.body_type === 'group_remove',
        'dave remove marker during catch-up',
        30_000,
      );

      const daveHistory = harness.dave.readHistory(cliConvId);
      const floorAppliedIndex = historyIndex(daveHistory, historyMatchesProposal('gov.applied', cliFloorThreeProposalId));
      const addIndex = historyIndex(daveHistory, (entry) => entry.body_type === 'group_add');
      const addTextIndex = historyIndex(daveHistory, historyContainsText('after dave add'));
      const removeIndex = historyIndex(daveHistory, (entry) => entry.body_type === 'group_remove');
      const rekeyCount = countHistoryMatches(daveHistory, (entry) => entry.body_type === 'group_rekey');

      expect(floorAppliedIndex).toBeGreaterThan(-1);
      expect(addIndex).toBeGreaterThan(floorAppliedIndex);
      expect(addTextIndex).toBeGreaterThan(addIndex);
      expect(removeIndex).toBeGreaterThan(addTextIndex);
      expect(rekeyCount).toBeGreaterThanOrEqual(2);
      expect(daveHistory.some(historyContainsText('after dave remove'))).toBe(false);
      expect(daveHistory.some(historyMatchesProposal('gov.applied', cliRemoveDaveProposalId))).toBe(false);

      const daveConversation = harness.dave.readConversation(cliConvId);
      expect(daveConversation.current_epoch).toBe(1);
    } catch (error) {
      await printDiagnostics(harness, cliConvId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 9: dropped member stale traffic never affects the live conversation', async () => {
    try {
      const removedText = 'removed dave says hello';
      await harness.dave.run(['send', cliConvId, removedText]);
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyContainsText(removedText),
        6_000,
      );

      harness.resetCounterExecutions();
      const staleRequest = await harness.dave.run(['gate-run', 'counter.bump', '-c', cliConvId]);
      const staleRequestId = String(staleRequest.data?.request_id);
      await harness.pumpGateway(cliConvId);
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.request', staleRequestId),
        6_000,
      );
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequest('gate.result', staleRequestId),
        6_000,
      );
      expect(harness.getCounterExecutions()).toBe(0);

      await harness.dave.run(['gate-approve', cliRestartRequestId, '-c', cliConvId]);
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesRequestSigner('gate.approval', cliRestartRequestId, daveKeyIdWire),
        6_000,
      );

      await harness.dave.run(['gov', 'approve', cliFloorThreeProposalId, '-c', cliConvId]);
      await assertNoCliHistory(
        harness.alice,
        cliConvId,
        historyMatchesProposalSigner('gov.approve', cliFloorThreeProposalId, daveKeyIdWire),
        6_000,
      );
    } catch (error) {
      await printDiagnostics(harness, cliConvId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
