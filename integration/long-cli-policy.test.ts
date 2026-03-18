import { setTimeout as delay } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { LongHarness } from './src/runtime.js';
import { assertNoCliHistory, createLongHarness } from './src/runtime.js';
import {
  LONG_TIMEOUT,
  assertCounterResultPayload,
  countHistoryMatches,
  historyMatchesProposal,
  historyMatchesRequest,
  historyMatchesService,
  parseUnsafeBody,
  printDiagnostics,
  requireUi,
  setupCliGovernedConversation,
  waitForCliHistory,
  waitForUiText,
} from './long-helpers.js';

describe.sequential('real long-running gateway integration CLI policy flow', () => {
  let harness: LongHarness;
  let convId = '';
  let gatewayPublicKey = '';
  let keepFloorProposalId = '';
  let invalidatedFloorProposalId = '';
  let restartRequestId = '';
  let expiredRequestId = '';

  beforeAll(async () => {
    harness = await createLongHarness({ withUi: true });
    const setup = await setupCliGovernedConversation(harness, 'Long CLI Policy');
    convId = setup.convId;
    gatewayPublicKey = setup.gatewayPublicKey;
  }, LONG_TIMEOUT);

  afterAll(async () => {
    await harness.stop();
  }, LONG_TIMEOUT);

  it('phase 5: invalidates a conflicting proposal in transcript', async () => {
    const ui = requireUi(harness);

    try {
      const keepFloor = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '2', '--required-approvals', '2',
      ]);
      keepFloorProposalId = String(keepFloor.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', keepFloorProposalId),
        'charlie keep-floor proposal',
        30_000,
      );

      const staleFloor = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '3', '--required-approvals', '2',
      ]);
      invalidatedFloorProposalId = String(staleFloor.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', invalidatedFloorProposalId),
        'charlie stale floor proposal',
        30_000,
      );

      await harness.charlie.run(['gov', 'approve', keepFloorProposalId, '-c', convId]);
      await harness.pumpGateway(convId);

      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', keepFloorProposalId),
        'cli keep-floor application',
        30_000,
      );
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.invalidated', invalidatedFloorProposalId),
        'cli conflicting proposal invalidation',
        30_000,
      );
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.invalidated', invalidatedFloorProposalId),
        'charlie conflicting proposal invalidation',
        30_000,
      );
      await waitForUiText(ui, 'Governance proposal invalidated');
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', invalidatedFloorProposalId),
        6_000,
      );
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 6: restarts the gateway around an approved request and executes it once', async () => {
    const ui = requireUi(harness);

    try {
      harness.resetCounterExecutions();

      const request = await harness.alice.run(['gate-run', 'counter.bump', '-c', convId]);
      restartRequestId = String(request.data?.request_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesRequest('gate.request', restartRequestId),
        'charlie counter.bump request',
        30_000,
      );
      await harness.charlie.run(['gate-approve', restartRequestId, '-c', convId]);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.approval', restartRequestId),
        'counter approval before restart',
        30_000,
      );

      await harness.restartGateway();
      await harness.pumpGateway(convId);

      const resultEntry = await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', restartRequestId),
        'counter result after gateway restart',
        30_000,
      );
      assertCounterResultPayload(parseUnsafeBody(resultEntry), 1);
      expect(harness.getCounterExecutions()).toBe(1);
      await waitForUiText(ui, '"count": 1');

      const aliceHistory = harness.alice.readHistory(convId);
      expect(countHistoryMatches(aliceHistory, historyMatchesRequest('gate.executed', restartRequestId))).toBe(1);
      expect(countHistoryMatches(aliceHistory, historyMatchesRequest('gate.result', restartRequestId))).toBe(1);
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 7: blocks execution after secret expiry and resumes it after reprovision', async () => {
    const ui = requireUi(harness);

    try {
      harness.resetCounterExecutions();

      await harness.alice.run([
        'gate-secret',
        '-c',
        convId,
        '--service',
        'fun',
        `--gateway-pubkey=${gatewayPublicKey}`,
        '--value',
        'short-lived-fun-token',
        '--header-name',
        'X-Test',
        '--header-template',
        '{value}',
        '--ttl',
        '1',
      ]);
      await harness.pumpGateway(convId);
      await delay(2_000);
      await harness.pumpGateway(convId);

      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesService('gate.expired', 'fun'),
        'fun secret expiry marker',
        30_000,
      );
      await waitForUiText(ui, 'Credential Expired');

      const blocked = await harness.alice.run(['gate-run', 'counter.bump', '-c', convId]);
      expiredRequestId = String(blocked.data?.request_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesRequest('gate.request', expiredRequestId),
        'charlie blocked counter request',
        30_000,
      );
      await harness.charlie.run(['gate-approve', expiredRequestId, '-c', convId]);
      await harness.pumpGateway(convId);

      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', expiredRequestId),
        6_000,
      );
      expect(harness.getCounterExecutions()).toBe(0);

      await harness.alice.run([
        'gate-secret',
        '-c',
        convId,
        '--service',
        'fun',
        `--gateway-pubkey=${gatewayPublicKey}`,
        '--value',
        'restored-fun-token',
        '--header-name',
        'X-Test',
        '--header-template',
        '{value}',
      ]);
      await harness.pumpGateway(convId);

      const recovered = await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', expiredRequestId),
        'counter result after secret reprovision',
        30_000,
      );
      assertCounterResultPayload(parseUnsafeBody(recovered), 1);
      expect(harness.getCounterExecutions()).toBe(1);
      await waitForUiText(ui, '"count": 1');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
