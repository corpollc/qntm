import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { LongHarness } from './src/runtime.js';
import { assertNoCliHistory, createLongHarness } from './src/runtime.js';
import {
  LONG_TIMEOUT,
  countHistoryMatches,
  historyContainsText,
  historyIndex,
  historyMatchesProposal,
  historyMatchesProposalSigner,
  historyMatchesRequest,
  historyMatchesRequestSigner,
  printDiagnostics,
  setupCliGovernedConversation,
  waitForCliHistory,
} from './long-helpers.js';

describe.sequential('real long-running gateway integration CLI membership flow', () => {
  let harness: LongHarness;
  let convId = '';
  let daveKeyId = '';
  let daveKeyIdWire = '';
  let davePublicKey = '';
  let restartRequestId = '';
  let floorThreeProposalId = '';
  let addDaveProposalId = '';
  let removeDaveProposalId = '';

  beforeAll(async () => {
    harness = await createLongHarness({ withUi: false });
    const setup = await setupCliGovernedConversation(harness, 'Long CLI Membership', { joinDaveOffline: true });
    convId = setup.convId;
    daveKeyId = setup.daveKeyId;
    daveKeyIdWire = setup.daveKeyIdWire;
    davePublicKey = setup.davePublicKey;

    const baselineRequest = await harness.alice.run(['gate-run', 'counter.bump', '-c', convId]);
    restartRequestId = String(baselineRequest.data?.request_id);
    await waitForCliHistory(
      harness.charlie,
      convId,
      historyMatchesRequest('gate.request', restartRequestId),
      'baseline counter request',
      30_000,
    );
  }, LONG_TIMEOUT);

  afterAll(async () => {
    await harness.stop();
  }, LONG_TIMEOUT);

  it('phase 8: lets an offline prejoined member catch up through add and removal rekeys', async () => {
    try {
      const floorProposal = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '3', '--required-approvals', '2',
      ]);
      floorThreeProposalId = String(floorProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', floorThreeProposalId),
        'charlie floor-3 proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', floorThreeProposalId, '-c', convId]);
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', floorThreeProposalId),
        'floor-3 application',
        30_000,
      );

      const addProposal = await harness.alice.run([
        'gov', 'propose-add', '-c', convId, '--required-approvals', '2', '--', davePublicKey,
      ]);
      addDaveProposalId = String(addProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', addDaveProposalId),
        'charlie add-dave proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', addDaveProposalId, '-c', convId]);
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', addDaveProposalId),
        'dave add application',
        30_000,
      );

      await harness.alice.run(['send', convId, 'after dave add']);

      const removeProposal = await harness.alice.run([
        'gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', daveKeyId,
      ]);
      removeDaveProposalId = String(removeProposal.data?.proposal_id);
      await waitForCliHistory(
        harness.charlie,
        convId,
        historyMatchesProposal('gov.propose', removeDaveProposalId),
        'charlie remove-dave proposal',
        30_000,
      );
      await harness.charlie.run(['gov', 'approve', removeDaveProposalId, '-c', convId]);
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', removeDaveProposalId),
        'dave removal application',
        30_000,
      );

      await harness.alice.run(['send', convId, 'after dave remove']);

      await waitForCliHistory(
        harness.dave,
        convId,
        historyContainsText('after dave add'),
        'dave catch-up through add rekey',
        30_000,
      );
      await waitForCliHistory(
        harness.dave,
        convId,
        (entry) => entry.body_type === 'group_remove',
        'dave remove marker during catch-up',
        30_000,
      );

      const daveHistory = harness.dave.readHistory(convId);
      const floorAppliedIndex = historyIndex(daveHistory, historyMatchesProposal('gov.applied', floorThreeProposalId));
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
      expect(daveHistory.some(historyMatchesProposal('gov.applied', removeDaveProposalId))).toBe(false);

      const daveConversation = harness.dave.readConversation(convId);
      expect(daveConversation.current_epoch).toBe(1);
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 9: dropped member stale traffic never affects the live conversation', async () => {
    try {
      const removedText = 'removed dave says hello';
      await harness.dave.run(['send', convId, removedText]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyContainsText(removedText),
        6_000,
      );

      harness.resetCounterExecutions();
      const staleRequest = await harness.dave.run(['gate-run', 'counter.bump', '-c', convId]);
      const staleRequestId = String(staleRequest.data?.request_id);
      await harness.pumpGateway(convId);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.request', staleRequestId),
        6_000,
      );
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.result', staleRequestId),
        6_000,
      );
      expect(harness.getCounterExecutions()).toBe(0);

      await harness.dave.run(['gate-approve', restartRequestId, '-c', convId]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequestSigner('gate.approval', restartRequestId, daveKeyIdWire),
        6_000,
      );

      await harness.dave.run(['gov', 'approve', floorThreeProposalId, '-c', convId]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesProposalSigner('gov.approve', floorThreeProposalId, daveKeyIdWire),
        6_000,
      );
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
