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
  requireUi,
  setupTwoPartyGovernedConversation,
  waitForCliHistory,
  waitForUiText,
} from './long-helpers.js';

describe.sequential('real long-running gateway integration CLI membership flow', () => {
  let harness: LongHarness;
  let convId = '';
  let inviteToken = '';
  let charlieKeyId = '';
  let charlieKeyIdWire = '';
  let charliePublicKey = '';
  let addCharlieProposalId = '';
  let removeCharlieProposalId = '';
  let pendingRequestId = '';

  beforeAll(async () => {
    harness = await createLongHarness({ withUi: true });
    const setup = await setupTwoPartyGovernedConversation(harness, 'Long CLI Membership');
    convId = setup.convId;
    inviteToken = setup.inviteToken;
    charlieKeyId = setup.charlieKeyId;
    charlieKeyIdWire = setup.charlieKeyIdWire;
    charliePublicKey = setup.charliePublicKey;
  }, LONG_TIMEOUT);

  afterAll(async () => {
    await harness.stop();
  }, LONG_TIMEOUT);

  it('phase 8: lets an offline third participant catch up through add and removal rekeys', async () => {
    const ui = requireUi(harness);

    try {
      await harness.charlie.run(['group', 'join', '--name', 'Long CLI Membership', '--', inviteToken]);

      const addProposal = await harness.alice.run([
        'gov', 'propose-add', '-c', convId, '--required-approvals', '2', '--', charliePublicKey,
      ]);
      addCharlieProposalId = String(addProposal.data?.proposal_id);
      await waitForUiText(ui, 'adding 1 member');
      await ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', addCharlieProposalId),
        'charlie add application',
        30_000,
      );

      await harness.alice.run(['send', convId, 'after charlie add']);

      const pendingRequest = await harness.alice.run(['gate-run', 'counter.bump', '-c', convId]);
      pendingRequestId = String(pendingRequest.data?.request_id);

      const removeProposal = await harness.alice.run([
        'gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', charlieKeyId,
      ]);
      removeCharlieProposalId = String(removeProposal.data?.proposal_id);
      await waitForUiText(ui, 'removing 1 member');
      await ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', removeCharlieProposalId),
        'charlie removal application',
        30_000,
      );
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesRequest('gate.invalidated', pendingRequestId),
        'pending request invalidated on charlie removal',
        30_000,
      );

      await harness.alice.run(['send', convId, 'after charlie remove']);

      await waitForCliHistory(
        harness.charlie,
        convId,
        historyContainsText('after charlie add'),
        'charlie catch-up through add rekey',
        30_000,
      );
      await waitForCliHistory(
        harness.charlie,
        convId,
        (entry) => entry.body_type === 'group_remove',
        'charlie remove marker during catch-up',
        30_000,
      );

      const charlieHistory = harness.charlie.readHistory(convId);
      const addIndex = historyIndex(charlieHistory, (entry) => entry.body_type === 'group_add');
      const addTextIndex = historyIndex(charlieHistory, historyContainsText('after charlie add'));
      const removeIndex = historyIndex(charlieHistory, (entry) => entry.body_type === 'group_remove');
      const rekeyCount = countHistoryMatches(charlieHistory, (entry) => entry.body_type === 'group_rekey');

      expect(addIndex).toBeGreaterThan(-1);
      expect(addTextIndex).toBeGreaterThan(addIndex);
      expect(removeIndex).toBeGreaterThan(addTextIndex);
      expect(rekeyCount).toBeGreaterThanOrEqual(2);
      expect(charlieHistory.some(historyMatchesRequest('gate.invalidated', pendingRequestId))).toBe(false);
      expect(charlieHistory.some(historyContainsText('after charlie remove'))).toBe(false);
      expect(charlieHistory.some(historyMatchesProposal('gov.applied', removeCharlieProposalId))).toBe(false);

      const charlieConversation = harness.charlie.readConversation(convId);
      expect(charlieConversation.current_epoch).toBe(1);
      await waitForUiText(ui, '1 member removed');
      await waitForUiText(ui, 'Pending request invalidated');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 9: dropped member stale traffic never affects the live conversation', async () => {
    try {
      const removedText = 'removed charlie says hello';
      await harness.charlie.run(['send', convId, removedText]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyContainsText(removedText),
        6_000,
      );

      await harness.charlie.run(['gate-approve', pendingRequestId, '-c', convId]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesRequestSigner('gate.approval', pendingRequestId, charlieKeyIdWire),
        6_000,
      );

      await harness.charlie.run(['gov', 'approve', addCharlieProposalId, '-c', convId]);
      await assertNoCliHistory(
        harness.alice,
        convId,
        historyMatchesProposalSigner('gov.approve', addCharlieProposalId, charlieKeyIdWire),
        6_000,
      );
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
