import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { LongHarness } from './src/runtime.js';
import { assertNoCliHistory, createLongHarness } from './src/runtime.js';
import {
  LONG_TIMEOUT,
  assertLiveHnItemPayload,
  assertLiveHnTopStoriesPayload,
  historyContainsText,
  historyMatchesProposal,
  historyMatchesRequest,
  parseUnsafeBody,
  printDiagnostics,
  requireUi,
  setupUiConversation,
  traceGateResultDelivery,
  uiHistoryMatchesRequest,
  waitForCliHistory,
  waitForUiStoredHistory,
  waitForUiText,
} from './long-helpers.js';

const UI_LABEL = 'Long Run';

describe.sequential('real long-running gateway integration UI flow', () => {
  let harness: LongHarness;
  let convId = '';
  let inviteToken = '';
  let gatewayPublicKey = '';
  let gatewayKid = '';
  let charlieKeyId = '';
  let charliePublicKey = '';
  let phase2FloorProposalId = '';
  let phase1TopStoriesRequestId = '';
  let phase1TopStoryItemRequestId = '';
  let staleRequestId = '';
  let strictRequestId = '';
  let leetRequestId = '';

  beforeAll(async () => {
    harness = await createLongHarness({ withUi: true });
    const setup = await setupUiConversation(harness, UI_LABEL);
    convId = setup.convId;
    inviteToken = setup.inviteToken;
    charlieKeyId = setup.charlieKeyId;
    charliePublicKey = setup.charliePublicKey;
  }, LONG_TIMEOUT);

  afterAll(async () => {
    await harness.stop();
  }, LONG_TIMEOUT);

  it('phase 1: bootstraps the gateway and stores a successful API result in chat', async () => {
    const ui = requireUi(harness);

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

      await waitForUiText(ui, 'hn.top-stories');
      await ui.approveLatestRequest();
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
        ui,
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
      await waitForUiText(ui, String(topStoryId));
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

      await waitForUiText(ui, 'hn.get-item');
      await ui.approveLatestRequest();
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
        ui,
        convId,
        uiHistoryMatchesRequest('gate.result', phase1TopStoryItemRequestId),
        'phase 1 UI hn.get-item gate.result',
        30_000,
      );
      const uiItemText = uiItemResultEntry.text;
      expect(typeof uiItemText).toBe('string');
      const uiItemResultBody = JSON.parse(String(uiItemText)) as Record<string, unknown>;
      expect(uiItemResultBody).toEqual(itemResultBody);
      await waitForUiText(ui, topStoryTitle);
      traceGateResultDelivery('hn.get-item', itemResultBody, uiItemResultBody, [
        `Top story title: ${topStoryTitle}`,
      ]);
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 2: raises the threshold, adds Charlie, invalidates the stale request, and executes a strict request', async () => {
    const ui = requireUi(harness);

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
      await waitForUiText(ui, 'proposed floor to 3');
      await ui.approveLatestProposal();
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
      await waitForUiText(ui, 'adding 1 member');
      await ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', addProposalId),
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

      await ui.approveLatestRequest();
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
      await waitForUiText(ui, 'Pending request invalidated');

      const strict = await harness.alice.run(['gate-run', 'hn.top-stories.strict', '-c', convId]);
      strictRequestId = String(strict.data?.request_id);
      await waitForUiText(ui, 'hn.top-stories.strict');
      await ui.approveLatestRequest();
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
      await waitForUiText(ui, '1 member added');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 3: removes Charlie, rotates keys, and excludes him from future chat traffic', async () => {
    const ui = requireUi(harness);

    try {
      const removeProposal = await harness.alice.run([
        'gov', 'propose-remove', '-c', convId, '--required-approvals', '2', '--', charlieKeyId,
      ]);
      const removeProposalId = String(removeProposal.data?.proposal_id);
      await waitForUiText(ui, 'removing 1 member');
      await ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', removeProposalId),
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
      await waitForUiText(ui, '1 member removed');
      await waitForUiText(ui, 'Security keys rotated');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);

  it('phase 4: lowers the threshold back to 2 and blocks leet.translate with a UI disapproval', async () => {
    const ui = requireUi(harness);

    try {
      const floorProposal = await harness.alice.run([
        'gov', 'propose-floor', '-c', convId, '--floor', '2', '--required-approvals', '2',
      ]);
      const floorProposalId = String(floorProposal.data?.proposal_id);
      await waitForUiText(ui, 'proposed floor to 2');
      await ui.approveLatestProposal();
      await harness.pumpGateway(convId);
      await waitForCliHistory(
        harness.alice,
        convId,
        historyMatchesProposal('gov.applied', floorProposalId),
        'return to floor 2',
        30_000,
      );

      const leet = await harness.alice.run(['gate-run', 'leet.translate', '-c', convId, '--arg', 'text=hello agent']);
      leetRequestId = String(leet.data?.request_id);
      await waitForUiText(ui, 'leet.translate');
      await ui.rejectLatestRequest();
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
      await waitForUiText(ui, 'Request Denied');
    } catch (error) {
      await printDiagnostics(harness, convId);
      throw error;
    }
  }, LONG_TIMEOUT);
});
