/**
 * Isolated follow-up for qntm-wx41. Not a Playwright testDir file
 * (config testDir is tests/e2e) and not a release gate.
 *
 * Recorded failures (2026-09-10, worktree feature/grok-browser-control-receipts):
 * - 21:24:04 / call-1c093aef: 307s timeout clicking Contacts (locator resolved,
 *   never became stable). No console/storage exception in error-context.md.
 * - 21:29:46 / call-ea5263cb: after posting 8192 signed texts and restoring the
 *   conversation URL, poll saw cursor 8 vs expected >= 8200 (180s).
 * - call-45abbd98: .message-body evict-8191 never appeared after goto('/').
 *
 * Root cause not established. Do not rerun this bulk case as a CI gate.
 */
export const QNTM_WX41 = 'qntm-wx41'
export const EVIDENCE = {
  contactsTimeoutMs: 307040,
  contactsError: 'Test timeout of 300000ms exceeded waiting for Contacts click stable',
  bulkReplayCursorObserved: 8,
  bulkReplayCursorExpected: 8200,
  bulkReplayPollMs: 180000,
  playwrightErrorContext: 'ui/aim-chat/test-results/contact-groups-browser-ret-8059d-estart-and-a-later-rotation-chromium/error-context.md',
  capturedReceiverOrQuotaError: null,
}
