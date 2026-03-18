import { expect } from 'vitest';
import type { AimUiAgent, LongHarness } from './src/runtime.js';
import { waitForCliHistory, waitForUiStoredHistory, waitForUiText } from './src/runtime.js';

export const LONG_TIMEOUT = 300_000;

export function parseUnsafeBody(entry: Record<string, unknown>): Record<string, unknown> {
  const raw = entry.unsafe_body;
  if (typeof raw !== 'string') {
    throw new Error(`Missing unsafe_body on history entry: ${JSON.stringify(entry)}`);
  }
  return JSON.parse(raw) as Record<string, unknown>;
}

export function historyMatchesRequest(bodyType: string, requestId: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).request_id === requestId;
    } catch {
      return false;
    }
  };
}

export function historyMatchesRequestSigner(bodyType: string, requestId: string, signerKid: string) {
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

export function historyMatchesProposal(bodyType: string, proposalId: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).proposal_id === proposalId;
    } catch {
      return false;
    }
  };
}

export function historyMatchesProposalSigner(bodyType: string, proposalId: string, signerKid: string) {
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

export function historyMatchesService(bodyType: string, service: string) {
  return (entry: Record<string, unknown>): boolean => {
    if (entry.body_type !== bodyType) return false;
    try {
      return parseUnsafeBody(entry).service === service;
    } catch {
      return false;
    }
  };
}

export function historyContainsText(text: string) {
  return (entry: Record<string, unknown>): boolean => (
    entry.body_type === 'text' && entry.unsafe_body === text
  );
}

export function uiHistoryMatchesRequest(bodyType: string, requestId: string) {
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

export function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

export function countHistoryMatches(
  entries: Array<Record<string, unknown>>,
  predicate: (entry: Record<string, unknown>) => boolean,
): number {
  return entries.filter(predicate).length;
}

export function historyIndex(
  entries: Array<Record<string, unknown>>,
  predicate: (entry: Record<string, unknown>) => boolean,
): number {
  return entries.findIndex(predicate);
}

export async function printDiagnostics(harness: LongHarness, convId: string): Promise<void> {
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

export function traceGateResultDelivery(
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

export function assertLiveHnTopStoriesPayload(resultBody: Record<string, unknown>): number[] {
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

export function assertLiveHnItemPayload(resultBody: Record<string, unknown>, expectedId: number): string {
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

export function assertCounterResultPayload(resultBody: Record<string, unknown>, expectedCount: number): void {
  expect(resultBody.status_code).toBe(200);
  expect(resultBody.content_type).toContain('application/json');
  expect(typeof resultBody.body).toBe('string');

  const parsed = JSON.parse(String(resultBody.body)) as Record<string, unknown>;
  expect(parsed.count).toBe(expectedCount);
}

export function requireUi(harness: LongHarness): AimUiAgent {
  if (!harness.ui) {
    throw new Error('AIM UI was not started for this harness');
  }
  return harness.ui;
}

export interface UiConversationSetup {
  convId: string;
  inviteToken: string;
  charlieKeyId: string;
  charliePublicKey: string;
}

export async function setupUiConversation(
  harness: LongHarness,
  label: string,
): Promise<UiConversationSetup> {
  const ui = requireUi(harness);

  await harness.alice.run(['identity', 'generate']);
  await harness.charlie.run(['identity', 'generate']);
  await ui.generateIdentity();

  const group = await harness.alice.run(['group', 'create', label]);
  const convId = String(group.data?.conversation_id);
  const inviteToken = String(group.data?.invite_token);

  const charlieIdentity = harness.charlie.readIdentity();
  const charlieKeyId = charlieIdentity.key_id;
  const charliePublicKey = charlieIdentity.public_key;

  await ui.joinConversation(inviteToken, label);
  await ui.sendText('hello from bob');
  await waitForCliHistory(
    harness.alice,
    convId,
    historyContainsText('hello from bob'),
    'initial UI hello',
  );

  return {
    convId,
    inviteToken,
    charlieKeyId,
    charliePublicKey,
  };
}

export interface CliConversationSetup {
  convId: string;
  inviteToken: string;
  gatewayPublicKey: string;
  gatewayKid: string;
  charlieKeyId: string;
  charliePublicKey: string;
  daveKeyId: string;
  daveKeyIdWire: string;
  davePublicKey: string;
}

export async function setupCliGovernedConversation(
  harness: LongHarness,
  label: string,
  options: { joinDaveOffline?: boolean } = {},
): Promise<CliConversationSetup> {
  const joinDaveOffline = options.joinDaveOffline ?? false;

  await harness.alice.run(['identity', 'generate']);
  await harness.charlie.run(['identity', 'generate']);
  await harness.dave.run(['identity', 'generate']);

  const group = await harness.alice.run(['group', 'create', label]);
  const convId = String(group.data?.conversation_id);
  const inviteToken = String(group.data?.invite_token);

  const charlieIdentity = harness.charlie.readIdentity();
  const charlieKeyId = charlieIdentity.key_id;
  const charliePublicKey = charlieIdentity.public_key;

  const daveIdentity = harness.dave.readIdentity();
  const daveKeyId = daveIdentity.key_id;
  const daveKeyIdWire = hexToBase64Url(daveKeyId);
  const davePublicKey = daveIdentity.public_key;

  await harness.charlie.run(['group', 'join', '--name', label, '--', inviteToken]);
  await harness.charlie.run(['send', convId, 'hello from charlie cli']);
  await waitForCliHistory(
    harness.alice,
    convId,
    historyContainsText('hello from charlie cli'),
    'charlie cli hello',
    30_000,
  );

  if (joinDaveOffline) {
    await harness.dave.run(['group', 'join', '--name', label, '--', inviteToken]);
  }

  const bootstrap = await harness.bootstrapGateway(convId, harness.alice);
  const gatewayPublicKey = bootstrap.gateway_public_key;
  const gatewayKid = bootstrap.gateway_kid;

  await harness.alice.run([
    'gate-promote',
    '-c',
    convId,
    '--threshold',
    '2',
    `--gateway-kid=${gatewayKid}`,
  ]);
  await harness.alice.run([
    'gate-secret',
    '-c',
    convId,
    '--service',
    'fun',
    `--gateway-pubkey=${gatewayPublicKey}`,
    '--value',
    'dummy-fun-token',
    '--header-name',
    'X-Test',
    '--header-template',
    '{value}',
  ]);
  await harness.pumpGateway(convId);

  return {
    convId,
    inviteToken,
    gatewayPublicKey,
    gatewayKid,
    charlieKeyId,
    charliePublicKey,
    daveKeyId,
    daveKeyIdWire,
    davePublicKey,
  };
}

export {
  waitForCliHistory,
  waitForUiStoredHistory,
  waitForUiText,
};
