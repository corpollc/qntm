/** Installed, actual OpenClaw host and real relay worker. The only model double
 * is the deterministic loopback tool caller used by the existing host suite. */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { OpenClawAgent } from './src/openclaw-agent.js';
import { createLongHarness, waitForCliHistory, type LongHarness } from './src/runtime.js';
import { stageGroupDelivery, stageAcceptedGroupSend } from '../openclaw-qntm/tests/support/group-queue-fixture.mjs';
import {
  DropboxClient, base64UrlEncode, generateIdentity, openGroupWelcome, parseGroupLink, createGroupLink,
  groupSessionFromWelcome, checkGroupWelcomeReplay, receiveGroupEvent, deserializeEnvelope, groupSessionConversation, createMessage,
  serializeEnvelope, restoreGroupSession, prepareGroupSessionRekey, prepareGroupSessionAddition, type GroupSessionState, type OuterEnvelope,
} from '@corpollc/qntm';
const TIMEOUT = 240_000;
describe.sequential('native OpenClaw contact welcomes with Python and TypeScript peers', () => {
  let h: LongHarness, host: OpenClawAgent, convId: string, relay: DropboxClient;
  const tsPeer = generateIdentity();
  let tsSession: GroupSessionState;
  let tsCursor = 0;
  let bootstrapWinnerRoot: string, bootstrapLosingRoot: string;
  let delayedBootstrapWinner: OuterEnvelope, delayedBootstrapRoot: string;
  const aliceIdentity = () => {
    const raw = h.alice.readIdentity();
    return { privateKey: new Uint8Array(Buffer.from(raw.private_key, 'hex')), publicKey: new Uint8Array(Buffer.from(raw.public_key, 'hex')), keyID: new Uint8Array(Buffer.from(raw.key_id, 'hex')) };
  };
  const checkpoint = () => JSON.parse(readFileSync(join(host.stateDir, 'plugins/qntm/accounts/default/groups', `${convId}.json`), 'utf8'));
  afterEach(({ task }) => {
    if (task.result?.state !== 'fail' || !h || !host) return;
    const state = checkpoint();
    let lock: unknown = null;
    try { lock = JSON.parse(readFileSync(join(host.stateDir, 'plugins/qntm/accounts/default/groups', `${convId}.json.lock`), 'utf8')); } catch {}
    const diagnostic = { test: task.name, cursor: state.cursor, epoch: state.session?.epoch,
      recovery: state.session?.recovery?.reason, needsRekey: state.session?.needsRekey, removed: state.session?.removed,
      operation: state.operation && { action: state.operation.action, sentControls: state.operation.sentControls, sentWelcomes: state.operation.sentWelcomes },
      pending: state.pending.length, outbox: state.outbox.length, lock };
    mkdirSync(h.artifactDir, { recursive: true });
    writeFileSync(join(h.artifactDir, `openclaw-contact-${task.id}.json`), JSON.stringify(diagnostic));
    console.error('OpenClaw contact checkpoint:', JSON.stringify(diagnostic));
  });
  const action = async (id: string, action: string, options: Record<string, unknown> = {}) => host.journey(h.alice,
    { id, tool: 'qntm_group', action, options, initialStatus: 'ready' });
  beforeAll(async () => {
    h = await createLongHarness({ withUi: false }); relay = new DropboxClient(h.relayUrl);
    await h.alice.run(['identity', 'generate']); await h.dave.run(['identity', 'generate']);
    const created = await h.alice.run(['group', 'create', 'OpenClaw contact welcomes']); convId = String(created.data!.conversation_id);
    host = new OpenClawAgent(join(h.rootDir, 'openclaw'), convId);
    await h.alice.run(['contact', 'add', 'OpenClaw', base64UrlEncode(host.identity.publicKey)]);
    // Exercise the supported legacy-to-contact upgrade without adding a member
    // or rotating: the creator can refresh their own current admission.
    await h.alice.run(['group', 'refresh', convId, h.alice.readIdentity().public_key]);
    const identity = aliceIdentity(), record = h.alice.readConversation(convId);
    const source = restoreGroupSession(identity, record.group_session);
    let added = prepareGroupSessionAddition(identity, source, [host.identity.publicKey], undefined, undefined, Number(record.group_cursor));
    while (added.rekey.msg_id[0] < 170) added = prepareGroupSessionAddition(identity, source, [host.identity.publicKey], undefined, undefined, Number(record.group_cursor));
    const admitted = receiveGroupEvent(identity, added.addition, source).state;
    let winner = prepareGroupSessionRekey(identity, admitted);
    while (winner.rekey.msg_id[0] < 85 || winner.rekey.msg_id[0] >= 170) winner = prepareGroupSessionRekey(identity, admitted);
    let delayed = prepareGroupSessionRekey(identity, admitted);
    while (delayed.rekey.msg_id[0] >= 85) delayed = prepareGroupSessionRekey(identity, admitted);
    delayedBootstrapWinner = delayed.rekey; delayedBootstrapRoot = Buffer.from(delayed.conversation.keys.root).toString('hex');
    bootstrapWinnerRoot = Buffer.from(winner.conversation.keys.root).toString('hex');
    bootstrapLosingRoot = Buffer.from(added.conversation.keys.root).toString('hex');
    const losingPlan = { id: 'losing-bootstrap-branch', tool: 'qntm_group', single: { operation: 'status' }, expectedStatus: 'ready' };
    const losingText = createMessage(identity, added.conversation, 'text', new TextEncoder().encode('gateway-tool-smoke:' + Buffer.from(JSON.stringify(losingPlan)).toString('base64url')));
    for (const envelope of [added.addition, added.rekey, winner.rekey, losingText, added.welcomes[0]]) await relay.postMessage(added.conversation.id, serializeEnvelope(envelope));
    const groupLink = createGroupLink({ conversationId: added.conversation.id, inviterPublicKey: identity.publicKey, relayUrl: h.relayUrl });
    await host.configure(h.relayUrl, String(created.data!.invite_token));
    const cfg = JSON.parse(readFileSync(host.configPath, 'utf8'));
    cfg.tools.alsoAllow = ['qntm_group'];
    cfg.channels.qntm.contacts = { Alice: h.alice.readIdentity().public_key, Dave: h.dave.readIdentity().public_key, TypeScript: base64UrlEncode(tsPeer.publicKey) };
    cfg.channels.qntm.conversations.test = { groupLink, name: 'Native contact group', trigger: 'mention', triggerNames: ['gateway-tool-smoke:'],
      groupActions: ['add', 'remove', 'refresh', 'rekey', 'retry', 'open', 'send'] };
    writeFileSync(host.configPath, JSON.stringify(cfg), { mode: 0o600 });
    await host.start(); await host.waitFor(() => { try { return Boolean(checkpoint().session?.recovery); } catch { return false; } }, 'native competing-bootstrap recovery persisted');
  }, TIMEOUT);
  it('blocks the competing bootstrap branch before agent dispatch and accepts a same-epoch challenged Python refresh', async () => {
    expect(checkpoint().session.epoch).toBe(1); expect(checkpoint().session.root).toBe(bootstrapLosingRoot);
    expect(checkpoint().outbox).toEqual([]);
    const challenge = checkpoint().session.recovery.challenge;
    await h.alice.run(['recv', convId]);
    expect((h.alice.readConversation(convId).group_session as GroupSessionState).root).toBe(bootstrapWinnerRoot);
    await h.alice.run(['group', 'refresh', convId, 'OpenClaw', '--challenge', challenge]);
    await host.waitFor(() => !checkpoint().session?.recovery && checkpoint().session.root === bootstrapWinnerRoot, 'native same-epoch challenged replacement');
    expect(checkpoint().session.epoch).toBe(1); expect(checkpoint().session.rekeys).toEqual([]); expect(checkpoint().outbox).toEqual([]);
    await action('after-bootstrap-recovery', 'send', { text: 'native recovered the winning bootstrap key' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native recovered the winning bootstrap key', 'safe native bootstrap reply');
  }, TIMEOUT);
  it('also blocks an unverifiable older-source winner arriving after bootstrap, including preceding queued agent text', async () => {
    await host.stop();
    const identity = aliceIdentity(), state = restoreGroupSession(identity, h.alice.readConversation(convId).group_session);
    const losingPlan = { id: 'losing-delayed-bootstrap-branch', tool: 'qntm_group', single: { operation: 'status' }, expectedStatus: 'ready' };
    const losingText = createMessage(identity, groupSessionConversation(state), 'text', new TextEncoder().encode('gateway-tool-smoke:' + Buffer.from(JSON.stringify(losingPlan)).toString('base64url')));
    await relay.postMessage(delayedBootstrapWinner.conv_id, serializeEnvelope(losingText));
    // Complete real receive and durable queue admission while the host is down,
    // leaving the verified payload pending across its next replay/recovery.
    const pending = await stageGroupDelivery(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir, Buffer.from(losingText.msg_id).toString('hex'));
    expect(pending.generation).toBe(checkpoint().dispatchGeneration);
    await relay.postMessage(delayedBootstrapWinner.conv_id, serializeEnvelope(delayedBootstrapWinner));
    await host.start();
    await host.waitFor(() => Boolean(checkpoint().session?.recovery), 'post-bootstrap old-source recovery before queued dispatch');
    expect(checkpoint().outbox).toEqual([]); expect(checkpoint().session.epoch).toBe(1);
    const challenge = checkpoint().session.recovery.challenge;
    await h.alice.run(['recv', convId]);
    expect((h.alice.readConversation(convId).group_session as GroupSessionState).root).toBe(delayedBootstrapRoot);
    await h.alice.run(['group', 'refresh', convId, 'OpenClaw', '--challenge', challenge]);
    await host.waitFor(() => !checkpoint().session?.recovery && checkpoint().session.root === delayedBootstrapRoot, 'native delayed-winner challenged replacement');
    expect(checkpoint().outbox).toEqual([]); expect(checkpoint().session.rekeys).toEqual([]);
    await action('after-delayed-bootstrap-recovery', 'send', { text: 'native recovered a delayed old-source winner' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native recovered a delayed old-source winner', 'safe native delayed-bootstrap reply');
    expect((host as unknown as { provider: { outcomes: Map<string, unknown> } }).provider.outcomes.has(losingPlan.id)).toBe(false);
  }, TIMEOUT);
  afterAll(async () => {
    if (h && host) { mkdirSync(h.artifactDir, { recursive: true }); writeFileSync(join(h.artifactDir, 'openclaw-contact.log'), host.log); }
    await host?.close(); await h?.stop();
  }, TIMEOUT);
  it('uses the native reviewed tool to add two contacts who open in the opposite order, with Python and TypeScript replies', async () => {
    const dave = await action('contact-dave', 'add', { contact: 'Dave' });
    expect(dave[1].review!.recipientPublicKey).toBe(base64UrlEncode(new Uint8Array(Buffer.from(h.dave.readIdentity().public_key, 'hex'))));
    const ts = await action('contact-ts', 'add', { contact: 'TypeScript' });
    const link = String(ts.at(-1)!.groupLink), locator = parseGroupLink(link);
    const result = await relay.receiveMessages(locator.conversationId);
    for (const row of result.entries) {
      try {
        const welcome = openGroupWelcome(tsPeer, row.envelope, locator);
        tsSession = checkGroupWelcomeReplay(groupSessionFromWelcome(tsPeer, welcome, row.seq), welcome, result.sequence, result.entries);
        tsCursor = welcome.replayFromSequence;
      } catch { /* Other recipients and ordinary messages. */ }
    }
    expect(tsSession!.epoch).toBe(3); expect(tsSession!.rekeys).toEqual([]);
    expect(tsSession.recovery).toBeNull();
    for (const row of result.entries.filter(row => row.seq > tsCursor)) {
      try { tsSession = receiveGroupEvent(tsPeer, deserializeEnvelope(row.envelope), tsSession).state; } catch {}
    }
    await relay.postMessage(locator.conversationId, serializeEnvelope(createMessage(tsPeer, groupSessionConversation(tsSession), 'text', new TextEncoder().encode('typescript welcome reply'))));
    await h.dave.run(['group', 'join', String(dave.at(-1)!.groupLink)]);
    await h.dave.run(['send', convId, 'python late opening reply']);
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'typescript welcome reply', 'TypeScript recipient reply');
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'python late opening reply', 'Python recipient opposite opening order');
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).epoch).toBe(3);
    await action('reviewed-text', 'send', { text: 'native reviewed group text' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native reviewed group text', 'native explicit reviewed send');
  }, TIMEOUT);
  it('refreshes current membership and persists it through a real host restart', async () => {
    const before = checkpoint().session.root;
    await action('refresh-dave', 'refresh', { contact: 'Dave' });
    expect(checkpoint().session.root).toBe(before);
    await action('rotate', 'rekey');
    await host.stop('SIGKILL');
    // Force the real crash window instead of depending on the race between
    // relay receipt and the host's final local send-journal write.
    const interrupted = await stageAcceptedGroupSend(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir);
    expect(checkpoint().operation.action).toBe('send');
    await host.start();
    await host.waitFor(() => !checkpoint().operation, 'accepted pre-crash send finalized without another POST');
    expect(checkpoint().session.epoch).toBe(4);
    await waitForCliHistory(h.alice, convId, row => row.msg_id === interrupted.messageId, 'exact accepted pre-crash text');
    const replay = await relay.receiveMessages(new Uint8Array(Buffer.from(convId, 'hex')));
    expect(replay.entries.filter(row => { try { return Buffer.from(deserializeEnvelope(row.envelope).msg_id).toString('hex') === interrupted.messageId; } catch { return false; } })).toHaveLength(1);
    await action('after-restart', 'send', { text: 'restored native checkpoint' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'restored native checkpoint', 'restored host reply');
  }, TIMEOUT);
  it('pauses on an expired authenticated rekey and automatically accepts a nonce-bound Python refresh', async () => {
    await host.stop();
    await h.alice.run(['recv', convId]);
    const identity = aliceIdentity();
    const state = restoreGroupSession(identity, h.alice.readConversation(convId).group_session);
    const rekey = prepareGroupSessionRekey(identity, state, 20);
    await relay.postMessage(rekey.conversation.id, serializeEnvelope(rekey.rekey));
    await h.alice.run(['recv', convId]);
    await h.dave.run(['recv', convId]);
    expect((h.alice.readConversation(convId).group_session as GroupSessionState).epoch).toBe(5);
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).epoch).toBe(5);
    await delay(Math.max(0, (rekey.rekey.expiry_ts + 2) * 1000 - Date.now())); await host.start();
    await host.waitFor(() => Boolean(checkpoint().session?.recovery), 'persisted expired-control recovery barrier');
    const challenge = checkpoint().session.recovery.challenge;
    await h.alice.run(['group', 'refresh', convId, 'OpenClaw', '--challenge', challenge]);
    await host.waitFor(() => !checkpoint().session?.recovery && checkpoint().session.epoch === 5, 'native challenged refresh installed');
    await action('after-recovery', 'send', { text: 'native recovered without old keys' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native recovered without old keys', 'recovered native reply');
  }, TIMEOUT);
  it('removes a pinned contact, rejects a refresh for them, and requires explicit readmission', async () => {
    await action('remove-dave', 'remove', { contact: 'Dave' });
    await h.dave.run(['recv', convId]); expect((h.dave.readConversation(convId).group_session as GroupSessionState).removed).toBe(true);
    await expect(h.dave.run(['send', convId, 'excluded'])).rejects.toThrow();
    await host.journey(h.alice, { id: 'no-refresh-removed', tool: 'qntm_group', single: { operation: 'prepare', action: 'refresh', options: { contact: 'Dave' } }, expectedStatus: 'error', expectedCode: 'group_action_failed' });
    const readded = await action('readmit-dave', 'add', { contact: 'Dave' });
    await h.dave.run(['group', 'join', String(readded.at(-1)!.groupLink)]);
    await h.dave.run(['send', convId, 'readmitted without exclusion keys']);
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'readmitted without exclusion keys', 'Python explicit readmission');
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).epoch).toBe(7);
  }, TIMEOUT);
});
