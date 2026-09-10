/** Installed, actual OpenClaw host and real relay worker. The only model double
 * is the deterministic loopback tool caller used by the existing host suite. */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { OpenClawAgent } from './src/openclaw-agent.js';
import { createLongHarness, waitForCliHistory, CliAgent, type LongHarness } from './src/runtime.js';
import { stageGroupDelivery, stageAcceptedGroupSend, stageCompletedGroupAddition, stageGenericGroupRefresh, stageAcceptedGroupRotation, stagePendingGroupRotation, stagePendingGroupRemoval, stageUncertainRemovalRepair } from '../openclaw-qntm/tests/support/group-queue-fixture.mjs';
import {
  DropboxClient, base64UrlEncode, generateIdentity, openGroupWelcome, parseGroupLink, createGroupLink,
  groupSessionFromWelcome, checkGroupWelcomeReplay, receiveGroupEvent, deserializeEnvelope, groupSessionConversation, createMessage,
  serializeEnvelope, restoreGroupSession, prepareGroupSessionRekey, prepareGroupSessionAddition, prepareGroupWelcomeRefresh, decryptMessage, type GroupSessionState, type OuterEnvelope,
} from '@corpollc/qntm';
const TIMEOUT = 240_000;
describe.sequential('native OpenClaw contact welcomes with Python and TypeScript peers', () => {
  let h: LongHarness, host: OpenClawAgent, convId: string, relay: DropboxClient;
  const tsPeer = generateIdentity();
  let tsSession: GroupSessionState;
  let tsCursor = 0;
  let bootstrapWinnerRoot: string, bootstrapLosingRoot: string;
  let delayedBootstrapWinner: OuterEnvelope, delayedBootstrapRoot: string;
  let bootstrapWelcome: OuterEnvelope;
  const aliceIdentity = () => {
    const raw = h.alice.readIdentity();
    return { privateKey: new Uint8Array(Buffer.from(raw.private_key, 'hex')), publicKey: new Uint8Array(Buffer.from(raw.public_key, 'hex')), keyID: new Uint8Array(Buffer.from(raw.key_id, 'hex')) };
  };
  const checkpointLink = () => createGroupLink({ conversationId: new Uint8Array(Buffer.from(convId, 'hex')), inviterPublicKey: host.identity.publicKey, relayUrl: h.relayUrl });
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
    bootstrapWelcome = added.welcomes[0];
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
    const refreshed = await action('refresh-dave', 'refresh', { contact: 'Dave' });
    expect(refreshed[1].review!.welcomePurpose).toBe('renewal');
    const founder = await action('refresh-alice-founder', 'refresh', { contact: 'Alice' });
    expect(founder[1].review!.welcomePurpose).toBe('refresh');
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
  it('accepts Python renewal of a later expired readmission without receiving exclusion keys', async () => {
    await h.alice.run(['group', 'remove', convId, 'OpenClaw']);
    await host.waitFor(() => checkpoint().session?.removed === true, 'native saved removal before offline readmission');
    expect(checkpoint().session.removedAtEpoch).toBe(7);
    await host.stop();
    const identity = aliceIdentity();
    let state = restoreGroupSession(identity, h.alice.readConversation(convId).group_session);
    const excluded = createMessage(identity, groupSessionConversation(state), 'text', new TextEncoder().encode('private while native host was excluded'));
    await relay.postMessage(excluded.conv_id, serializeEnvelope(excluded));
    await h.alice.run(['recv', convId]);
    const record = h.alice.readConversation(convId);
    state = restoreGroupSession(identity, record.group_session);
    const readmission = prepareGroupSessionAddition(identity, state, [host.identity.publicKey], 20, undefined, Number(record.group_cursor));
    for (const envelope of [readmission.addition, readmission.rekey, readmission.welcomes[0]]) await relay.postMessage(envelope.conv_id, serializeEnvelope(envelope));
    await h.alice.run(['recv', convId]);
    await h.dave.run(['recv', convId]); // Still-admitted Dave catches the short-lived rotation before expiry.
    expect((h.alice.readConversation(convId).group_session as GroupSessionState).epoch).toBe(9);
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).epoch).toBe(9);
    await delay(Math.max(0, (readmission.welcomes[0].expiry_ts + 2) * 1000 - Date.now()));
    // Use the matching Python library in the fixture's installed CLI environment.
    // No new CLI/agent renewal action is implied by this receiving-client test.
    const script = `import sys
from qntm import cli
from qntm.group_client import GroupClient
from qntm.group_session import prepare_group_admission_renewal, assert_group_admission_renewal_current
from qntm.identity import key_id_from_public_key
from qntm.message import serialize_envelope
config, relay, cid, address = sys.argv[1:]
identity = cli._load_identity(config)
record = GroupClient(config, identity, relay).sync(cid)
recipient = bytes.fromhex(address)
admission = record['group_session']['admissions'][key_id_from_public_key(recipient).hex()]
operation = prepare_group_admission_renewal(identity, record['group_session'], recipient,
    {key: admission[key] for key in ('addId', 'addDigest')}, replay_from_sequence=record['group_cursor'])
assert_group_admission_renewal_current(identity, record['group_session'], operation)
cli._http_send(relay, cid, serialize_envelope(operation['welcomes'][0]))
`;
    await promisify(execFile)(join(h.rootDir, 'venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'),
      ['-c', script, h.alice.configDir, h.relayUrl, convId, Buffer.from(host.identity.publicKey).toString('hex')], { timeout: 30_000 });
    await relay.postMessage(bootstrapWelcome.conv_id, serializeEnvelope(bootstrapWelcome));
    await host.start();
    await host.waitFor(() => !checkpoint().session?.removed && !checkpoint().session?.recovery && checkpoint().session.epoch === 9, 'native Python renewal installed');
    const installed = restoreGroupSession(host.identity, checkpoint().session);
    expect(installed.rekeys).toEqual([]);
    expect(installed.admissions[Buffer.from(host.identity.keyID).toString('hex')].sourceEpoch).toBe(8);
    expect(() => decryptMessage(excluded, groupSessionConversation(installed))).toThrow();
    await action('after-python-renewal', 'send', { text: 'native accepts renewed delivery of its later admission' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native accepts renewed delivery of its later admission', 'native reply after Python renewal');
  }, TIMEOUT);
  it('uses the native reviewed refresh to renew Python readmission after its first welcome expires', async () => {
    await action('remove-dave-before-renewal', 'remove', { contact: 'Dave' });
    await h.dave.run(['recv', convId]);
    const removed = h.dave.readConversation(convId).group_session as GroupSessionState;
    expect(removed.removed).toBe(true); expect(removed.removedAtEpoch).toBe(9);
    await h.alice.run(['recv', convId]);
    const identity = aliceIdentity();
    const excluded = createMessage(identity, groupSessionConversation(restoreGroupSession(identity, h.alice.readConversation(convId).group_session)),
      'text', new TextEncoder().encode('private while Dave was excluded'));
    await relay.postMessage(excluded.conv_id, serializeEnvelope(excluded));
    await h.alice.run(['recv', convId]);
    const record = h.alice.readConversation(convId);
    const addition = prepareGroupSessionAddition(identity, restoreGroupSession(identity, record.group_session),
      [new Uint8Array(Buffer.from(h.dave.readIdentity().public_key, 'hex'))], 20, undefined, Number(record.group_cursor));
    for (const envelope of [addition.addition, addition.rekey, addition.welcomes[0]]) await relay.postMessage(envelope.conv_id, serializeEnvelope(envelope));
    await h.alice.run(['recv', convId]);
    await host.waitFor(() => checkpoint().session?.epoch === 11 && !checkpoint().session?.needsRekey, 'native accepted later Dave admission');
    await delay(Math.max(0, (addition.welcomes[0].expiry_ts + 2) * 1000 - Date.now()));
    const accepted = checkpoint(), nativeState = restoreGroupSession(host.identity, accepted.session);
    const recipient = new Uint8Array(Buffer.from(h.dave.readIdentity().public_key, 'hex'));
    const generic = prepareGroupWelcomeRefresh(host.identity, nativeState, [recipient], undefined, undefined, accepted.cursor);
    await relay.postMessage(generic.conversation.id, serializeEnvelope(generic.welcomes[0]));
    const link = createGroupLink({ conversationId: generic.conversation.id, inviterPublicKey: host.identity.publicKey, relayUrl: h.relayUrl });
    await expect(h.dave.run(['group', 'join', link])).rejects.toThrow();
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).removed).toBe(true);
    const reviewed = await action('renew-dave-readmission', 'refresh', { contact: 'Dave' });
    expect(reviewed[1].review!.welcomePurpose).toBe('renewal');
    expect(reviewed[1].review!.effect).toContain('proof of this existing admission');
    expect(checkpoint().session.epoch).toBe(11); expect(checkpoint().session.root).toBe(nativeState.root);
    await h.dave.run(['group', 'join', link]);
    const dave = h.dave.readConversation(convId).group_session as GroupSessionState;
    expect(dave.removed).toBe(false); expect(dave.epoch).toBe(11); expect(dave.rekeys).toEqual([]);
    expect(dave.admissions[h.dave.readIdentity().key_id].sourceEpoch).toBe(10);
    expect(() => decryptMessage(excluded, groupSessionConversation(dave))).toThrow();
    await h.dave.run(['send', convId, 'Python received native renewal without exclusion keys']);
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'Python received native renewal without exclusion keys', 'Python reply after reviewed native renewal');
  }, TIMEOUT);
  it('reviews native retry of a completed expired ADD and delivers its current renewal to the removed Python peer', async () => {
    await action('remove-dave-before-pending-retry', 'remove', { contact: 'Dave' });
    await h.dave.run(['recv', convId]);
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).removed).toBe(true);
    const removedEpoch = (h.dave.readConversation(convId).group_session as GroupSessionState).removedAtEpoch!;
    let original: { controls: string[]; welcomes: string[] }, root: string;
    const reviewed = await host.journey(h.alice,
      { id: 'retry-expired-native-add', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' }, async () => {
        // The request already entered the real host before the operation barrier.
        // Simulate interruption after accepted controls, before welcome delivery.
        const staged = await stageCompletedGroupAddition(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir, 'Dave', 5);
        original = staged.original; root = staged.currentRoot;
        await h.alice.run(['recv', convId]);
        await delay(Math.max(0, (staged.expiry + 1) * 1000 - Date.now()));
        expect(checkpoint().operation.welcomes).toEqual(original.welcomes);
      });
    expect(reviewed[1].review!.welcomePurpose).toBe('renewal');
    expect(reviewed[1].review!.effect).toContain('same verified completed admission');
    // Peer receipt of the turn's reply can precede the sender's final journal save.
    await host.waitFor(() => !checkpoint().operation, 'native retry and its turn reply finalized');
    expect(checkpoint().operation).toBeNull(); expect(checkpoint().session.root).toBe(root!);
    const result = await relay.receiveMessages(parseGroupLink(checkpointLink()).conversationId, 0);
    const originalWires = original!.controls.map(wire => Buffer.from(wire, 'base64url').toString('hex'));
    for (const wire of originalWires) expect(result.entries.filter(row => Buffer.from(row.envelope).toString('hex') === wire)).toHaveLength(1);
    expect(result.entries.some(row => Buffer.from(row.envelope).toString('base64url') === original!.welcomes[0])).toBe(false);
    await h.dave.run(['group', 'join', checkpointLink()]);
    const dave = h.dave.readConversation(convId).group_session as GroupSessionState;
    expect(dave.removed).toBe(false); expect(dave.rekeys).toEqual([]);
    expect(dave.admissions[h.dave.readIdentity().key_id].sourceEpoch).toBeGreaterThan(removedEpoch);
    await h.dave.run(['send', convId, 'Python joined through native reviewed pending admission retry']);
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'Python joined through native reviewed pending admission retry', 'Python reply after pending native admission recovery');
  }, TIMEOUT);

  it('finishes an expired partial native admission through rotation and welcome reviews in one real agent turn', async () => {
    await action('remove-dave-before-partial-retry', 'remove', { contact: 'Dave' });
    await h.dave.run(['recv', convId]);
    const removed = h.dave.readConversation(convId).group_session as GroupSessionState;
    expect(removed.removed).toBe(true);
    let original: { controls: string[]; welcomes: string[] }, originalRoot: string;
    const reviewed = await host.journey(h.alice,
      { id: 'retry-partial-native-add', tool: 'qntm_group', action: 'retry', initialStatus: 'ready', finishRotation: true }, async () => {
        const staged = await stageCompletedGroupAddition(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir, 'Dave', 5, true);
        original = staged.original; originalRoot = staged.currentRoot;
        await h.alice.run(['recv', convId]);
        expect(checkpoint().session.needsRekey).toBe(true);
        await delay(Math.max(0, (staged.expiry + 1) * 1000 - Date.now()));
      });
    expect(reviewed[1].review!.recoveryPhase).toBe('addition_rekey');
    expect(reviewed[1].review!.retryMode).toBe('replacement_rotation');
    expect(reviewed[1].review!.effect).toContain('does not deliver contact keys');
    expect(reviewed[2]).toMatchObject({ status: 'rotation_verified', welcomePending: true });
    expect(reviewed[3].review!.welcomePurpose).toBe('renewal');
    expect(reviewed[3].review!.retryMode).toBe('replacement_renewal'); expect(reviewed[4].status).toBe('submitted');
    expect(checkpoint().operation).toBeNull(); expect(checkpoint().session.root).not.toBe(originalRoot!);
    const result = await relay.receiveMessages(parseGroupLink(checkpointLink()).conversationId, 0);
    const wires = result.entries.map(row => Buffer.from(row.envelope).toString('base64url'));
    expect(wires.filter(wire => wire === original!.controls[0])).toHaveLength(1);
    expect(wires).not.toContain(original!.controls[1]); expect(wires).not.toContain(original!.welcomes[0]);
    await h.dave.run(['group', 'join', checkpointLink()]);
    const dave = h.dave.readConversation(convId).group_session as GroupSessionState;
    expect(dave.removed).toBe(false); expect(dave.recovery).toBeNull(); expect(dave.rekeys).toEqual([]);
    expect(dave.admissions[h.dave.readIdentity().key_id].sourceEpoch).toBeGreaterThan(removed.removedAtEpoch!);
    await h.dave.run(['send', convId, 'Python joined after native repaired admission rotation']);
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'Python joined after native repaired admission rotation', 'Python reply after two native recovery reviews');
  }, TIMEOUT);

  it('recovers an expired generic founder refresh through native review and a fresh Python identity restore', async () => {
    const challenge = '51'.repeat(32);
    let original: { welcomes: string[] }, root: string, anchor: number;
    const reviewed = await host.journey(h.alice,
      { id: 'retry-generic-founder-refresh', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' }, async () => {
        const staged = await stageGenericGroupRefresh(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir, 'Alice', 5, challenge);
        original = staged.original; root = staged.currentRoot; anchor = staged.cursor;
        await delay(Math.max(0, (staged.expiry + 1) * 1000 - Date.now()));
      });
    expect(reviewed[1].review!.retryMode).toBe('replacement_refresh');
    expect(reviewed[1].review!.welcomePurpose).toBe('refresh'); expect(reviewed[1].review!.recoveryChallenge).toBe(challenge);
    expect(checkpoint().operation).toBeNull(); expect(checkpoint().session.root).toBe(root!);
    const messages = await relay.receiveMessages(parseGroupLink(checkpointLink()).conversationId, anchor!);
    expect(messages.entries.some(row => Buffer.from(row.envelope).toString('base64url') === original!.welcomes[0])).toBe(false);
    const welcomes = messages.entries.flatMap(row => {
      try { return [openGroupWelcome(aliceIdentity(), row.envelope, { inviterPublicKey: host.identity.publicKey, conversationId: parseGroupLink(checkpointLink()).conversationId })]; }
      catch { return []; }
    });
    expect(welcomes).toHaveLength(1); expect(welcomes[0].purpose).toBe('refresh');
    expect(welcomes[0].replayFromSequence).toBeGreaterThanOrEqual(anchor!);
    expect(welcomes[0].recoveryChallenge).toEqual(new Uint8Array(Buffer.from(challenge, 'hex')));
    const restored = new CliAgent('restored-founder', h.alice.qntmBin, h.relayUrl, h.recipeCatalogPath,
      fileURLToPath(new URL('../', import.meta.url)), h.rootDir);
    writeFileSync(join(restored.configDir, 'identity.json'), JSON.stringify(h.alice.readIdentity()), { mode: 0o600 });
    await restored.run(['group', 'join', checkpointLink()]);
    const state = restored.readConversation(convId).group_session as GroupSessionState;
    expect(state.root).toBe(root!); expect(state.rekeys).toEqual([]); expect(state.recovery).toBeNull();
    await restored.run(['send', convId, 'Python restored founder from native generic refresh retry']);
    await waitForCliHistory(h.dave, convId, row => row.unsafe_body === 'Python restored founder from native generic refresh retry', 'Python peer reply after generic native refresh');
  }, TIMEOUT);

  it('finishes an accepted native rotation after real replay-cache eviction and a later Python rotation without any POST', async () => {
    let staged: Awaited<ReturnType<typeof stageAcceptedGroupRotation>>, before: number;
    const reviewed = await host.journey(h.alice,
      { id: 'retry-accepted-native-rotation', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' }, async () => {
        // The request already entered the real host before the operation barrier.
        // Simulate a lost POST acknowledgement after the relay accepted the exact rotation.
        staged = await stageAcceptedGroupRotation(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir);
        expect(checkpoint().controlReceipts).toEqual([{ messageId: staged.messageId, digest: expect.any(String), epoch: staged.epoch - 1, sequence: staged.sequence, valid: true }]);
        await h.alice.run(['recv', convId]);
        for (const text of ['native cache pressure one', 'native cache pressure two']) await h.alice.run(['send', convId, text]);
        await host.waitFor(() => !(staged.messageId in checkpoint().session.seen) && checkpoint().controlReceipts?.[0]?.valid === true,
          'real host eviction of the accepted rotation marker');
        await h.alice.run(['group', 'rekey', convId]);
        await host.waitFor(() => checkpoint().session?.epoch === staged.epoch + 1, 'later canonical Python rotation');
        expect(checkpoint().operation.controls).toEqual([staged.control]);
        before = (await relay.receiveMessages(parseGroupLink(checkpointLink()).conversationId, 0)).sequence;
      });
    expect(reviewed[1].review!.retryMode).toBe('accepted_cleanup'); expect(reviewed[1].review!.acceptedControls).toBe(1);
    expect(reviewed[1].review!.effect).toContain('No messages will be posted'); expect(reviewed[2].status).toBe('submitted');
    expect((reviewed[2] as { pendingOperation?: unknown }).pendingOperation).toBeNull();
    // The host's own turn-completion text send finalizes its journal shortly after the reply lands.
    await host.waitFor(() => !checkpoint().operation, 'host send journal finalized after accepted-control cleanup');
    expect(checkpoint().controlReceipts).toEqual([]);
    expect(checkpoint().session.epoch).toBe(staged!.epoch + 1); expect(checkpoint().session.root).not.toBe(staged!.expectedRoot);
    const result = await relay.receiveMessages(parseGroupLink(checkpointLink()).conversationId, 0);
    expect(result.entries.filter(row => Buffer.from(row.envelope).toString('base64url') === staged!.control)).toHaveLength(1);
    // Only the host's turn-completion text follows the review; no control or welcome was reposted.
    const after = result.entries.filter(row => row.seq > before!);
    const alice = groupSessionConversation(restoreGroupSession(aliceIdentity(), h.alice.readConversation(convId).group_session));
    expect(after.map(row => decryptMessage(deserializeEnvelope(row.envelope), alice).inner.body_type)).toEqual(['text']);
    expect(new TextDecoder().decode(decryptMessage(deserializeEnvelope(after[0].envelope), alice).inner.body)).toContain('gateway-tool-complete:');
    await action('after-accepted-cleanup', 'send', { text: 'native finished an accepted rotation without reposting it' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native finished an accepted rotation without reposting it', 'native reply after accepted-control cleanup');
  }, TIMEOUT);

  it('recovers a crash before POST through an operator-initiated turn from a fresh CLI process after host restart, while inbound messages stay deferred', async () => {
    await host.stop();
    // Durable state of a host that saved its exact rotation and died before publishing it.
    const staged = await stagePendingGroupRotation(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir);
    expect(checkpoint().operation.controls).toEqual([staged.control]);
    await host.start();
    await host.waitFor(() => checkpoint().cursor >= staged.cursor, 'host replayed the relay after restart');
    // Untrusted inbound group traffic cannot start a turn through the pending-operation barrier.
    const deferredPlan = { id: 'deferred-behind-pending-rotation', tool: 'qntm_group', single: { operation: 'status' }, expectedStatus: 'ready' };
    const deferredMarker = 'gateway-tool-smoke:' + Buffer.from(JSON.stringify(deferredPlan)).toString('base64url');
    await h.alice.run(['send', convId, deferredMarker]);
    await host.waitFor(() => checkpoint().cursor > staged.cursor, 'host received the deferred inbound message');
    await delay(3000);
    expect((host as unknown as { provider: { outcomes: Map<string, unknown> } }).provider.outcomes.has(deferredPlan.id)).toBe(false);
    expect(checkpoint().operation.controls).toEqual([staged.control]); expect(checkpoint().session.epoch).toBe(staged.epoch);
    const conversationId = parseGroupLink(checkpointLink()).conversationId;
    const before = await relay.receiveMessages(conversationId, 0);
    expect(before.entries.some(row => Buffer.from(row.envelope).toString('base64url') === staged.control)).toBe(false);
    // A route that names no configured conversation of this account hides the tool and changes nothing.
    const wrong = await host.localAgentTurn({ id: 'operator-wrong-conversation', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' },
      'ff'.repeat(16), { expectToolAbsent: true });
    expect(wrong.results).toEqual([]); expect(wrong.toolAbsent || wrong.code !== 0).toBe(true);
    expect(checkpoint().operation.controls).toEqual([staged.control]);
    expect((await relay.receiveMessages(conversationId, 0)).sequence).toBe(before.sequence);
    // The documented local entry point: a normal agent turn in the group's own session, started by the operator.
    const recovered = await host.localAgentTurn({ id: 'operator-retry-after-restart', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' }, 'test');
    expect(recovered.code).toBe(0);
    // The turn's reply returns to the operator's terminal as CLI JSON, not to the group.
    expect(JSON.parse(recovered.stdout)).toBeTypeOf('object');
    expect(recovered.stdout).toContain('gateway-tool-complete:operator-retry-after-restart');
    expect(recovered.results[1].review!.retryMode).toBe('exact'); expect(recovered.results[1].review!.acceptedControls).toBe(0);
    expect(recovered.results[2].status).toBe('submitted');
    await host.waitFor(() => !checkpoint().operation && checkpoint().session.epoch === staged.epoch + 1, 'reviewed retry published the exact rotation once');
    expect(checkpoint().session.root).toBe(staged.expectedRoot);
    const after = await relay.receiveMessages(conversationId, 0);
    expect(after.entries.filter(row => Buffer.from(row.envelope).toString('base64url') === staged.control)).toHaveLength(1);
    // Delivery resumes: the deferred inbound message now runs exactly once.
    await host.waitFor(() => (host as unknown as { provider: { outcomes: Map<string, unknown> } }).provider.outcomes.has(deferredPlan.id), 'deferred inbound turn released after recovery');
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === `gateway-tool-complete:${deferredPlan.id}`, 'deferred turn completion');
    await h.alice.run(['recv', convId]);
    const alice = groupSessionConversation(restoreGroupSession(aliceIdentity(), h.alice.readConversation(convId).group_session));
    const completions = (await relay.receiveMessages(conversationId, 0)).entries.filter(row => {
      try { return new TextDecoder().decode(decryptMessage(deserializeEnvelope(row.envelope), alice).inner.body) === `gateway-tool-complete:${deferredPlan.id}`; } catch { return false; }
    });
    expect(completions).toHaveLength(1);
    await action('after-operator-recovery', 'send', { text: 'native delivery resumed after operator-initiated recovery' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native delivery resumed after operator-initiated recovery', 'native reply after local recovery');
  }, TIMEOUT);

  it('finishes an accepted native removal whose rotation expired through operator-initiated turns after host restarts, with the removed Python peer excluded', async () => {
    const provider = (host as unknown as { provider: { outcomes: Map<string, unknown> } }).provider;
    const conversationId = parseGroupLink(checkpointLink()).conversationId;
    const hostConversation = () => groupSessionConversation(restoreGroupSession(host.identity, checkpoint().session));
    const decryptAll = (rows: Array<{ seq: number; envelope: Uint8Array }>, conversation: ReturnType<typeof hostConversation>) => rows.flatMap(row => {
      try { const message = decryptMessage(deserializeEnvelope(row.envelope), conversation); return [{ seq: row.seq, type: message.inner.body_type, text: new TextDecoder().decode(message.inner.body) }]; } catch { return []; }
    });
    // Round one: crash before the completing rotation, expiry, denied action, then a reviewed replacement.
    await host.stop();
    const deferredPlan = { id: 'deferred-behind-pending-removal', tool: 'qntm_group', single: { operation: 'status' }, expectedStatus: 'ready' };
    await h.alice.run(['send', convId, 'gateway-tool-smoke:' + Buffer.from(JSON.stringify(deferredPlan)).toString('base64url')]);
    const config = JSON.parse(readFileSync(host.configPath, 'utf8')), permitted = config.channels.qntm.conversations.test.groupActions as string[];
    const staged = await stagePendingGroupRemoval(config, host.stateDir, 'Dave', 8);
    expect(checkpoint().operation.controls).toEqual(staged.controls); expect(checkpoint().session.needsRekey).toBe(true);
    expect(checkpoint().controlReceipts).toEqual([expect.objectContaining({ messageId: staged.removalId, epoch: staged.epoch, valid: true })]);
    config.channels.qntm.conversations.test.groupActions = permitted.filter(action => action !== 'remove');
    writeFileSync(host.configPath, JSON.stringify(config), { mode: 0o600 });
    await host.start();
    await host.waitFor(() => checkpoint().cursor >= staged.cursor, 'host replayed the accepted removal after restart');
    await delay(Math.max(0, (staged.expiry + 1) * 1000 - Date.now()));
    expect(provider.outcomes.has(deferredPlan.id)).toBe(false); expect(checkpoint().operation.controls).toEqual(staged.controls);
    const before = await relay.receiveMessages(conversationId, 0);
    const denied = await host.localAgentTurn({ id: 'operator-removal-denied', tool: 'qntm_group', single: { operation: 'prepare', action: 'retry' },
      expectedStatus: 'error', expectedCode: 'group_action_failed' }, 'test');
    expect(String(denied.results[0].message)).toContain('no longer locally permitted');
    expect((await relay.receiveMessages(conversationId, 0)).sequence).toBe(before.sequence); expect(checkpoint().operation.phase).toBeUndefined();
    await host.stop();
    config.channels.qntm.conversations.test.groupActions = permitted; writeFileSync(host.configPath, JSON.stringify(config), { mode: 0o600 });
    await host.start();
    await host.waitFor(() => checkpoint().cursor >= staged.cursor, 'host replayed again with removal permitted');
    expect(provider.outcomes.has(deferredPlan.id)).toBe(false);
    const repaired = await host.localAgentTurn({ id: 'operator-removal-repair', tool: 'qntm_group', action: 'retry', initialStatus: 'rotation_required' }, 'test');
    expect(repaired.code).toBe(0);
    expect(repaired.results[1].review!.recoveryPhase).toBe('removal_rekey'); expect(repaired.results[1].review!.retryMode).toBe('replacement_rotation');
    expect(repaired.results[1].review!.effect).toContain('never reposted'); expect(repaired.results[2].status).toBe('submitted');
    await host.waitFor(() => !checkpoint().operation && checkpoint().session.epoch === staged.epoch + 1, 'reviewed replacement rotation completed the removal');
    expect(checkpoint().session.needsRekey).toBe(false); expect(checkpoint().controlReceipts).toEqual([]);
    const afterRepair = await relay.receiveMessages(conversationId, 0), wires = afterRepair.entries.map(row => Buffer.from(row.envelope).toString('base64url'));
    expect(wires.filter(wire => wire === staged.controls[0])).toHaveLength(1); expect(wires).not.toContain(staged.controls[1]);
    const rotations = afterRepair.entries.filter(row => row.seq > before.sequence && (() => { try { return deserializeEnvelope(row.envelope).conv_epoch === staged.epoch; } catch { return false; } })());
    expect(rotations).toHaveLength(1);
    await host.waitFor(() => provider.outcomes.has(deferredPlan.id), 'deferred inbound turn released after the removal completed');
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === `gateway-tool-complete:${deferredPlan.id}`, 'deferred turn completion');
    await h.dave.run(['recv', convId]);
    expect((h.dave.readConversation(convId).group_session as GroupSessionState).removed).toBe(true);
    await expect(h.dave.run(['send', convId, 'removed peer cannot send'])).rejects.toThrow();
    await h.alice.run(['send', convId, 'survivor reply after native removal repair']);
    await host.waitFor(() => checkpoint().cursor > afterRepair.sequence, 'host received the survivor reply');
    const survivorRows = await relay.receiveMessages(conversationId, afterRepair.sequence);
    expect(decryptAll(survivorRows.entries, hostConversation()).map(row => row.text)).toContain('survivor reply after native removal repair');
    // Round two: the reviewed repair itself is posted, then the host dies before its journal is finalized.
    await host.stop();
    await h.alice.run(['recv', convId]);
    const deferredAgain = { id: 'deferred-behind-uncertain-repair', tool: 'qntm_group', single: { operation: 'status' }, expectedStatus: 'ready' };
    await h.alice.run(['send', convId, 'gateway-tool-smoke:' + Buffer.from(JSON.stringify(deferredAgain)).toString('base64url')]);
    const second = await stagePendingGroupRemoval(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir, 'TypeScript', 8);
    await delay(Math.max(0, (second.expiry + 1) * 1000 - Date.now()));
    const uncertain = await stageUncertainRemovalRepair(JSON.parse(readFileSync(host.configPath, 'utf8')), host.stateDir);
    expect(checkpoint().operation).toMatchObject({ phase: 'removal_rekey', controls: [uncertain.rotation], origin: { kind: 'remove', controls: second.controls, delivery: 'unknown' } });
    expect(checkpoint().controlReceipts).toEqual([expect.objectContaining({ messageId: second.removalId, valid: true })]);
    await host.start();
    await host.waitFor(() => checkpoint().cursor > second.cursor, 'host replayed the uncertain repair rotation after restart');
    expect(provider.outcomes.has(deferredAgain.id)).toBe(false);
    const finished = await host.localAgentTurn({ id: 'operator-uncertain-repair', tool: 'qntm_group', action: 'retry', initialStatus: 'ready' }, 'test');
    expect(finished.code).toBe(0); expect(finished.results[1].review!.retryMode).toBe('accepted_cleanup'); expect(finished.results[2].status).toBe('submitted');
    await host.waitFor(() => !checkpoint().operation && checkpoint().session.epoch === second.epoch + 1, 'uncertain repair proven from replay without another POST');
    const final = await relay.receiveMessages(conversationId, 0), finalWires = final.entries.map(row => Buffer.from(row.envelope).toString('base64url'));
    expect(finalWires.filter(wire => wire === uncertain.rotation)).toHaveLength(1); expect(finalWires.filter(wire => wire === second.controls[0])).toHaveLength(1);
    expect(finalWires).not.toContain(second.controls[1]);
    await host.waitFor(() => provider.outcomes.has(deferredAgain.id), 'second deferred inbound turn released');
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === `gateway-tool-complete:${deferredAgain.id}`, 'second deferred turn completion');
    // Both removed peers are absent from the host's authenticated roster and from Alice's
    // Python view; the TypeScript peer's last keys (epoch 3) cannot open post-repair traffic.
    // (A cold offline replay of this whole history with the bare reducer is not attempted:
    // earlier tests posted 20-second rotations that decryptMessage now rejects as expired.)
    const hostRoster = groupSessionConversation(restoreGroupSession(host.identity, checkpoint().session)).participants.map(kid => Buffer.from(kid).toString('hex'));
    expect(hostRoster).not.toContain(Buffer.from(tsPeer.keyID).toString('hex')); expect(hostRoster).not.toContain(h.dave.readIdentity().key_id);
    expect(hostRoster).toContain(h.alice.readIdentity().key_id);
    await h.alice.run(['recv', convId]);
    expect(h.alice.readConversation(convId).participants).not.toContain(Buffer.from(tsPeer.keyID).toString('hex'));
    await action('after-removal-recoveries', 'send', { text: 'native finished both removals from the current roster' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'native finished both removals from the current roster', 'native reply after removal recoveries');
    const latest = (await relay.receiveMessages(conversationId, final.sequence)).entries;
    expect(latest.length).toBeGreaterThan(0);
    for (const row of latest) expect(() => decryptMessage(deserializeEnvelope(row.envelope), groupSessionConversation(tsSession))).toThrow();
  }, TIMEOUT);

});
