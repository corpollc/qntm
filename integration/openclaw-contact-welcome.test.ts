/** Installed, actual OpenClaw host and real relay worker. The only model double
 * is the deterministic loopback tool caller used by the existing host suite. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { OpenClawAgent } from './src/openclaw-agent.js';
import { createLongHarness, waitForCliHistory, type LongHarness } from './src/runtime.js';
import {
  DropboxClient, base64UrlEncode, generateIdentity, openGroupWelcome, parseGroupLink,
  groupSessionFromWelcome, receiveGroupEvent, deserializeEnvelope, groupSessionConversation, createMessage,
  serializeEnvelope, restoreGroupSession, prepareGroupSessionRekey, type GroupSessionState,
} from '@corpollc/qntm';
const TIMEOUT = 240_000;
describe.sequential('native OpenClaw contact welcomes with Python and TypeScript peers', () => {
  let h: LongHarness, host: OpenClawAgent, convId: string, relay: DropboxClient;
  const tsPeer = generateIdentity();
  let tsSession: GroupSessionState;
  let tsCursor = 0;
  const checkpoint = () => JSON.parse(readFileSync(join(host.stateDir, 'plugins/qntm/accounts/default/groups', `${convId}.json`), 'utf8'));
  const action = async (id: string, action: string, options: Record<string, unknown> = {}) => host.journey(h.alice,
    { id, tool: 'qntm_group', action, options, initialStatus: 'ready' });
  beforeAll(async () => {
    h = await createLongHarness({ withUi: false }); relay = new DropboxClient(h.relayUrl);
    await h.alice.run(['identity', 'generate']); await h.dave.run(['identity', 'generate']);
    const created = await h.alice.run(['group', 'create', 'OpenClaw contact welcomes']); convId = String(created.data!.conversation_id);
    host = new OpenClawAgent(join(h.rootDir, 'openclaw'), convId);
    await h.alice.run(['contact', 'add', 'OpenClaw', base64UrlEncode(host.identity.publicKey)]);
    const added = await h.alice.run(['group', 'add', convId, 'OpenClaw']);
    await host.configure(h.relayUrl, String(created.data!.invite_token));
    const cfg = JSON.parse(readFileSync(host.configPath, 'utf8'));
    cfg.tools.alsoAllow = ['qntm_group'];
    cfg.channels.qntm.contacts = { Alice: h.alice.readIdentity().public_key, Dave: h.dave.readIdentity().public_key, TypeScript: base64UrlEncode(tsPeer.publicKey) };
    cfg.channels.qntm.conversations.test = { groupLink: added.data!.group_link, name: 'Native contact group', trigger: 'mention', triggerNames: ['gateway-tool-smoke:'],
      groupActions: ['add', 'remove', 'refresh', 'rekey', 'retry', 'open', 'send'] };
    writeFileSync(host.configPath, JSON.stringify(cfg), { mode: 0o600 });
    await host.start(); await host.waitFor(() => { try { return checkpoint().session?.epoch === 1; } catch { return false; } }, 'native welcome installed');
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
        const welcome = openGroupWelcome(tsPeer, row.envelope, locator); tsSession = groupSessionFromWelcome(tsPeer, welcome, row.seq); tsCursor = row.seq;
      } catch { /* Other recipients and ordinary messages. */ }
    }
    expect(tsSession!.epoch).toBe(3); expect(tsSession!.rekeys).toEqual([]);
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
    await host.stop('SIGKILL'); await host.start();
    expect(checkpoint().session.epoch).toBe(4);
    await action('after-restart', 'send', { text: 'restored native checkpoint' });
    await waitForCliHistory(h.alice, convId, row => row.unsafe_body === 'restored native checkpoint', 'restored host reply');
  }, TIMEOUT);
  it('pauses on an expired authenticated rekey and automatically accepts a nonce-bound Python refresh', async () => {
    await host.stop();
    await h.alice.run(['recv', convId]);
    const raw = h.alice.readIdentity();
    const identity = { privateKey: new Uint8Array(Buffer.from(raw.private_key, 'hex')), publicKey: new Uint8Array(Buffer.from(raw.public_key, 'hex')), keyID: new Uint8Array(Buffer.from(raw.key_id, 'hex')) };
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
