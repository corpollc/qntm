import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  generateIdentity, createInvite, inviteToToken, createConversation, deriveConversationKeys,
  createMessage, serializeEnvelope, deserializeEnvelope, decryptMessage, serializeIdentity,
  base64UrlEncode, DropboxClient, createGroupRekeyBody, createGroupRemoveBody, QSP1Suite,
  createGatewaySession, createGatewayInviteBody, gatewayInvitationHash, receiveConversationEvent,
  sessionGatewayContext, createGateRequestBody, createGatewayProposalBody, addParticipant,
} from '@corpollc/qntm';
import { createHostRelay } from '../tests/support/host-relay.mjs';
import { createToolProvider } from '../tests/support/tool-provider.mjs';
import { stagePlugin } from './package.mjs';

const host = fileURLToPath(new URL('../../openclaw.mjs', import.meta.resolve('openclaw/plugin-sdk/channel-core')));
const temporary = await mkdtemp(join(tmpdir(), 'qntm-openclaw-smoke-'));
const state = join(temporary, 'state');
const stage = join(temporary, 'plugin');
const fixture = join(temporary, 'fixture');
const config = join(state, 'openclaw.json');
const env = {
  ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH}`,
  OPENCLAW_STATE_DIR: state, OPENCLAW_CONFIG_PATH: config,
  OPENCLAW_SKIP_GMAIL_WATCHER: '1', OPENCLAW_SKIP_CANVAS_HOST: '1',
};
// Use only disposable state and a deterministic reply hook; no provider keys,
// live contacts, operator profiles or model calls participate in this test.
for (const key of Object.keys(env)) {
  if (/(API_KEY|ACCESS_TOKEN|AUTH_TOKEN|OPENCLAW_GATEWAY_TOKEN|OPENCLAW_GATEWAY_PASSWORD)$/.test(key)) delete env[key];
}
let gateway;
let sessionLock;
let gatewayLog = '';
const relay = await createHostRelay();
const provider = await createToolProvider();
function terminate(child, signal) {
  try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function command(command, args, cwd = temporary) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timeout = setTimeout(() => terminate(child, 'SIGKILL'), 180_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => { clearTimeout(timeout); reject(error); });
    child.once('exit', (code) => {
      clearTimeout(timeout);
      if (code === 0) resolve(stdout);
      else reject(new Error(`${command} exited ${code}\n${stdout}\n${stderr}`));
    });
  });
}
const cli = (...args) => command(process.execPath, [host, ...args]);
async function waitFor(predicate, description, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (provider.failures.length) throw new Error(provider.failures.join('\n'));
    if (await predicate()) return;
    if (gateway && (gateway.exitCode != null || gateway.signalCode != null)) throw new Error(`OpenClaw exited ${gateway.exitCode ?? gateway.signalCode}\n${gatewayLog}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out: ${description}\n${gatewayLog}`);
}
async function stopHost(signal = 'SIGTERM') {
  if (!gateway || gateway.exitCode != null || gateway.signalCode != null) return;
  const exited = new Promise((resolve) => gateway.once('exit', resolve));
  terminate(gateway, signal);
  const timeout = setTimeout(() => terminate(gateway, 'SIGKILL'), 10_000);
  await exited;
  clearTimeout(timeout);
}
function startHost() {
  gateway = spawn(process.execPath, [host, 'gateway', 'run'], { cwd: temporary, env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
  gateway.stdout.on('data', (chunk) => { gatewayLog += chunk; });
  gateway.stderr.on('data', (chunk) => { gatewayLog += chunk; });
}
try {
  await mkdir(state, { mode: 0o700 });
  await stagePlugin(stage);
  await mkdir(fixture);
  await writeFile(join(fixture, 'package.json'), JSON.stringify({
    name: 'qntm-smoke-fixture', version: '1.0.0', type: 'module', openclaw: { extensions: ['./index.js'] },
  }));
  await writeFile(join(fixture, 'openclaw.plugin.json'), JSON.stringify({
    id: 'qntm-smoke-fixture', configSchema: { type: 'object', properties: {}, additionalProperties: false },
  }));
  await writeFile(join(fixture, 'index.js'), `export default {
    id: 'qntm-smoke-fixture', name: 'qntm smoke fixture', register(api) {
      api.on('before_agent_reply', (event, ctx) => {
        if (ctx.channel !== 'qntm' && ctx.messageProvider !== 'qntm') return;
        if (event.cleanedBody.includes('gateway-tool-smoke:')) return;
        return { handled: true, reply: { text: 'host-reply: ' + event.cleanedBody } };
      }, { eligibleTriggers: ['user'] });
    }
  };\n`);
  // Allocate the host's port independently of the relay, without terminating
  // any pre-existing listener if a concurrent process wins the bind race.
  const { createServer } = await import('node:net');
  const portProbe = createServer();
  await new Promise((resolve) => portProbe.listen(0, '127.0.0.1', resolve));
  const port = portProbe.address().port;
  await new Promise((resolve) => portProbe.close(resolve));
  const identity = generateIdentity();
  const peer = generateIdentity();
  const conversations = ['direct', 'group', 'group'].map((type) => {
    const invite = createInvite(peer, type);
    return { invite, conversation: createConversation(invite, deriveConversationKeys(invite)) };
  });
  await writeFile(config, JSON.stringify({
    gateway: { mode: 'local', bind: 'loopback', port, auth: { mode: 'token', token: 'disposable-qntm-smoke-test-token' } },
    agents: { defaults: { workspace: join(temporary, 'workspace'), model: { primary: 'qntm-fixture/fixture' }, thinkingDefault: 'off',
      models: { 'qntm-fixture/fixture': {} } } },
    models: { providers: { 'qntm-fixture': { baseUrl: provider.url, apiKey: 'disposable-local-fixture-key', api: 'openai-completions',
      models: [{ id: 'fixture', name: 'qntm local test fixture', reasoning: false, input: ['text'], contextWindow: 200000, maxTokens: 4096,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } },
    tools: { alsoAllow: ['qntm_gateway'] },
    session: { dmScope: 'per-account-channel-peer', store: join(state, 'smoke-sessions.json') },
    plugins: { enabled: true, allow: ['qntm', 'qntm-smoke-fixture'] },
  }), { mode: 0o600 });
  const [artifact] = JSON.parse(await command('npm', ['pack', '--json', '--pack-destination', temporary], stage));
  await cli('plugins', 'install', '--force', '--accept-capabilities', join(temporary, artifact.filename));
  await cli('plugins', 'install', '--link', '--force', '--accept-capabilities', fixture);
  const cfg = JSON.parse(await readFile(config, 'utf8'));
  // The fixture is explicitly authorized to read these generated test chats.
  // This permission exists only in the disposable host, never in user config.
  cfg.plugins.entries['qntm-smoke-fixture'].hooks = { allowConversationAccess: true };
  cfg.channels = { qntm: {
    identity: base64UrlEncode(serializeIdentity(identity)), relayUrl: relay.url,
    conversations: Object.fromEntries(conversations.map(({ invite }, index) => [
      `chat${index}`, { invite: inviteToToken(invite), name: `Smoke ${index}`,
        ...(index === 1 ? { trigger: 'mention', triggerNames: ['wire-smoke'] } : {}),
        ...(index === 2 ? { trigger: 'mention', triggerNames: ['gateway-tool-smoke:'],
          gatewayActions: ['request', 'approve', 'disapprove', 'secret', 'propose', 'gov-approve', 'gov-disapprove'] } : {}) },
    ])),
  } };
  await writeFile(config, JSON.stringify(cfg));
  const doctor = await cli('plugins', 'doctor');
  assert.match(doctor, /checks passed/);
  startHost();
  const client = new DropboxClient(relay.url);
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  await waitFor(() => conversations.every(({ conversation }) => relay.conversations.get(hex(conversation.id))?.sockets.size), 'both OpenClaw subscriptions');
  async function expectReply(conversation, text) {
    await waitFor(() => relay.conversations.get(hex(conversation.id)).messages.some((record) => {
      const envelope = deserializeEnvelope(Buffer.from(record.envelope_b64, 'base64'));
      if (envelope.conv_epoch !== conversation.currentEpoch) return false;
      const message = decryptMessage(envelope, conversation);
      return hex(message.inner.sender_kid) === hex(identity.keyID)
        && new TextDecoder().decode(message.inner.body).includes(`host-reply: ${text}`);
    }), `host reply to ${text}`);
  }
  async function sendAndExpect(conversation, text) {
    const envelope = createMessage(peer, conversation, 'text', new TextEncoder().encode(text));
    await client.postMessage(conversation.id, serializeEnvelope(envelope));
    await expectReply(conversation, text);
  }
  const checkpoint = async conversation => {
    try { return JSON.parse(await readFile(join(state, 'plugins/qntm/accounts/default/conversations', `${hex(conversation.id)}.json`), 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
  };
  // A deterministic loopback model asks the actual agent harness to invoke the
  // installed optional tool. No direct controller invocation substitutes for it.
  const managed = conversations[2].conversation, authority = generateIdentity();
  addParticipant(managed, identity.publicKey);
  let managedSession = createGatewaySession(managed, [peer.publicKey, identity.publicKey]);
  const members = Object.fromEntries([peer, identity].map(value => [base64UrlEncode(value.keyID), base64UrlEncode(value.publicKey)]));
  const admission = createGatewayInviteBody({ invitation_id: 'ac'.repeat(16), inviter_public_key: base64UrlEncode(peer.publicKey),
    gateway_public_key: base64UrlEncode(authority.publicKey), gateway_kid: base64UrlEncode(authority.keyID),
    expires_at: Math.floor(Date.now() / 1000) + 600 }, managed, members, 2);
  async function postManaged(sender, type, body) {
    const envelope = createMessage(sender, managed, type, new TextEncoder().encode(JSON.stringify(body)));
    const event = receiveConversationEvent(envelope, managed, peer, managedSession);
    managedSession = event.state;
    await client.postMessage(managed.id, serializeEnvelope(envelope));
    return envelope;
  }
  const invited = await postManaged(peer, 'gate.promote', admission);
  await postManaged(authority, 'gate.accept', { type: 'gate.accept', invitation_id: admission.invitation_id, invitation_msg_id: hex(invited.msg_id),
    invitation_hash: gatewayInvitationHash(JSON.stringify(admission)), conv_id: hex(managed.id), conv_epoch: 0,
    gateway_kid: admission.gateway_kid, gateway_public_key: admission.gateway_public_key });
  await waitFor(async () => (await checkpoint(managed))?.session.gateway?.accepted, 'signed gateway acceptance in host checkpoint');
  async function toolJourney(id, action, options) {
    const marker = 'gateway-tool-smoke:' + Buffer.from(JSON.stringify({ id, action, options })).toString('base64url');
    await client.postMessage(managed.id, serializeEnvelope(createMessage(peer, managed, 'text', new TextEncoder().encode(marker))));
    await waitFor(() => provider.outcomes.has(id), `native tool prepare and commit: ${id}`, 60_000);
    const receipt = provider.outcomes.get(id)[2];
    await waitFor(() => relay.conversations.get(hex(managed.id)).messages.some(record => {
      const envelope = deserializeEnvelope(Buffer.from(record.envelope_b64, 'base64'));
      if (hex(envelope.msg_id) !== receipt.messageId) return false;
      const verified = receiveConversationEvent(envelope, managed, peer, managedSession);
      assert.equal(hex(verified.message.inner.sender_kid), hex(identity.keyID));
      managedSession = verified.state;
      return true;
    }), `verified native tool message: ${id}`);
    await waitFor(() => relay.conversations.get(hex(managed.id)).messages.some(record => {
      const message = decryptMessage(deserializeEnvelope(Buffer.from(record.envelope_b64, 'base64')), managed);
      return new TextDecoder().decode(message.inner.body) === `gateway-tool-complete:${id}`;
    }), `native agent tool completion: ${id}`);
  }
  await toolJourney('request', 'request', { service: 'demo', endpoint: '/record', verb: 'POST', targetUrl: 'https://example.test/record', payload: { amount: 42 } });
  const peerRequest = createGateRequestBody(peer, sessionGatewayContext(managedSession), { service: 'demo', endpoint: '/', verb: 'GET', targetUrl: 'https://example.test/' });
  await postManaged(peer, peerRequest.type, peerRequest);
  await toolJourney('approve', 'approve', { id: peerRequest.request_id });
  await toolJourney('disapprove', 'disapprove', { id: peerRequest.request_id });
  await toolJourney('secret', 'secret', { service: 'demo', value: 'disposable-host-fixture-secret' });
  await toolJourney('propose', 'propose', { proposalType: 'floor_change', proposedFloor: 1 });
  const peerProposal = createGatewayProposalBody(peer, sessionGatewayContext(managedSession), { proposalType: 'floor_change', proposedFloor: 1 });
  await postManaged(peer, peerProposal.type, peerProposal);
  await toolJourney('gov-approve', 'gov-approve', { id: peerProposal.proposal_id });
  await toolJourney('gov-disapprove', 'gov-disapprove', { id: peerProposal.proposal_id });
  await sendAndExpect(conversations[0].conversation, 'direct-wire-smoke');
  await sendAndExpect(conversations[1].conversation, 'group-wire-smoke');
  const group = conversations[1].conversation;
  const root = new Uint8Array(32).fill(42);
  const rekey = serializeEnvelope(createMessage(peer, group, 'group_rekey', createGroupRekeyBody(root, 1,
    [peer, identity].map(value => ({ kid: value.keyID, publicKey: value.publicKey })), group.id)));
  await client.postMessage(group.id, rekey);
  await waitFor(async () => (await checkpoint(group))?.conversation.currentEpoch === 1, 'durable rekey without agent wakeup');
  const epochKeys = new QSP1Suite().deriveEpochKeys(root, group.id, 1);
  group.keys = { root, aeadKey: epochKeys.aeadKey, nonceKey: epochKeys.nonceKey };
  group.currentEpoch = 1;
  await stopHost();
  const counts = conversations.map(({ conversation }) => relay.conversations.get(hex(conversation.id)).messages.length);
  startHost();
  await waitFor(() => conversations.every(({ conversation }) => relay.conversations.get(hex(conversation.id))?.sockets.size), 'subscriptions after restart');
  await sendAndExpect(conversations[0].conversation, 'restart-wire-smoke');
  assert.equal(relay.conversations.get(hex(conversations[0].conversation.id)).messages.length, counts[0] + 2);
  assert.equal(relay.conversations.get(hex(conversations[1].conversation.id)).messages.length, counts[1]);
  await client.postMessage(group.id, rekey); // Exact replay of the prior epoch needs no retained old key.
  await sendAndExpect(group, 'rekey-restart-wire-smoke');
  assert.equal(relay.conversations.get(hex(group.id)).messages.length, counts[1] + 3);

  const direct = conversations[0].conversation;
  // Force SQLite contention at host session admission, before ownership
  // transfers. Only the disposable host's synthetic session store is locked.
  sessionLock = new DatabaseSync(join(state, 'smoke-sessions.sqlite'));
  sessionLock.exec('BEGIN IMMEDIATE');
  const crashEnvelope = createMessage(peer, direct, 'text', new TextEncoder().encode('crash-wire-smoke'));
  await client.postMessage(direct.id, serializeEnvelope(crashEnvelope));
  const database = new DatabaseSync(join(state, 'plugins/qntm/accounts/default/ingress.sqlite'), { readOnly: true });
  const crashId = `${hex(direct.id)}:${hex(crashEnvelope.msg_id)}`;
  try {
    await waitFor(() => {
      const row = database.prepare('SELECT status,attempts FROM ingress WHERE id=?').get(crashId);
      return row?.status === 'pending' && row.attempts >= 1;
    }, 'failed host session admission retained for retry');
  } finally { database.close(); }
  await stopHost('SIGKILL'); // Kill the host after its relay cursor has already committed.
  assert.ok((await checkpoint(direct)).cursor >= relay.conversations.get(hex(direct.id)).messages.length);
  sessionLock.exec('ROLLBACK'); sessionLock.close(); sessionLock = undefined;
  startHost();
  await waitFor(() => conversations.every(({ conversation }) => relay.conversations.get(hex(conversation.id))?.sockets.size), 'subscriptions after process crash');
  await expectReply(direct, 'crash-wire-smoke'); // No resend or new relay message is needed.

  await client.postMessage(group.id, serializeEnvelope(createMessage(peer, group, 'group_remove', createGroupRemoveBody([identity.keyID]))));
  await waitFor(async () => (await checkpoint(group))?.session.removed, 'durable local removal');
  await stopHost(); startHost();
  await waitFor(() => relay.conversations.get(hex(group.id))?.sockets.size, 'removed subscription after restart');
  const beforeRemovalProbe = relay.conversations.get(hex(group.id)).messages.length;
  await client.postMessage(group.id, serializeEnvelope(createMessage(peer, group, 'text', new TextEncoder().encode('removed-wire-smoke'))));
  await waitFor(async () => (await checkpoint(group))?.cursor >= beforeRemovalProbe + 1, 'removed message consumed without wakeup');
  await sendAndExpect(direct, 'still-connected-wire-smoke');
  assert.equal(relay.conversations.get(hex(group.id)).messages.length, beforeRemovalProbe + 1);
  console.log('PASS: real OpenClaw install/discovery, native model/tool request/votes/secret/governance, encrypted direct/group replies, rekey/replay, SIGKILL recovery before adoption, removal across restart.');
} catch (error) {
  console.error(gatewayLog);
  throw error;
} finally {
  if (sessionLock) { sessionLock.exec('ROLLBACK'); sessionLock.close(); }
  await stopHost();
  await relay.close();
  await provider.close();
  if (process.env.QNTM_KEEP_HOST_SMOKE === '1') console.log(`Disposable evidence retained: ${temporary}`);
  else await rm(temporary, { recursive: true, force: true });
}
