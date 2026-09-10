import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { buildSignedReceipt, generateIdentity, base64UrlEncode, keyIDFromPublicKey, QSP1Suite } from '@corpollc/qntm';
import { GroupState, createInvite, createConversation, deriveConversationKeys, createGroupGenesisBody,
  parseGroupGenesisBody, createMessage, decryptMessage, marshalCanonical, deserializeEnvelope,
  prepareGroupAddition, openGroupWelcome, createGroupLink, parseGroupLink, isGroupWelcomeEnvelope,
  createGroupSession, restoreGroupSession, receiveGroupEvent, assertGroupAdditionAccepted,
  createGroupControlMessage, createGroupRemoveBody, createRekey, assertGroupCanSend,
  groupSessionFromWelcome, checkGroupReplayCoverage, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch,
  groupSessionConversation, prepareGroupSessionAddition, prepareGroupSessionRekey, serializeEnvelope,
  DropboxClient } from '@corpollc/qntm';
import type { GroupSessionState } from '@corpollc/qntm';
import { ManagedProcess, workerTestEnv } from './src/runtime.js';
import { recordingRelay } from './src/recording-relay.js';

interface RelayFrame {
  type: string;
  seq?: number;
  head_seq?: number;
  envelope_b64?: string;
}

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CONV_ID = '0123456789abcdef0123456789abcdef';

async function waitForFrame(
  frames: RelayFrame[],
  predicate: (frame: RelayFrame) => boolean,
  description: string,
  timeoutMs = 10_000,
): Promise<RelayFrame> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const frame = frames.find(predicate);
    if (frame) return frame;
    await delay(25);
  }
  throw new Error(`Timed out waiting for ${description}: ${JSON.stringify(frames)}`);
}

async function openSubscription(
  relayUrl: string,
  fromSeq: number,
): Promise<{ socket: WebSocket; frames: RelayFrame[] }> {
  const frames: RelayFrame[] = [];
  const socket = new WebSocket(
    `${relayUrl.replace(/^http/, 'ws')}/v1/subscribe?conv_id=${CONV_ID}&from_seq=${fromSeq}`,
  );
  socket.addEventListener('message', (event) => {
    frames.push(JSON.parse(String(event.data)) as RelayFrame);
  });
  await waitForFrame(frames, (frame) => frame.type === 'ready', 'relay ready frame');
  return { socket, frames };
}

async function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return;
  await Promise.race([
    new Promise<void>((resolveClose) => {
      socket.addEventListener('close', () => resolveClose(), { once: true });
      socket.close();
    }),
    delay(1_000),
  ]);
}

describe.sequential('real relay worker subscribe acceptance', () => {
  let relayProcess: ManagedProcess | null = null;
  let relayUrl = '';
  let stateDir = '';
  let artifactDir = '';
  let failed = false;
  const timeline: Array<Record<string, unknown>> = [];

  function captureRuntime(): void {
    if (!artifactDir) return;
    mkdirSync(artifactDir, { recursive: true });
    writeFileSync(join(artifactDir, 'relay.stdout.log'), relayProcess?.stdout ?? '');
    writeFileSync(join(artifactDir, 'relay.stderr.log'), relayProcess?.stderr ?? '');
    writeFileSync(join(artifactDir, 'runtime.json'), JSON.stringify({
      node: process.version, undici: process.versions.undici, platform: process.platform, arch: process.arch,
      url: relayUrl, command: relayProcess?.command, timeline,
    }, null, 2));
  }

  beforeEach(({ task }) => {
    timeline.push({ event: 'start', name: task.name, at: new Date().toISOString() });
  });

  afterEach(({ task }) => {
    failed ||= task.result?.state === 'fail';
    timeline.push({ event: 'end', name: task.name, at: new Date().toISOString(),
      state: task.result?.state, errors: task.result?.errors?.map(error => error.message) });
    captureRuntime();
  });

  it('reconnects a native WebSocket after an application callback fails', async () => {
    const cid = generateIdentity().keyID, relay = new DropboxClient(relayUrl);
    const sequence = await relay.postMessage(cid, new Uint8Array([97]));
    const injectedFailure = new Error('fixture persistence failure');
    const callbackAttempts: number[] = [], errors: Error[] = [];
    const frames: RelayFrame[] = [];
    const subscription = relay.subscribeMessages(cid, 0, {
      onMessage: ({ seq }) => {
        callbackAttempts.push(seq);
        if (callbackAttempts.length === 1) throw injectedFailure;
        frames.push({ type: 'message', seq });
      },
      // onError also reports socket failures during reconnection. Preserve the
      // actual cause instead of labelling every transport error a callback error.
      onError: error => { errors.push(error); },
      onClose: ({ code }) => { frames.push({ type: 'closed', seq: code }); },
    });
    try {
      await waitForFrame(frames, frame => frame.type === 'message' && frame.seq === sequence, 'native callback retry', 20_000);
      expect(errors.filter(error => error === injectedFailure)).toHaveLength(1);
      expect(callbackAttempts).toEqual([sequence, sequence]);
      expect(frames.filter(frame => frame.type === 'message')).toEqual([{ type: 'message', seq: sequence }]);
      expect(frames.some(frame => frame.type === 'closed' && frame.seq === 4000)).toBe(true);
    } finally {
      subscription.close();
      await subscription.closed;
      writeFileSync(join(artifactDir, 'native-callback-reconnect.json'), JSON.stringify({ callbackAttempts,
        errors: errors.map(error => ({ name: error.name, message: error.message, injected: error === injectedFailure })), frames }, null, 2));
    }
  }, 40_000);

  it('exposes sequenced replay and serialized ready callbacks through the TypeScript client', async () => {
    const cid = generateIdentity().keyID, relay = new DropboxClient(relayUrl);
    const first = new Uint8Array([97]), second = new Uint8Array([98]);
    const firstSeq = await relay.postMessage(cid, first);
    const secondSeq = await relay.postMessage(cid, second);
    const replay = await relay.receiveMessages(cid);
    expect(replay.entries.map(({ seq, envelope }) => ({ seq, bytes: Array.from(envelope) })))
      .toEqual([{ seq: firstSeq, bytes: [97] }, { seq: secondSeq, bytes: [98] }]);
    expect(replay.sequence).toBe(secondSeq);
    const frames: RelayFrame[] = [];
    const subscription = relay.subscribeMessages(cid, firstSeq, {
      onMessage: ({ seq }) => { frames.push({ type: 'message', seq }); },
      onReady: head_seq => { frames.push({ type: 'ready', head_seq }); },
    });
    try {
      await waitForFrame(frames, frame => frame.type === 'ready', 'shared ready callback');
      expect(frames).toEqual([{ type: 'message', seq: secondSeq }, { type: 'ready', head_seq: secondSeq }]);
      const liveSeq = await relay.postMessage(cid, new Uint8Array([99]));
      await waitForFrame(frames, frame => frame.seq === liveSeq, 'shared live callback');
      expect(frames.at(-1)).toEqual({ type: 'message', seq: liveSeq });
    } finally {
      subscription.close();
      await subscription.closed;
    }
  }, 30_000);

  beforeAll(async () => {
    stateDir = mkdtempSync(join(tmpdir(), 'qntm-relay-acceptance-'));
    artifactDir = join(REPO_ROOT, 'integration', 'test-results', basename(stateDir));
    mkdirSync(artifactDir, { recursive: true });
    // Keep a stock-Wrangler control for diagnosing workers-sdk#14641. Normal
    // acceptance uses the deploy bundle in direct workerd, with no POST retry.
    const command = process.env.QNTM_RELAY_DEV_PROXY === '1'
      ? [process.platform === 'win32' ? 'npx.cmd' : 'npx', 'wrangler', 'dev', '--local',
        '--ip', '127.0.0.1', '--inspector-port', '0']
      : [process.execPath, join(REPO_ROOT, 'integration', 'src', 'relay-worker-process.mjs')];
    relayProcess = new ManagedProcess(
      'relay-acceptance',
      [
        ...command,
        '--name', basename(stateDir).toLowerCase(),
        '--port', '0',
        '--persist-to', stateDir,
        '--var', 'RATE_LIMIT_PER_MIN:5000',
        '--var', 'ENVELOPE_TTL_SECONDS:60',
        '--var', 'METRICS_READ_TOKEN:local-metrics-test-token',
        '--var', `MONITOR_CONVERSATION_ID:${'fe'.repeat(16)}`,
      ],
      join(REPO_ROOT, 'worker'),
      { ...workerTestEnv(stateDir), WRANGLER_SEND_METRICS: 'false',
        WRANGLER_LOG_PATH: join(artifactDir, 'wrangler.log') },
    );
    relayUrl = await relayProcess.waitForLocalUrl('worker', '/healthz');
  }, 60_000);

  afterAll(async () => {
    let stopped = false;
    try {
      if (relayProcess) await relayProcess.stop();
      stopped = true;
    } finally {
      captureRuntime();
      // These are synthetic test conversations. Preserve their stopped SQLite
      // state only on failure; never copy Wrangler's registry or credentials.
      const runtimeState = join(stateDir, 'v3');
      if (stopped && failed && existsSync(runtimeState)) {
        cpSync(runtimeState, join(artifactDir, 'runtime-state'), { recursive: true });
      }
      if (stopped && stateDir) rmSync(stateDir, { recursive: true, force: true });
    }
  });

  async function publish(label: string, msgId?: string): Promise<number> {
    const response = await fetch(`${relayUrl}/v1/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        conv_id: CONV_ID,
        envelope_b64: Buffer.from(label).toString('base64'),
        ...(msgId ? { msg_id: msgId } : {}),
      }),
    });
    expect(response.status).toBe(201);
    return Number(((await response.json()) as { seq: number }).seq);
  }

  it('rejects malformed or non-WebSocket subscribe attempts', async () => {
    const invalidConversation = await fetch(`${relayUrl}/v1/subscribe?conv_id=bad&from_seq=0`);
    expect(invalidConversation.status).toBe(400);

    const invalidCursor = await fetch(`${relayUrl}/v1/subscribe?conv_id=${CONV_ID}&from_seq=-1`);
    expect(invalidCursor.status).toBe(400);

    const missingUpgrade = await fetch(`${relayUrl}/v1/subscribe?conv_id=${CONV_ID}&from_seq=0`);
    expect(missingUpgrade.status).toBe(426);
  });

  it('replays backlog, fans out live messages, and resumes exactly after reconnect', async () => {
    await expect(publish('first')).resolves.toBe(1);
    await expect(publish('second')).resolves.toBe(2);

    const initial = await openSubscription(relayUrl, 0);
    expect(initial.frames.filter((frame) => frame.type === 'message').map((frame) => frame.seq)).toEqual([1, 2]);
    expect(initial.frames.find((frame) => frame.type === 'ready')?.head_seq).toBe(2);

    await expect(publish('third')).resolves.toBe(3);
    await waitForFrame(initial.frames, (frame) => frame.type === 'message' && frame.seq === 3, 'live sequence 3');
    await closeSocket(initial.socket);

    await expect(publish('fourth')).resolves.toBe(4);
    const resumed = await openSubscription(relayUrl, 3);
    expect(resumed.frames.filter((frame) => frame.type === 'message').map((frame) => frame.seq)).toEqual([4]);
    expect(resumed.frames.find((frame) => frame.type === 'ready')?.head_seq).toBe(4);
    await closeSocket(resumed.socket);
  }, 30_000);

  it('keeps a message after an arbitrary signer submits a one-ack receipt', async () => {
    const msgId = 'ab'.repeat(16);
    const sequence = await publish('receipt-retained', msgId);
    const receipt = buildSignedReceipt(
      generateIdentity(),
      Buffer.from(CONV_ID, 'hex'),
      Buffer.from(msgId, 'hex'),
      1,
    );

    const receiptResponse = await fetch(`${relayUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(receipt),
    });
    expect(receiptResponse.status).toBe(200);
    expect(await receiptResponse.json()).toMatchObject({
      recorded: true,
      deleted: false,
      receipts: 1,
      required_acks: 1,
    });

    const duplicate = await fetch(`${relayUrl}/v1/receipt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(receipt),
    });
    expect(await duplicate.json()).toMatchObject({ deleted: false, receipts: 1 });
    const forged = await fetch(`${relayUrl}/v1/receipt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...receipt, required_acks: 2 }),
    });
    expect(forged.status).toBe(401);

    const retained = await openSubscription(relayUrl, sequence - 1);
    const frame = await waitForFrame(
      retained.frames,
      (candidate) => candidate.type === 'message' && candidate.seq === sequence,
      'receipt-retained message replay',
    );
    expect(Buffer.from(String(frame.envelope_b64), 'base64').toString()).toBe('receipt-retained');
    await closeSocket(retained.socket);
  }, 30_000);

  it('counts concurrent Cloudflare postings with private totals and aggregate-only public stats', async () => {
    expect((await fetch(`${relayUrl}/v1/metrics`)).status).toBe(404);
    expect((await fetch(`${relayUrl}/v1/metrics`, { headers: { Authorization: 'Bearer wrong' } })).status).toBe(404);
    expect((await fetch(`${relayUrl}/v1/metrics`, { headers: { Authorization: 'local-metrics-test-token' } })).status).toBe(404);
    const getMetrics = async () => {
      const response = await fetch(`${relayUrl}/v1/metrics`, { headers: { Authorization: 'Bearer local-metrics-test-token' } });
      expect(response.status).toBe(200);
      expect(response.headers.get('Cache-Control')).toBe('no-store');
      return await response.json() as { traffic: Array<{ traffic: string; messages: number; active_conversations_7d: number }> };
    };
    const baseline = await getMetrics();
    const application = baseline.traffic.find(row => row.traffic === 'application');
    const probe = baseline.traffic.find(row => row.traffic === 'probe');
    const applicationMessages = (application?.messages ?? 0) + 16;
    const applicationConversations = (application?.active_conversations_7d ?? 0) + 16;
    const probeMessages = (probe?.messages ?? 0) + 1;
    const probeConversations = (probe?.active_conversations_7d ?? 0) + 1;
    // These conversations are unique to this test; earlier journeys may post freely.
    const rows = Array.from({ length: 16 }, (_, i) => (i + 100).toString(16).padStart(32, '0'));
    await Promise.all([...rows, 'fe'.repeat(16)].map(async conv_id => {
      const response = await fetch(`${relayUrl}/v1/send`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conv_id, envelope_b64: btoa('aggregate test') }),
      });
      expect(response.status).toBe(201);
    }));
    await expect.poll(async () => (await getMetrics()).traffic.find(x => x.traffic === 'application')?.messages, { timeout: 10_000 }).toBe(applicationMessages);
    await expect.poll(async () => (await getMetrics()).traffic.find(x => x.traffic === 'probe')?.messages, { timeout: 10_000 }).toBe(probeMessages);
    const result = await getMetrics();
    expect(result.traffic).toEqual(expect.arrayContaining([
      expect.objectContaining({ traffic: 'application', messages: applicationMessages, active_conversations_7d: applicationConversations }),
      expect.objectContaining({ traffic: 'probe', messages: probeMessages, active_conversations_7d: probeConversations }),
    ]));
    expect(JSON.stringify(result)).not.toContain(CONV_ID);
    const stats = await (await fetch(`${relayUrl}/v1/stats`)).json();
    expect(stats).toMatchObject({ active_conversations_7d: applicationConversations + probeConversations });
    expect(stats).not.toHaveProperty('traffic');
    expect((await fetch(`${relayUrl}/record`, { method: 'POST', body: '[]' })).status).toBe(404);
  }, 30_000);

  it('passes the external Python monitor encrypted live-delivery and reconnect/replay probe', async () => {
    const config = join(stateDir, 'monitor-config.json');
    writeFileSync(config, JSON.stringify({ relay_url: relayUrl, metrics_read_token: 'local-metrics-test-token' }), { mode: 0o600 });
    const { stdout, stderr } = await promisify(execFile)(process.env.QNTM_MONITOR_PYTHON || 'python3', [
      join(REPO_ROOT, 'monitoring/relay_monitor.py'), '--once', '--config', config,
      '--state-dir', join(stateDir, 'monitor-state'),
    ], { timeout: 40_000 });
    expect(stdout).toContain('qntm_relay_stats_scrape_success 1');
    expect(stdout, stderr).toContain('qntm_relay_probe_success 1');
    expect(stdout).toContain('qntm_relay_probe_last_success_timestamp_seconds');
    expect(stdout).not.toContain('local-metrics-test-token');
  }, 45_000);

  it('rejects malformed public keys and invalid challenge signatures', async () => {
    for (const key of ['aa'.repeat(16), 'aa'.repeat(32), `01${'00'.repeat(31)}`, '00'.repeat(32)]) {
      const frames: Array<{ type: string }> = [];
      const socket = new WebSocket(`${relayUrl.replace(/^http/, 'ws')}/v1/subscribe?conv_id=${CONV_ID}&pub_key=${key}`);
      socket.addEventListener('message', event => {
        const frame = JSON.parse(String(event.data));
        frames.push(frame);
        if (frame.type === 'auth_challenge') socket.send(JSON.stringify({ type: 'auth_response',
          signature_hex: key.startsWith('01') ? `01${'00'.repeat(63)}` : '00'.repeat(64) }));
      });
      await waitForFrame(frames, frame => frame.type === 'auth_failed', 'invalid authentication rejected');
      expect(frames.some(frame => frame.type === 'ready')).toBe(false);
      await closeSocket(socket);
    }
  }, 15_000);

  it('rejects identity-key receipt and announcement forgeries and weak posting keys', async () => {
    const identityKey = new Uint8Array([1, ...new Uint8Array(31)]);
    const forgedSignature = new Uint8Array([...identityKey, ...new Uint8Array(32)]);
    const post = (path: string, body: unknown) => fetch(`${relayUrl}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const receipt = buildSignedReceipt(generateIdentity(), Buffer.from(CONV_ID, 'hex'), Buffer.from('cd'.repeat(16), 'hex'), 1);
    const rejected = await post('/v1/receipt', { ...receipt,
      reader_ik_pk: base64UrlEncode(identityKey), reader_kid: Buffer.from(keyIDFromPublicKey(identityKey)).toString('hex'),
      sig: base64UrlEncode(forgedSignature),
    });
    expect(rejected.status).toBe(401);
    expect(await rejected.json()).toMatchObject({ error: 'invalid receipt signature' });
    const conv_id = 'e1'.repeat(16), posting = generateIdentity(), master = generateIdentity();
    const registration = { name: 'signature-profile', conv_id, master_pk: base64UrlEncode(identityKey),
      posting_pk: base64UrlEncode(posting.publicKey), sig: Buffer.from(forgedSignature).toString('hex') };
    expect((await post('/v1/announce/register', registration)).status).toBe(403);
    const suite = new QSP1Suite();
    const sign = (body: string) => Buffer.from(suite.sign(master.privateKey, suite.hash(new TextEncoder().encode(body)))).toString('hex');
    registration.master_pk = base64UrlEncode(master.publicKey);
    registration.posting_pk = base64UrlEncode(identityKey);
    registration.sig = sign(`qntm-announce-v1|register|${registration.name}|${conv_id}|${registration.posting_pk}`);
    expect((await post('/v1/announce/register', registration)).status).toBe(400);
    registration.posting_pk = base64UrlEncode(posting.publicKey);
    registration.sig = sign(`qntm-announce-v1|register|${registration.name}|${conv_id}|${registration.posting_pk}`);
    expect((await post('/v1/announce/register', registration)).status).toBe(201);
    const new_posting_pk = base64UrlEncode(identityKey);
    expect((await post('/v1/announce/rotate', { conv_id, master_pk: registration.master_pk, new_posting_pk,
      sig: sign(`qntm-announce-v1|rotate|${conv_id}|${new_posting_pk}`),
    })).status).toBe(400);
  });

  it('delivers a recipient-encrypted welcome through the ordinary group stream', async () => {
    const owner = generateIdentity(), contact = generateIdentity(), outsider = generateIdentity();
    const invite = createInvite(owner, 'group');
    const source = createConversation(invite, deriveConversationKeys(invite));
    const state = new GroupState();
    state.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Relay contact addition', '', owner, [])));
    source.participants = state.listMembers();
    const relay = new DropboxClient(relayUrl);
    const before = createMessage(owner, source, 'text', new TextEncoder().encode('before contact addition'));
    const added = prepareGroupAddition(owner, source, state, [contact.publicKey]);
    await relay.postMessage(source.id, marshalCanonical(before));
    await relay.postMessage(source.id, marshalCanonical(added.addition));
    await relay.postMessage(source.id, marshalCanonical(added.rekey));
    let senderState = createGroupSession(owner, source, state);
    const accepted = await relay.receiveMessages(source.id);
    for (const wire of accepted.messages) senderState = receiveGroupEvent(owner, deserializeEnvelope(wire), senderState).state;
    assertGroupAdditionAccepted(owner, senderState, added);
    const welcomeSequence = await relay.postMessage(source.id, marshalCanonical(added.welcomes[0]));
    expect(welcomeSequence).toBe(4);
    const link = createGroupLink({ conversationId: source.id, inviterPublicKey: owner.publicKey, relayUrl });
    const locator = parseGroupLink(link);
    const replay = await new DropboxClient(locator.relayUrl).receiveMessages(locator.conversationId);
    const welcomeWire = replay.messages.find(wire => isGroupWelcomeEnvelope(deserializeEnvelope(wire)))!;
    expect(Buffer.from(welcomeWire).toString('hex')).toBe(Buffer.from(marshalCanonical(added.welcomes[0])).toString('hex'));
    const joined = openGroupWelcome(contact, welcomeWire, locator);
    let contactState = createGroupSession(contact, joined.conversation, joined.state);
    expect(() => openGroupWelcome(outsider, welcomeWire, locator)).toThrow();
    expect(() => decryptMessage(deserializeEnvelope(replay.messages[0]), joined.conversation)).toThrow();
    const reply = createMessage(contact, joined.conversation, 'text', new TextEncoder().encode('joined from group link'));
    await relay.postMessage(joined.conversation.id, marshalCanonical(reply));
    const received = await relay.receiveMessages(source.id, replay.sequence);
    expect(received.messages).toHaveLength(1);
    const delivered = receiveGroupEvent(owner, deserializeEnvelope(received.messages[0]), senderState);
    senderState = delivered.state;
    expect(delivered.duplicate).toBe(false);
    if (delivered.duplicate) throw new Error('Expected new contact reply');
    const clear = delivered.message;
    expect(new TextDecoder().decode(clear.inner.body)).toBe('joined from group link');
    expect(clear.inner.sender_ik_pk).toEqual(contact.publicKey);
    const removal = createGroupControlMessage(owner, added.conversation, 'group_remove', createGroupRemoveBody([contact.keyID]));
    const remaining = new GroupState(); remaining.applyGenesis(added.state.snapshot());
    remaining.applyRemove({ removed_at: Math.floor(Date.now() / 1000), removed_members: [contact.keyID], reason: '' });
    const rekey = createGroupControlMessage(owner, added.conversation, 'group_rekey', createRekey(owner, added.conversation, remaining).bodyBytes);
    await relay.postMessage(source.id, marshalCanonical(removal));
    await relay.postMessage(source.id, marshalCanonical(rekey));
    // Reconnect from a persisted checkpoint and process the same relay controls
    // as the continuing member. The removed receiver must retain only old keys.
    contactState = restoreGroupSession(contact, JSON.parse(JSON.stringify(contactState)));
    const afterRestart = await relay.receiveMessages(source.id, received.sequence);
    for (const wire of afterRestart.messages) {
      const envelope = deserializeEnvelope(wire);
      senderState = receiveGroupEvent(owner, envelope, senderState).state;
      contactState = receiveGroupEvent(contact, envelope, contactState).state;
    }
    expect(contactState.removed).toBe(true);
    expect(() => assertGroupCanSend(contact, contactState)).toThrow('removed');
    const continuing = receiveGroupEvent(owner, rekey, senderState).conversation;
    const privateMessage = createMessage(owner, continuing, 'text', new TextEncoder().encode('after contact removal'));
    await relay.postMessage(source.id, marshalCanonical(privateMessage));
    const future = await relay.receiveMessages(source.id, afterRestart.sequence);
    expect(future.messages).toHaveLength(1);
    expect(() => receiveGroupEvent(contact, deserializeEnvelope(future.messages[0]), contactState)).toThrow();
  }, 30_000);

  it('runs contact addition through fresh Python CLI processes and a TypeScript peer', async () => {
    const contact = generateIdentity();
    const python = process.env.QNTM_MONITOR_PYTHON || 'python3';
    const invoke = async (phase: string, extra: string) => {
      const { stdout } = await promisify(execFile)(python, [join(REPO_ROOT, 'python-dist/tests/group_cli_peer.py'),
        phase, relayUrl, stateDir, extra], { timeout: 45_000,
        env: { ...process.env, PYTHONPATH: join(REPO_ROOT, 'python-dist/src') } });
      return JSON.parse(stdout);
    };
    const prepared = await invoke('prepare', Buffer.from(contact.publicKey).toString('hex'));
    const locator = parseGroupLink(prepared.group_link);
    const relay = new DropboxClient(locator.relayUrl);
    const replay = await relay.receiveMessages(locator.conversationId);
    const welcome = replay.entries.find(row => isGroupWelcomeEnvelope(deserializeEnvelope(row.envelope)))!;
    const joined = openGroupWelcome(contact, welcome.envelope, locator);
    let checkpoint = checkGroupWelcomeReplay(groupSessionFromWelcome(contact, joined, welcome.seq), joined, replay.sequence, replay.entries);
    assertGroupCanSend(contact, checkpoint);
    expect(() => decryptMessage(deserializeEnvelope(replay.messages[1]), joined.conversation)).toThrow();
    const refreshed = await invoke('refresh', prepared.conversation_id);
    expect(refreshed).toMatchObject({ group_link: prepared.group_link, epoch: 1 });
    const refreshReplay = await relay.receiveMessages(locator.conversationId, replay.sequence);
    expect(refreshReplay.messages).toHaveLength(1);
    const refreshedWelcome = openGroupWelcome(contact, refreshReplay.messages[0], locator);
    expect(refreshedWelcome.purpose).toBe('renewal');
    expect(refreshedWelcome.admissions).toEqual(joined.admissions);
    expect(refreshedWelcome.conversation.keys).toEqual(joined.conversation.keys);
    const reply = createMessage(contact, joined.conversation, 'text', new TextEncoder().encode('TypeScript contact reply'));
    await relay.postMessage(locator.conversationId, marshalCanonical(reply));
    const finished = await invoke('finish', prepared.conversation_id);
    expect(finished).toMatchObject({ received_reply: true, epoch: 2 });
    checkpoint = restoreGroupSession(contact, JSON.parse(JSON.stringify(checkpoint)));
    const changes = await relay.receiveMessages(locator.conversationId, replay.sequence);
    checkpoint = checkGroupReplayCoverage(checkpoint, replay.sequence, changes.sequence, changes.entries.map(row => row.seq));
    for (const row of changes.entries) checkpoint = checkGroupUnverifiableEpoch(checkpoint, deserializeEnvelope(row.envelope), row.seq);
    let sawExcludedMessage = false;
    for (const wire of changes.messages) {
      const envelope = deserializeEnvelope(wire);
      if (isGroupWelcomeEnvelope(envelope)) {
        // Recipient-box messages use the welcome parser, not group decryption.
        expect(openGroupWelcome(contact, wire, locator).purpose).toBe('renewal');
        continue;
      }
      if (Buffer.from(envelope.msg_id).toString('hex') === finished.future_message_id) {
        expect(() => receiveGroupEvent(contact, envelope, checkpoint)).toThrow();
        sawExcludedMessage = true;
      } else checkpoint = receiveGroupEvent(contact, envelope, checkpoint).state;
    }
    expect(sawExcludedMessage).toBe(true);
    expect(checkpoint.removed).toBe(true);
  }, 90_000);

  for (const surface of ['CLI', 'MCP']) for (const stale of ['expired', 'rotated']) {
    it(`recovers ${stale} generic founder refresh through fresh ${surface} processes and a lost ACK`, async () => {
      type Journal = { kind: string; controls: string[]; welcomes: string[]; welcomes_sent: number;
        recipient?: string; recovery_challenge?: string; expected: GroupSessionState;
        superseded_operations?: Array<Record<string, unknown>> };
      type RecordState = { id: string; group_session: GroupSessionState; group_operation?: Journal };
      const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
      const profile = join(stateDir, `${surface.toLowerCase()}-${stale}-generic-refresh`);
      const python = process.env.QNTM_MONITOR_PYTHON || 'python3';
      const env = { ...process.env, PYTHONPATH: join(REPO_ROOT, 'python-dist/src') };
      const readRecord = (id: string): RecordState => JSON.parse(readFileSync(join(profile, 'conversations.json'), 'utf8'))
        .find((record: RecordState) => record.id === id);
      const beforePost: Journal[] = [];
      let capture = false;
      const proxy = await recordingRelay(relayUrl, { onSend(send) {
        if (capture) beforePost.push(structuredClone(readRecord(send.conv_id).group_operation!));
      } });
      const command = async (...args: string[]) => {
        const { stdout } = await promisify(execFile)(python, ['-m', 'qntm.cli', '--config-dir', profile,
          '--dropbox-url', proxy.url, ...args], { env, timeout: 30_000, maxBuffer: 1024 * 1024 });
        const result = JSON.parse(stdout);
        if (!result.ok) throw new Error(JSON.stringify(result));
        return result.data;
      };
      const retry = async (id: string): Promise<Record<string, unknown>> => {
        if (surface === 'CLI') return command('group', 'retry', id);
        const client = new Client({ name: 'fresh-generic-refresh-retry', version: '1' });
        try {
          await client.connect(new StdioClientTransport({ command: python, args: ['-m', 'qntm.mcp_server'],
            env: { ...Object.fromEntries(Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
              QNTM_CONFIG_DIR: profile, QNTM_RELAY_URL: proxy.url }, stderr: 'pipe' }));
          const response = await client.callTool({ name: 'group_retry', arguments: { conversation: id } });
          const result = response.structuredContent as Record<string, unknown>
            ?? JSON.parse((response.content as Array<{ text: string }>)[0].text);
          if (response.isError || result.error) throw new Error(JSON.stringify(result));
          return result;
        } finally { await client.close(); }
      };
      try {
        const issuer = await command('identity', 'generate');
        const issuerKey = Buffer.from(issuer.public_key, 'base64url');
        const founder = generateIdentity();
        const invite = createInvite(founder, 'group');
        const conversation = createConversation(invite, deriveConversationKeys(invite));
        const genesisBody = createGroupGenesisBody(`${surface} ${stale} founder refresh`, '', founder, []);
        const group = new GroupState(); group.applyGenesis(parseGroupGenesisBody(genesisBody));
        conversation.participants = group.listMembers();
        let founderState = createGroupSession(founder, conversation, group);
        const oldRoot = founderState.root, id = hex(conversation.id);
        const transport = new DropboxClient(proxy.url);
        const genesis = createGroupControlMessage(founder, conversation, 'group_genesis', genesisBody);
        const genesisSeq = await transport.postMessage(conversation.id, serializeEnvelope(genesis));
        const oldMessage = createMessage(founder, conversation, 'text', new TextEncoder().encode('history before Python admission'));
        const oldMessageSeq = await transport.postMessage(conversation.id, serializeEnvelope(oldMessage));
        founderState = receiveGroupEvent(founder, oldMessage, founderState).state;
        expect(oldMessageSeq).toBe(genesisSeq + 1);
        const addition = prepareGroupSessionAddition(founder, founderState, [issuerKey], undefined, undefined, oldMessageSeq);
        for (const envelope of [addition.addition, addition.rekey]) {
          await transport.postMessage(conversation.id, serializeEnvelope(envelope));
          founderState = receiveGroupEvent(founder, envelope, founderState).state;
        }
        assertGroupAdditionAccepted(founder, founderState, addition);
        await transport.postMessage(conversation.id, serializeEnvelope(addition.welcomes[0]));
        await command('convo', 'join', createGroupLink({ conversationId: conversation.id, inviterPublicKey: founder.publicKey, relayUrl: proxy.url }));
        expect(readRecord(id).group_session.admissions[hex(founder.keyID)]).toBeUndefined();
        expect(readRecord(id).group_session.admissions[issuer.key_id].completion).not.toBeNull();
        const challenge = new Uint8Array(32).fill(stale === 'expired' ? 41 : 42);
        // Legacy journals authenticate their missing recipient/challenge from
        // the original sender-encrypted box, without inventing membership.
        const shape = stale === 'expired' ? 'current' : 'legacy';
        const staged = await promisify(execFile)(python, [join(REPO_ROOT, 'integration/src/stage-generic-refresh.py'),
          profile, proxy.url, id, hex(founder.publicKey), hex(challenge), shape], { env, timeout: 30_000 });
        const stage = JSON.parse(staged.stdout) as { expires_at: number; cursor: number; epoch: number };
        const original = readRecord(id).group_operation!;
        expect(original).toMatchObject({ kind: 'refresh', controls: [], welcomes_sent: 0 });
        expect(original.recipient).toBe(shape === 'current' ? hex(founder.publicKey) : undefined);
        const locator = parseGroupLink(createGroupLink({ conversationId: conversation.id, inviterPublicKey: issuerKey, relayUrl: proxy.url }));
        const originalWelcome = openGroupWelcome(founder, Buffer.from(original.welcomes[0], 'base64'), locator);
        expect(originalWelcome.purpose).toBe('refresh');
        expect(originalWelcome.replayFromSequence).toBe(stage.cursor);
        const previousRoot = founderState.root;
        let anchor = stage.cursor;
        if (stale === 'expired') {
          const wait = Math.max(0, stage.expires_at * 1000 - Date.now() + 1100);
          expect(wait).toBeLessThanOrEqual(10_000);
          await delay(wait);
          expect(Math.floor(Date.now() / 1000)).toBeGreaterThan(stage.expires_at);
        } else {
          const rotation = prepareGroupSessionRekey(founder, founderState);
          anchor = await transport.postMessage(conversation.id, serializeEnvelope(rotation.rekey));
          founderState = receiveGroupEvent(founder, rotation.rekey, founderState).state;
        }

        const beforeRetry = proxy.sends.length;
        capture = true;
        proxy.loseNextSendAcknowledgement({ pauseReplay: true });
        await expect(retry(id)).rejects.toThrow();
        capture = false;
        expect(proxy.droppedAcknowledgements).toBe(1);
        expect(proxy.blockedReplays).toBeGreaterThan(0);
        expect(proxy.sends.slice(beforeRetry)).toHaveLength(1);
        const pending = readRecord(id).group_operation!;
        expect(pending).toMatchObject({ kind: 'refresh', controls: [], welcomes_sent: 0,
          recipient: hex(founder.publicKey), recovery_challenge: hex(challenge) });
        expect(pending.welcomes).toEqual([proxy.sends.at(-1)!.envelope_b64]);
        expect(pending.welcomes).not.toEqual(original.welcomes);
        expect(beforePost).toEqual([pending]); // Exact old wire was saved before the replacement POST.
        expect(pending.superseded_operations).toEqual([{ kind: 'refresh', controls: [],
          welcomes: original.welcomes, welcomes_sent: 0, delivery: 'unknown' }]);
        expect(pending.expected.root).toBe(founderState.root);
        expect(readRecord(id).group_session.root).toBe(founderState.root);
        expect(pending).not.toHaveProperty('admission');
        expect(pending).not.toHaveProperty('origin');

        proxy.resumeReplay();
        capture = true;
        const result = await retry(id);
        capture = false;
        expect(result.current_epoch).toBe(stale === 'rotated' ? 2 : 1);
        expect(readRecord(id).group_operation).toBeUndefined();
        expect(proxy.sends.slice(beforeRetry).map(send => send.envelope_b64)).toEqual([pending.welcomes[0], pending.welcomes[0]]);
        expect(beforePost).toEqual([pending, pending]); // A fresh process retries the same wire, without resealing.
        const replay = await transport.receiveMessages(conversation.id);
        const renewedWire = Buffer.from(pending.welcomes[0], 'base64');
        const matches = replay.entries.filter(row => Buffer.from(row.envelope).equals(renewedWire));
        expect(matches).toHaveLength(1); // Two exact attempts, one real relay effect.
        expect(replay.entries.some(row => Buffer.from(row.envelope).toString('base64') === original.welcomes[0])).toBe(false);
        const row = matches[0];
        expect(row.seq).toBe(anchor + 1);
        const welcome = openGroupWelcome(founder, row.envelope, locator);
        expect(welcome.purpose).toBe('refresh');
        expect(hex(welcome.recoveryChallenge!)).toBe(hex(challenge));
        expect(welcome.replayFromSequence).toBe(anchor);
        expect(welcome.admissions[hex(founder.keyID)]).toBeUndefined();
        expect(welcome.admissions).toEqual(founderState.admissions);
        const fresh = checkGroupWelcomeReplay(groupSessionFromWelcome(founder, welcome, row.seq), welcome, replay.sequence, replay.entries);
        assertGroupCanSend(founder, fresh);
        expect(fresh).toMatchObject({ root: founderState.root, epoch: founderState.epoch, rekeys: [] });
        expect(JSON.stringify(fresh)).not.toContain(oldRoot);
        if (stale === 'rotated') expect(JSON.stringify(fresh)).not.toContain(previousRoot);
        expect(() => decryptMessage(oldMessage, groupSessionConversation(fresh))).toThrow();
        const text = `${surface} ${stale} founder recovered reply`;
        await transport.postMessage(conversation.id, serializeEnvelope(createMessage(founder, groupSessionConversation(fresh), 'text', new TextEncoder().encode(text))));
        const received = await command('recv', id);
        expect(received.messages.filter((message: { unsafe_body?: string }) => message.unsafe_body === text)).toHaveLength(1);
        writeFileSync(join(artifactDir, `${surface.toLowerCase()}-${stale}-generic-refresh.json`), JSON.stringify({
          conversation: id, surface, stale, journalShape: shape,
          originalWelcome: hex(deserializeEnvelope(Buffer.from(original.welcomes[0], 'base64')).msg_id),
          replacementWelcome: hex(deserializeEnvelope(renewedWire).msg_id),
          replacementAttempts: 2, replacementEffects: matches.length, evidenceRecordsBeforePost: pending.superseded_operations!.length,
          lostAcknowledgements: proxy.droppedAcknowledgements, blockedReplays: proxy.blockedReplays,
          purpose: welcome.purpose, currentEpoch: fresh.epoch, replayAnchor: welcome.replayFromSequence,
          replaySequences: replay.entries.map(entry => entry.seq), receivedReply: true,
        }, null, 2));
      } finally { await proxy.stop(); }
    }, 90_000);
  }

  it('posts exactly once across the native runtime idle-connection boundary', async () => {
    // Send-time alignment deliberately exercises KJ's 5-second idle boundary.
    // Waiting five seconds *after* responses would miss the stale-socket race.
    const start = performance.now() + 150;
    const outcomes: Array<{ lane: number; round: number; sentAtMs: number; status: number; body: string; cause?: unknown }> = [];
    const conversations = Array.from({ length: 32 }, () => generateIdentity().keyID);
    await Promise.all(conversations.map(async (cid, lane) => {
      for (let round = 0; round < 5; round++) {
        await delay(Math.max(0, start + round * 5_000 + lane * 3 - performance.now()));
        const sentAtMs = performance.now() - start;
        try {
          const response = await fetch(`${relayUrl}/v1/send`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            signal: AbortSignal.timeout(5_000),
            body: JSON.stringify({ conv_id: Buffer.from(cid).toString('hex'),
              envelope_b64: Buffer.from(`idle-boundary-${round}`).toString('base64') }),
          });
          outcomes.push({ lane, round, sentAtMs, status: response.status, body: await response.text() });
        } catch (error) {
          // Await every lane before teardown, even if one transport fails.
          const cause = error instanceof Error ? error.cause : undefined;
          outcomes.push({ lane, round, sentAtMs, status: 0, body: String(error),
            cause: cause instanceof Error ? { name: cause.name, message: cause.message,
              ...Object.fromEntries(Object.entries(cause)) } : cause });
        }
      }
    }));
    writeFileSync(join(artifactDir, 'idle-boundary.json'), JSON.stringify(outcomes, null, 2));
    // Replayed bytes and sequence numbers prove that the fixture did not hide
    // an uncertain POST by resubmitting it or inventing a successful response.
    const relay = new DropboxClient(relayUrl);
    const replays = [];
    for (const cid of conversations) {
      const replay = await relay.receiveMessages(cid);
      replays.push({ conversation: Buffer.from(cid).toString('hex'), sequence: replay.sequence,
        entries: replay.entries.map(row => ({ seq: row.seq, body: Buffer.from(row.envelope).toString() })) });
    }
    writeFileSync(join(artifactDir, 'idle-boundary-replay.json'), JSON.stringify({ node: process.version, outcomes, replays }, null, 2));
    expect(outcomes.filter(row => row.status !== 201)).toEqual([]);
    for (const row of outcomes) expect(JSON.parse(row.body).seq).toBe(row.round + 1);
    for (const replay of replays) {
      expect(replay.sequence).toBe(5);
      expect(replay.entries).toEqual(Array.from({ length: 5 }, (_, round) => ({ seq: round + 1, body: `idle-boundary-${round}` })));
    }
  }, 45_000);

  it('preserves committed relay content and sequence through a process restart', async () => {
    const cid = generateIdentity().keyID;
    const relay = new DropboxClient(relayUrl);
    const before = new Uint8Array([101, 102]), after = new Uint8Array([103, 104]);
    expect(await relay.postMessage(cid, before)).toBe(1);
    await relayProcess!.restart();
    expect(await relayProcess!.waitForLocalUrl('worker', '/healthz')).toBe(relayUrl);
    const recovered = await relay.receiveMessages(cid);
    expect(recovered.sequence).toBe(1);
    expect(recovered.messages.map(bytes => Array.from(bytes))).toEqual([[101, 102]]);
    expect(await relay.postMessage(cid, after)).toBe(2);
    const resumed = await relay.receiveMessages(cid, recovered.sequence);
    expect(resumed.sequence).toBe(2);
    expect(resumed.messages.map(bytes => Array.from(bytes))).toEqual([[103, 104]]);
  }, 30_000);

  it('recovers a TypeScript member through a fresh CLI welcome after real relay retention', async () => {
    const peer = generateIdentity();
    const profileDir = join(stateDir, 'retention-recovery');
    const invoke = async (phase: string, extra: string, ...args: string[]) => {
      const { stdout } = await promisify(execFile)(process.env.QNTM_MONITOR_PYTHON || 'python3', [
        join(REPO_ROOT, 'python-dist/tests/group_cli_peer.py'), phase, relayUrl, profileDir, extra, ...args,
      ], { timeout: 45_000, env: { ...process.env, PYTHONPATH: join(REPO_ROOT, 'python-dist/src') } });
      return JSON.parse(stdout);
    };
    const prepared = await invoke('prepare', Buffer.from(peer.publicKey).toString('hex'));
    const locator = parseGroupLink(prepared.group_link), relay = new DropboxClient(relayUrl);
    const replay = await relay.receiveMessages(locator.conversationId);
    const welcomeRow = replay.entries.find(row => isGroupWelcomeEnvelope(deserializeEnvelope(row.envelope)))!;
    const welcome = openGroupWelcome(peer, welcomeRow.envelope, locator);
    const initial = checkGroupWelcomeReplay(groupSessionFromWelcome(peer, welcome, welcomeRow.seq), welcome, replay.sequence, replay.entries);
    assertGroupCanSend(peer, initial);
    const missed = await invoke('missed', prepared.conversation_id);
    await delay(65_000); // Actual Worker retention and alarm, not a mocked clock.
    const expired = await relay.receiveMessages(locator.conversationId, replay.sequence);
    expect(expired.messages).toEqual([]);
    expect(expired.sequence).toBe(missed.sequence);
    const blocked = checkGroupReplayCoverage(initial, replay.sequence, expired.sequence, []);
    expect(() => assertGroupCanSend(peer, blocked)).toThrow('incomplete');
    await invoke('refresh', prepared.conversation_id, blocked.recovery!.challenge);
    const fresh = await relay.receiveMessages(locator.conversationId, expired.sequence);
    expect(fresh.messages).toHaveLength(1);
    const opened = openGroupWelcome(peer, fresh.messages[0], locator);
    const recovered = checkGroupWelcomeReplay(groupSessionFromWelcome(peer, opened, fresh.entries[0].seq,
      restoreGroupSession(peer, JSON.parse(JSON.stringify(blocked)))), opened, fresh.sequence, fresh.entries);
    assertGroupCanSend(peer, recovered);
    expect(recovered.root).toBe(initial.root);
    const reply = createMessage(peer, opened.conversation, 'text', new TextEncoder().encode('TypeScript contact reply'));
    await relay.postMessage(locator.conversationId, marshalCanonical(reply));
    expect((await invoke('finish', prepared.conversation_id)).received_reply).toBe(true);
  }, 180_000);

  it('expires SQLite content and receipt metadata by alarm while the channel is idle', async () => {
    const msgId = 'cd'.repeat(16);
    const sequence = await publish('idle-expiry', msgId);
    const receipt = buildSignedReceipt(
      generateIdentity(), Buffer.from(CONV_ID, 'hex'), Buffer.from(msgId, 'hex'), 1,
    );
    const record = await fetch(`${relayUrl}/v1/receipt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(receipt),
    });
    expect(record.status).toBe(200);

    function storedRows(): { messages: number; metadata: number } {
      const paths = readdirSync(stateDir, { recursive: true }) as string[];
      const databases = paths.filter((path) => path.endsWith('.sqlite'));
      let found = false;
      let messages = 0;
      let metadata = 0;
      for (const path of databases) {
        const db = new DatabaseSync(join(stateDir, path), { readOnly: true });
        try {
          const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'messages'").all();
          if (!tables.length) continue;
          found = true;
          const assigned = db.prepare('SELECT expires_at - created_at AS ttl FROM messages').all();
          for (const row of assigned) expect(row.ttl, 'local test TTL override').toBe(60);
          messages += Number(db.prepare('SELECT COUNT(*) AS n FROM messages').get()!.n);
          metadata += Number(db.prepare('SELECT COUNT(*) AS n FROM message_metadata').get()!.n);
        } finally {
          db.close();
        }
      }
      expect(found, 'local relay SQLite database exists').toBe(true);
      return { messages, metadata };
    }

    expect(storedRows().messages).toBeGreaterThan(0);
    expect(storedRows().metadata).toBeGreaterThan(0);
    // No request or publish wakes the DO during this interval. Inspect only the
    // disposable local database, so an on-read sweep cannot make this test pass.
    await delay(62_000);
    expect(storedRows(), `${relayProcess?.stdout}\n${relayProcess?.stderr}`).toEqual({ messages: 0, metadata: 0 });

    const replay = await openSubscription(relayUrl, 0);
    expect(replay.frames.filter((frame) => frame.type === 'message')).toEqual([]);
    expect(replay.frames.find((frame) => frame.type === 'ready')?.head_seq).toBe(sequence);
    await closeSocket(replay.socket);
    const expiredReceipt = await fetch(`${relayUrl}/v1/receipt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(receipt),
    });
    expect(expiredReceipt.status).toBe(404);
  }, 75_000);
});
