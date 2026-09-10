import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSignedReceipt, generateIdentity, base64UrlEncode, keyIDFromPublicKey, QSP1Suite } from '@corpollc/qntm';
import { ManagedProcess, workerTestEnv } from './src/runtime.js';

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

  beforeAll(async () => {
    stateDir = mkdtempSync(join(tmpdir(), 'qntm-relay-acceptance-'));
    relayProcess = new ManagedProcess(
      'relay-acceptance',
      [
        process.platform === 'win32' ? 'npx.cmd' : 'npx',
        'wrangler', 'dev', '--local',
        '--name', basename(stateDir).toLowerCase(),
        '--port', '0',
        '--ip', '127.0.0.1',
        '--inspector-port', '0',
        '--persist-to', stateDir,
        '--var', 'RATE_LIMIT_PER_MIN:5000',
        '--var', 'ENVELOPE_TTL_SECONDS:60',
        '--var', 'METRICS_READ_TOKEN:local-metrics-test-token',
        '--var', `MONITOR_CONVERSATION_ID:${'fe'.repeat(16)}`,
      ],
      join(REPO_ROOT, 'worker'),
      workerTestEnv(stateDir),
    );
    relayUrl = await relayProcess.waitForLocalUrl('worker', '/healthz');
  }, 60_000);

  afterAll(async () => {
    if (relayProcess) await relayProcess.stop();
    if (stateDir) rmSync(stateDir, { recursive: true, force: true });
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
    // Previous tests have posted exactly five envelopes to the same conversation.
    const rows = Array.from({ length: 16 }, (_, i) => (i + 100).toString(16).padStart(32, '0'));
    await Promise.all([...rows, 'fe'.repeat(16)].map(async conv_id => {
      const response = await fetch(`${relayUrl}/v1/send`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conv_id, envelope_b64: btoa('aggregate test') }),
      });
      expect(response.status).toBe(201);
    }));
    await expect.poll(async () => (await getMetrics()).traffic.find(x => x.traffic === 'application')?.messages, { timeout: 10_000 }).toBe(21);
    const result = await getMetrics();
    expect(result.traffic).toEqual(expect.arrayContaining([
      expect.objectContaining({ traffic: 'application', messages: 21, active_conversations_7d: 17 }),
      expect.objectContaining({ traffic: 'probe', messages: 1, active_conversations_7d: 1 }),
    ]));
    expect(JSON.stringify(result)).not.toContain(CONV_ID);
    const stats = await (await fetch(`${relayUrl}/v1/stats`)).json();
    expect(stats).toMatchObject({ active_conversations_7d: 18 });
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
