import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSignedReceipt, generateIdentity } from '@corpollc/qntm';
import { ManagedProcess, waitForHttp } from './src/runtime.js';

interface RelayFrame {
  type: string;
  seq?: number;
  head_seq?: number;
  envelope_b64?: string;
}

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CONV_ID = '0123456789abcdef0123456789abcdef';

async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolvePort, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to allocate port'));
        return;
      }
      server.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

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
    const relayPort = await getFreePort();
    const inspectorPort = await getFreePort();
    relayUrl = `http://127.0.0.1:${relayPort}`;
    stateDir = mkdtempSync(join(tmpdir(), 'qntm-relay-acceptance-'));
    relayProcess = new ManagedProcess(
      'relay-acceptance',
      [
        process.platform === 'win32' ? 'npx.cmd' : 'npx',
        'wrangler', 'dev', '--local',
        '--port', String(relayPort),
        '--ip', '127.0.0.1',
        '--inspector-port', String(inspectorPort),
        '--persist-to', stateDir,
        '--var', 'RATE_LIMIT_PER_MIN:5000',
      ],
      join(REPO_ROOT, 'worker'),
      { ...process.env },
    );
    await waitForHttp(`${relayUrl}/healthz`);
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
});
