import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import diagnostics from 'node:diagnostics_channel';
import { connect as connectTcp, type Socket as TcpSocket } from 'node:net';
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
  groupSessionFromWelcome, checkGroupReplayCoverage, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch, checkExpiredGroupControl,
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

interface RawCloseHandshake {
  extensions: string | null;
  frames: RelayFrame[];
  close: { code: number; reason: string } | null;
  finAfterClose: boolean;
  bytesAfterClose: number;
}

/** Subscribe over a raw TCP WebSocket with no extensions requested, send a
 * masked Close after the ready frame, and parse exactly what the relay sends
 * back. This observes wire bytes directly and shares nothing with undici's
 * asynchronous permessage-deflate inflate, which can report 1006 for a Close
 * frame that did arrive. Resolves on the relay's FIN, or rejects on timeout,
 * socket error, TCP close without a Close frame, or a malformed frame. */
function rawCloseHandshake(
  relayUrl: string, convId: string, code: number, reason: string, timeoutMs = 10_000,
): Promise<RawCloseHandshake> {
  const url = new URL(relayUrl);
  const key = btoa(String.fromCharCode(...randomBytes(16)));
  const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  const result: RawCloseHandshake = { extensions: null, frames: [], close: null, finAfterClose: false, bytesAfterClose: 0 };
  return new Promise<RawCloseHandshake>((resolvePromise, rejectPromise) => {
    const socket = connectTcp({ host: url.hostname, port: Number(url.port) });
    let buffer = Buffer.alloc(0), upgraded = false, closeSent = false, settled = false;
    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) rejectPromise(Object.assign(error, { handshake: result }));
      else resolvePromise(result);
    };
    const timer = setTimeout(() => settle(new Error(`raw close handshake timed out: ${JSON.stringify(result)}`)), timeoutMs);
    const sendClose = () => {
      const payload = Buffer.concat([Buffer.from([code >> 8, code & 0xff]), Buffer.from(reason, 'utf8')]);
      const mask = randomBytes(4);
      const masked = Buffer.from(payload.map((byte: number, index: number) => byte ^ mask[index % 4]!));
      socket.write(Buffer.concat([Buffer.from([0x88, 0x80 | payload.length]), mask, masked]));
      closeSent = true;
    };
    const parse = () => {
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const head = buffer.subarray(0, end).toString();
        buffer = buffer.subarray(end + 4);
        if (!head.startsWith('HTTP/1.1 101 ')) return settle(new Error(`upgrade rejected: ${head.split('\r\n')[0]}`));
        if (/^sec-websocket-accept:\s*(.+?)\s*$/im.exec(head)?.[1] !== accept) return settle(new Error('bad Sec-WebSocket-Accept'));
        result.extensions = /^sec-websocket-extensions:\s*(.*?)\s*$/im.exec(head)?.[1] ?? null;
        upgraded = true;
      }
      while (!settled) {
        if (result.close) { result.bytesAfterClose += buffer.length; buffer = Buffer.alloc(0); return; }
        if (buffer.length < 2) return;
        if ((buffer[0]! & 0xf0) !== 0x80) return settle(new Error('unexpected fragmented or extension frame'));
        const opcode = buffer[0]! & 0x0f;
        if (buffer[1]! & 0x80) return settle(new Error('relay sent a masked frame'));
        let length = buffer[1]! & 0x7f, offset = 2;
        if (length === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4; }
        else if (length === 127) return settle(new Error('unexpected 64-bit frame length'));
        if (buffer.length < offset + length) return;
        const payload = buffer.subarray(offset, offset + length);
        buffer = buffer.subarray(offset + length);
        if (opcode === 0x1) {
          const frame = JSON.parse(payload.toString('utf8')) as RelayFrame;
          result.frames.push(frame);
          if (frame.type === 'ready' && !closeSent) sendClose();
        } else if (opcode === 0x8) {
          if (!closeSent) return settle(new Error(`relay closed first: ${payload.toString('hex')}`));
          result.close = { code: payload.length >= 2 ? payload.readUInt16BE(0) : 1005, reason: payload.subarray(2).toString('utf8') };
        } else if (opcode !== 0x9 && opcode !== 0xa) {
          return settle(new Error(`unexpected opcode ${opcode}`));
        }
      }
    };
    socket.once('connect', () => {
      socket.write(`GET /v1/subscribe?conv_id=${convId}&from_seq=0 HTTP/1.1\r\nHost: ${url.host}\r\n` +
        `Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    socket.on('data', (chunk: Buffer) => {
      try { buffer = Buffer.concat([buffer, chunk]); parse(); }
      catch (error) { settle(error instanceof Error ? error : new Error(String(error))); }
    });
    socket.on('end', () => {
      result.finAfterClose = result.close !== null;
      settle(result.close ? undefined : new Error(`relay sent FIN without a Close frame: ${JSON.stringify(result)}`));
    });
    socket.on('error', error => settle(error));
    socket.on('close', () => settle(new Error(`socket closed before the relay's FIN: ${JSON.stringify(result)}`)));
  });
}

interface TransportWitnessRecord {
  socket: number | null;
  reused: boolean | null;
  socketIdleMs: number | null;
  wroteHeadersAtMs: number | null;
  headersAtMs: number | null;
  completedAtMs: number | null;
  transportError: { name: string; code?: string; message: string } | null;
}

/** Attribute each tagged fetch to the undici socket that carried it, using
 * Node's undici diagnostics channels. Records whether the socket was reused,
 * how long it had been idle since its previous completed response, when the
 * response headers and trailers arrived, connection opens/closes, and stalls
 * of this process's event loop. This observes the maintained client's real
 * transport without changing it, so a failed POST can be attributed to a
 * stale reused socket, a slow relay, or a client-side stall from timestamps
 * rather than inferred. */
function transportWitness(tagHeader: string, start: number) {
  const now = () => Number((performance.now() - start).toFixed(3));
  const records = new Map<string, TransportWitnessRecord>();
  const byRequest = new WeakMap<object, { tag: string; socket: TcpSocket }>();
  const socketIds = new WeakMap<TcpSocket, number>();
  const socketLastCompletedAt = new WeakMap<TcpSocket, number>();
  const events: Array<Record<string, unknown>> = [];
  let socketCount = 0;
  const socketId = (socket: TcpSocket) => {
    let id = socketIds.get(socket);
    if (id === undefined) {
      id = ++socketCount;
      socketIds.set(socket, id);
      socket.once('close', hadError => events.push({ atMs: now(), event: 'socketClosed', socket: id, hadError,
        bytesWritten: socket.bytesWritten, bytesRead: socket.bytesRead }));
    }
    return id;
  };
  const record = (request: object) => {
    const key = byRequest.get(request);
    return key ? { key, row: records.get(key.tag)! } : null;
  };
  const tagPattern = new RegExp(`^${tagHeader}: (\\S+)$`, 'im');
  const subscriptions: Array<[string, (message: unknown) => void]> = [
    ['undici:client:connected', message => {
      const { socket } = message as { socket: TcpSocket };
      events.push({ atMs: now(), event: 'connected', socket: socketId(socket) });
    }],
    ['undici:client:connectError', message => {
      const { error } = message as { error: Error };
      events.push({ atMs: now(), event: 'connectError', message: error.message });
    }],
    ['undici:client:sendHeaders', message => {
      const { request, headers, socket } = message as { request: object; headers: string; socket: TcpSocket };
      const tag = tagPattern.exec(headers)?.[1];
      if (!tag) return;
      const lastCompleted = socketLastCompletedAt.get(socket);
      byRequest.set(request, { tag, socket });
      records.set(tag, { socket: socketId(socket), reused: socket.bytesWritten > 0,
        socketIdleMs: lastCompleted === undefined ? null : Number((now() - lastCompleted).toFixed(3)),
        wroteHeadersAtMs: now(), headersAtMs: null, completedAtMs: null, transportError: null });
    }],
    ['undici:request:headers', message => {
      const found = record((message as { request: object }).request);
      if (found) found.row.headersAtMs = now();
    }],
    ['undici:request:trailers', message => {
      const found = record((message as { request: object }).request);
      if (!found) return;
      found.row.completedAtMs = now();
      socketLastCompletedAt.set(found.key.socket, found.row.completedAtMs);
    }],
    ['undici:request:error', message => {
      const { request, error } = message as { request: object; error: Error & { code?: string } };
      const found = record(request);
      if (found) found.row.transportError = { name: error.name, code: error.code, message: error.message };
    }],
  ];
  for (const [name, handler] of subscriptions) diagnostics.subscribe(name, handler);
  // A stalled event loop delays undici's native keep-alive timer, so a socket
  // the client meant to drop at 4 s can still be reused at the relay's 5 s
  // idle boundary. Record stalls above 100 ms with their timing.
  const stalls: Array<{ atMs: number; lagMs: number }> = [];
  let expected = performance.now() + 50;
  const stallTimer = setInterval(() => {
    const lag = performance.now() - expected;
    if (lag > 100) stalls.push({ atMs: now(), lagMs: Number(lag.toFixed(1)) });
    expected = performance.now() + 50;
  }, 50);
  return {
    for: (tag: string): TransportWitnessRecord => records.get(tag)
      ?? { socket: null, reused: null, socketIdleMs: null, wroteHeadersAtMs: null, headersAtMs: null, completedAtMs: null, transportError: null },
    summary: () => ({ node: process.version, undici: process.versions.undici, sockets: socketCount, events, stalls }),
    stop: () => {
      clearInterval(stallTimer);
      for (const [name, handler] of subscriptions) diagnostics.unsubscribe(name, handler);
    },
  };
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
    const closeEvents: Array<{ code: number; reason: string; wasClean: boolean }> = [];
    // Record the close() calls the maintained client makes. This proves the
    // client invoked close(4000, reason); it does not observe wire bytes. The
    // code undici reports is the relay's echo, and undici can report 1006 for
    // an echo that did arrive: the relay compresses frames, undici inflates
    // them asynchronously, and a Close echo still queued behind that inflate
    // when the TCP connection ends is never parsed (qntm-bw96 local wire
    // captures on Node 22.23.2 / undici 6.28.0; CI only observed the 1006).
    // The raw handshake test below checks the relay's echo on the wire.
    const sentCloses: Array<{ code?: number; reason?: string }> = [];
    const NativeWebSocket = globalThis.WebSocket;
    let subscription: ReturnType<typeof relay.subscribeMessages> | null = null;
    try {
      globalThis.WebSocket = class RecordingWebSocket extends NativeWebSocket {
        override close(code?: number, reason?: string): void {
          sentCloses.push({ code, reason });
          super.close(code, reason);
        }
      };
      subscription = relay.subscribeMessages(cid, 0, {
        onMessage: ({ seq }) => {
          callbackAttempts.push(seq);
          if (callbackAttempts.length === 1) throw injectedFailure;
          frames.push({ type: 'message', seq });
        },
        // onError also reports socket failures during reconnection. Preserve the
        // actual cause instead of labelling every transport error a callback error.
        onError: error => { errors.push(error); },
        onClose: ({ code, reason, wasClean }) => {
          closeEvents.push({ code, reason, wasClean });
          frames.push({ type: 'closed', seq: code });
        },
      });
      await waitForFrame(frames, frame => frame.type === 'message' && frame.seq === sequence, 'native callback retry', 20_000);
      expect(errors.filter(error => error === injectedFailure)).toHaveLength(1);
      expect(callbackAttempts).toEqual([sequence, sequence]);
      expect(frames.filter(frame => frame.type === 'message')).toEqual([{ type: 'message', seq: sequence }]);
      // The client called close(4000, reason) exactly once before the
      // redelivery that ended the wait above.
      expect(sentCloses).toEqual([{ code: 4000, reason: 'receive callback failed' }]);
      // undici reported exactly one close for that socket: the echoed 4000, or
      // 1006 when it never parsed the echo. Other codes are rejected as
      // unexplained; they are not attributed to the relay here.
      expect(closeEvents).toHaveLength(1);
      expect([4000, 1006]).toContain(closeEvents[0]!.code);
    } finally {
      globalThis.WebSocket = NativeWebSocket;
      subscription?.close();
      await subscription?.closed;
      writeFileSync(join(artifactDir, 'native-callback-reconnect.json'), JSON.stringify({ node: process.version,
        undici: process.versions.undici, callbackAttempts,
        errors: errors.map(error => ({ name: error.name, message: error.message, injected: error === injectedFailure })),
        frames, sentCloses, closeEvents }, null, 2));
    }
  }, 40_000);

  it('echoes a client Close code and reason on the wire before closing the connection', async () => {
    // Exercise the relay's close-handshake reply directly: no extensions are
    // requested, so frames are parsed exactly as sent. The maintained client
    // sends these two Close codes; the relay must echo each before its FIN.
    const cases = [{ code: 4000, reason: 'receive callback failed' }, { code: 1000, reason: 'client closed' }];
    const observed: RawCloseHandshake[] = [];
    try {
      for (const { code, reason } of cases) {
        const handshake = await rawCloseHandshake(relayUrl, randomUUID().replaceAll('-', ''), code, reason);
        observed.push(handshake);
        expect(handshake.extensions).toBeNull();
        expect(handshake.frames).toEqual([{ type: 'ready', head_seq: 0 }]);
        expect(handshake.close).toEqual({ code, reason });
        expect(handshake.finAfterClose).toBe(true);
        expect(handshake.bytesAfterClose).toBe(0);
      }
    } finally {
      writeFileSync(join(artifactDir, 'raw-close-handshake.json'), JSON.stringify(observed, null, 2));
    }
  }, 30_000);

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
        const renewedId = hex(deserializeEnvelope(renewedWire).msg_id);
        const attempts = proxy.sends.slice(beforeRetry);
        // The relay is append-only: every accepted POST occupies a new sequence
        // row, so the committed-but-unacknowledged first attempt and the exact
        // retry are two physical rows of one ciphertext (worker/src/index.ts
        // increments next_seq per POST). Deduplication is the receiver's job by
        // message ID (docs/QSP-v1.0.md). Assert exactly one attempt per row, no
        // hidden resend, no hidden relay dedup, and one logical message.
        const matches = replay.entries.filter(row => Buffer.from(row.envelope).equals(renewedWire));
        expect(matches.map(row => row.seq)).toEqual(attempts.map((_, offset) => anchor + 1 + offset));
        expect(matches).toHaveLength(2);
        const welcomeRows = replay.entries.filter(row => row.seq > anchor && isGroupWelcomeEnvelope(deserializeEnvelope(row.envelope)));
        expect(welcomeRows.map(row => row.seq)).toEqual(matches.map(row => row.seq));
        expect(new Set(welcomeRows.map(row => hex(deserializeEnvelope(row.envelope).msg_id)))).toEqual(new Set([renewedId]));
        expect(replay.entries.some(row => Buffer.from(row.envelope).toString('base64') === original.welcomes[0])).toBe(false);
        expect(replay.entries.filter(row => row.seq > anchor)).toHaveLength(matches.length); // Nothing else was posted.
        const row = matches[0];
        const welcome = openGroupWelcome(founder, row.envelope, locator);
        expect(welcome.purpose).toBe('refresh');
        expect(hex(welcome.recoveryChallenge!)).toBe(hex(challenge));
        expect(welcome.replayFromSequence).toBe(anchor);
        expect(welcome.admissions[hex(founder.keyID)]).toBeUndefined();
        expect(welcome.admissions).toEqual(founderState.admissions);
        expect(Object.keys(welcome.admissions)).toEqual([issuer.key_id]);
        const fresh = checkGroupWelcomeReplay(groupSessionFromWelcome(founder, welcome, row.seq), welcome, replay.sequence, replay.entries);
        assertGroupCanSend(founder, fresh);
        expect(fresh).toMatchObject({ root: founderState.root, epoch: founderState.epoch, rekeys: [], recovery: null, removed: false, needsRekey: false });
        expect(fresh.snapshot).toBe(founderState.snapshot);
        expect(Object.keys(fresh.admissions)).toEqual([issuer.key_id]);
        expect(JSON.stringify(fresh)).not.toContain(oldRoot);
        if (stale === 'rotated') expect(JSON.stringify(fresh)).not.toContain(previousRoot);
        expect(() => decryptMessage(oldMessage, groupSessionConversation(fresh))).toThrow();
        // The duplicate row is the same signed box: it installs nothing new. It
        // neither rotates keys, adds an admission, decrypts as plaintext, nor
        // marks history missing when bootstrapping from either physical row.
        const duplicate = matches[1];
        const duplicateWelcome = openGroupWelcome(founder, duplicate.envelope, locator);
        expect(duplicateWelcome.admissions).toEqual(welcome.admissions);
        expect(hex(duplicateWelcome.conversation.keys.root)).toBe(fresh.root);
        expect(duplicateWelcome.conversation.currentEpoch).toBe(fresh.epoch);
        const reinstalled = checkGroupWelcomeReplay(groupSessionFromWelcome(founder, duplicateWelcome, duplicate.seq, fresh),
          duplicateWelcome, replay.sequence, replay.entries);
        expect(reinstalled).toEqual(fresh);
        const fromDuplicate = checkGroupWelcomeReplay(groupSessionFromWelcome(founder, duplicateWelcome, duplicate.seq),
          duplicateWelcome, replay.sequence, replay.entries);
        expect(fromDuplicate).toEqual(fresh);
        for (const welcomeRow of matches) {
          const envelope = deserializeEnvelope(welcomeRow.envelope);
          expect(() => decryptMessage(envelope, groupSessionConversation(fresh))).toThrow();
          expect(checkGroupUnverifiableEpoch(fresh, envelope, welcomeRow.seq)).toEqual(fresh);
        }
        expect(fresh.seen).not.toHaveProperty(renewedId);
        const text = `${surface} ${stale} founder recovered reply`;
        await transport.postMessage(conversation.id, serializeEnvelope(createMessage(founder, groupSessionConversation(fresh), 'text', new TextEncoder().encode(text))));
        const received = await command('recv', id);
        expect(received.messages.filter((message: { unsafe_body?: string }) => message.unsafe_body === text)).toHaveLength(1);
        expect(received.messages.filter((message: { message_id?: string }) => message.message_id === renewedId)).toEqual([]);
        // The issuing Python member replays its own duplicated welcome rows without
        // delivering them, rotating keys, or changing admission provenance.
        const settled = readRecord(id);
        expect(settled.group_operation).toBeUndefined();
        expect(settled.group_session).toMatchObject({ root: founderState.root, epoch: founderState.epoch, recovery: null });
        expect(settled.group_session.seen).not.toHaveProperty(renewedId);
        expect(Object.keys(settled.group_session.admissions)).toEqual([issuer.key_id]);
        expect(settled.group_session.admissions[issuer.key_id]).toEqual(founderState.admissions[issuer.key_id]);
        writeFileSync(join(artifactDir, `${surface.toLowerCase()}-${stale}-generic-refresh.json`), JSON.stringify({
          conversation: id, surface, stale, journalShape: shape,
          originalWelcome: hex(deserializeEnvelope(Buffer.from(original.welcomes[0], 'base64')).msg_id),
          replacementWelcome: renewedId,
          replacementAttempts: attempts.length, replacementRelayRows: matches.map(entry => entry.seq),
          distinctReplacementCiphertexts: new Set(attempts.map(send => send.envelope_b64)).size,
          evidenceRecordsBeforePost: pending.superseded_operations!.length,
          lostAcknowledgements: proxy.droppedAcknowledgements, blockedReplays: proxy.blockedReplays,
          purpose: welcome.purpose, currentEpoch: fresh.epoch, replayAnchor: welcome.replayFromSequence,
          replaySequences: replay.entries.map(entry => entry.seq), receivedReply: true,
        }, null, 2));
      } finally { await proxy.stop(); }
    }, 90_000);
  }

  for (const surface of ['CLI', 'MCP']) {
    it(`finishes an accepted removal whose rekey expired through fresh ${surface} processes, TypeScript peers and a lost ACK`, async () => {
      type Journal = { kind: string; controls: string[]; welcomes: string[]; welcomes_sent: number; expected: GroupSessionState;
        target?: Record<string, unknown>; origin?: Record<string, unknown>; superseded_operations?: Array<Record<string, unknown>> };
      type RecordState = { id: string; current_epoch: number; participants: string[]; group_cursor: number;
        group_session: GroupSessionState; group_operation?: Journal };
      const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
      const profile = join(stateDir, `${surface.toLowerCase()}-removal-recovery`);
      const python = process.env.QNTM_MONITOR_PYTHON || 'python3';
      const env = { ...process.env, PYTHONPATH: join(REPO_ROOT, 'python-dist/src') };
      const readRecord = (id: string): RecordState => JSON.parse(readFileSync(join(profile, 'conversations.json'), 'utf8'))
        .find((record: RecordState) => record.id === id);
      const beforePost: Array<Journal | undefined> = [];
      let capture = false;
      const proxy = await recordingRelay(relayUrl, { onSend(send) {
        if (capture) beforePost.push(structuredClone(readRecord(send.conv_id).group_operation));
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
        const client = new Client({ name: 'fresh-removal-retry', version: '1' });
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
      const transport = new DropboxClient(proxy.url);
      const survivor = generateIdentity(), target = generateIdentity();
      type Peer = { identity: ReturnType<typeof generateIdentity>; state: GroupSessionState; cursor: number };
      // A TypeScript peer replays exactly like a maintained client: coverage,
      // unverifiable-epoch preflight, expired-control detection, then the reducer.
      const advance = async (peer: Peer, conversationId: Uint8Array, bootstrap?: Awaited<ReturnType<DropboxClient['receiveMessages']>>) => {
        const result = bootstrap ?? await transport.receiveMessages(conversationId, peer.cursor);
        if (!bootstrap) {
          peer.state = checkGroupReplayCoverage(peer.state, peer.cursor, result.sequence, result.entries.map(row => row.seq));
          for (const row of result.entries) peer.state = checkGroupUnverifiableEpoch(peer.state, deserializeEnvelope(row.envelope), row.seq);
        }
        const texts: string[] = [], rejected: string[] = [];
        for (const row of [...result.entries].filter(row => row.seq > peer.cursor).sort((a, b) => a.seq - b.seq)) {
          const envelope = deserializeEnvelope(row.envelope);
          if (isGroupWelcomeEnvelope(envelope)) continue;
          // Bootstrap already checked signed exact hashes and the anchor; rows
          // sourced before admission never supply keys or history to a newcomer.
          if (bootstrap && envelope.conv_epoch < peer.state.epoch) continue;
          peer.state = checkExpiredGroupControl(peer.identity, peer.state, envelope, row.seq);
          if (peer.state.recovery || envelope.expiry_ts < Math.floor(Date.now() / 1000)) continue;
          try {
            const event = receiveGroupEvent(peer.identity, envelope, peer.state);
            peer.state = event.state;
            if (!event.duplicate && event.message.inner.body_type === 'text') texts.push(new TextDecoder().decode(event.message.inner.body));
          } catch (error) {
            if (!peer.state.removed) throw error;
            rejected.push(hex(envelope.msg_id));
          }
        }
        peer.cursor = result.sequence;
        return { texts, rejected };
      };
      const open = async (identity: ReturnType<typeof generateIdentity>, link: string): Promise<Peer> => {
        const locator = parseGroupLink(link);
        const replay = await transport.receiveMessages(locator.conversationId);
        const welcomes = replay.entries.flatMap(row => {
          try { return [{ seq: row.seq, welcome: openGroupWelcome(identity, row.envelope, locator) }]; } catch { return []; }
        });
        const { welcome, seq } = welcomes.at(-1)!;
        expect(welcome.purpose).toBe('addition');
        const state = checkGroupWelcomeReplay(groupSessionFromWelcome(identity, welcome, seq), welcome, replay.sequence, replay.entries);
        const peer: Peer = { identity, state, cursor: welcome.replayFromSequence };
        await advance(peer, locator.conversationId, replay);
        expect(peer.state.recovery).toBeNull();
        assertGroupCanSend(identity, peer.state);
        return peer;
      };
      try {
        await command('identity', 'generate');
        const created = await command('group', 'create', `${surface} removal recovery`);
        const id: string = created.conversation_id, conversationId = Buffer.from(id, 'hex');
        await command('contact', 'add', 'Survivor', hex(survivor.publicKey));
        await command('contact', 'add', 'Target', hex(target.publicKey));
        expect((await command('group', 'add', id, 'Survivor')).current_epoch).toBe(1);
        const admitted = await command('group', 'add', id, 'Target');
        expect(admitted.current_epoch).toBe(2);
        const survivorPeer = await open(survivor, admitted.group_link);
        const targetPeer = await open(target, admitted.group_link);
        expect(survivorPeer.state.epoch).toBe(2);
        expect(targetPeer.state.epoch).toBe(2);
        expect(survivorPeer.state.root).toBe(targetPeer.state.root);

        // Real crash window: the removal is accepted through authenticated
        // receive, the short-lived completing rekey is never posted.
        const stagedSends = proxy.sends.length;
        const staged = await promisify(execFile)(python, [join(REPO_ROOT, 'integration/src/stage-pending-removal.py'),
          profile, proxy.url, id, hex(target.keyID)], { env, timeout: 30_000 });
        const stage = JSON.parse(staged.stdout) as { cursor: number; epoch: number; removal_id: string; rekey_id: string;
          rekey_expires_at: number; target: Record<string, unknown> };
        expect(proxy.sends.slice(stagedSends)).toHaveLength(1);
        const removalWire = proxy.sends.at(-1)!.envelope_b64;
        const original = readRecord(id).group_operation!;
        expect(original).toMatchObject({ kind: 'remove', welcomes: [], welcomes_sent: 0, target: stage.target });
        expect(original.controls[0]).toBe(removalWire);
        expect(original.target).toMatchObject({ key_id: hex(target.keyID), public_key: hex(target.publicKey) });
        expect(hex(deserializeEnvelope(Buffer.from(original.controls[1], 'base64')).msg_id)).toBe(stage.rekey_id);
        const beforeRepair = readRecord(id);
        expect(beforeRepair.group_session).toMatchObject({ epoch: 2, needsRekey: true, recovery: null });
        expect(beforeRepair.participants).not.toContain(hex(target.keyID));
        expect(await advance(survivorPeer, conversationId)).toEqual({ texts: [], rejected: [] });
        expect(survivorPeer.state).toMatchObject({ epoch: 2, needsRekey: true, removed: false });
        expect(() => assertGroupCanSend(survivor, survivorPeer.state)).toThrow();
        await advance(targetPeer, conversationId);
        expect(targetPeer.state.removed).toBe(true);
        const wait = Math.max(0, stage.rekey_expires_at * 1000 - Date.now() + 1100);
        expect(wait).toBeLessThanOrEqual(10_000);
        await delay(wait);
        expect(Math.floor(Date.now() / 1000)).toBeGreaterThan(stage.rekey_expires_at);

        const beforeRetry = proxy.sends.length;
        capture = true;
        proxy.loseNextSendAcknowledgement({ pauseReplay: true });
        await expect(retry(id)).rejects.toThrow();
        capture = false;
        expect(proxy.droppedAcknowledgements).toBe(1);
        expect(proxy.blockedReplays).toBeGreaterThan(0);
        expect(proxy.sends.slice(beforeRetry)).toHaveLength(1);
        const rotationWire = proxy.sends.at(-1)!.envelope_b64;
        const rotation = deserializeEnvelope(Buffer.from(rotationWire, 'base64'));
        expect(rotation.conv_epoch).toBe(2);
        expect(hex(rotation.msg_id)).not.toBe(stage.rekey_id);
        const pending = readRecord(id).group_operation!;
        expect(pending).toMatchObject({ kind: 'removal_rekey', controls: [rotationWire], welcomes: [], welcomes_sent: 0,
          origin: { kind: 'remove', controls: original.controls, welcomes: [], welcomes_sent: 0, target: original.target, delivery: 'unknown' } });
        expect(pending).not.toHaveProperty('superseded_operations');
        expect(pending.expected.epoch).toBe(3);
        expect(beforePost).toEqual([pending]); // The repair was durable before its POST.
        const uncertain = readRecord(id);
        expect(uncertain.group_session).toMatchObject({ epoch: 2, needsRekey: true, root: beforeRepair.group_session.root });
        expect(JSON.stringify(uncertain.group_session)).not.toContain(pending.expected.root); // No predicted keys installed.

        proxy.resumeReplay();
        capture = true;
        const result = await retry(id);
        capture = false;
        expect(result).toMatchObject({ current_epoch: 3, members: 2 });
        // Verified replay proved the accepted rotation; the fresh process posted nothing more.
        expect(proxy.sends.slice(beforeRetry).map(send => send.envelope_b64)).toEqual([rotationWire]);
        expect(beforePost).toEqual([pending]);
        const replacementAttempts = proxy.sends.slice(beforeRetry).length;
        const settled = readRecord(id);
        expect(settled.group_operation).toBeUndefined();
        expect(settled.group_session).toMatchObject({ epoch: 3, needsRekey: false, recovery: null, root: pending.expected.root });
        expect(settled.participants).toHaveLength(2);
        expect(settled.participants).toContain(hex(survivor.keyID));
        expect(settled.participants).not.toContain(hex(target.keyID));
        const replay = await transport.receiveMessages(conversationId);
        const later = replay.entries.filter(row => row.seq > stage.cursor);
        expect(later.map(row => Buffer.from(row.envelope).toString('base64'))).toEqual([rotationWire]);
        expect(replay.entries.some(row => hex(deserializeEnvelope(row.envelope).msg_id) === stage.rekey_id)).toBe(false);
        expect(replay.entries.filter(row => hex(deserializeEnvelope(row.envelope).msg_id) === stage.removal_id)).toHaveLength(1);

        expect(await advance(survivorPeer, conversationId)).toEqual({ texts: [], rejected: [] });
        expect(survivorPeer.state).toMatchObject({ epoch: 3, needsRekey: false, removed: false, recovery: null, root: settled.group_session.root });
        expect(survivorPeer.state.rekeys.at(-1)).toMatchObject({ epoch: 2, messageId: hex(rotation.msg_id) });
        assertGroupCanSend(survivor, survivorPeer.state);
        const targetReplay = await advance(targetPeer, conversationId);
        expect(targetPeer.state).toMatchObject({ epoch: 2, removed: true });
        expect(targetPeer.state.root).not.toBe(settled.group_session.root);
        expect(targetReplay.texts).toEqual([]);

        const text = `${surface} text after the repaired removal`;
        await command('send', id, text);
        expect((await advance(survivorPeer, conversationId)).texts).toEqual([text]);
        const excluded = await advance(targetPeer, conversationId);
        expect(excluded.texts).toEqual([]);
        expect(excluded.rejected).toHaveLength(1);
        const reply = `${surface} survivor reply`;
        await transport.postMessage(conversationId, serializeEnvelope(createMessage(survivor, groupSessionConversation(survivorPeer.state), 'text', new TextEncoder().encode(reply))));
        const received = await command('recv', id);
        expect(received.messages.filter((message: { unsafe_body?: string }) => message.unsafe_body === reply)).toHaveLength(1);
        await expect(retry(id)).rejects.toThrow(/No pending group operation/);
        writeFileSync(join(artifactDir, `${surface.toLowerCase()}-removal-recovery.json`), JSON.stringify({
          conversation: id, surface, removal: stage.removal_id, expiredRekey: stage.rekey_id,
          replacementRotation: hex(rotation.msg_id), replacementAttempts,
          replacementRelayRows: later.map(row => row.seq), lostAcknowledgements: proxy.droppedAcknowledgements,
          blockedReplays: proxy.blockedReplays, journalBeforePost: pending.kind, evidenceOrigin: pending.origin?.kind,
          finalEpoch: settled.group_session.epoch, survivorEpoch: survivorPeer.state.epoch, targetRemoved: targetPeer.state.removed,
          replaySequences: replay.entries.map(entry => entry.seq), receivedReply: true,
        }, null, 2));
      } finally { await proxy.stop(); }
    }, 90_000);
  }

  for (const surface of ['CLI', 'MCP']) {
    const stale = surface === 'CLI' ? 'expired' : 'superseded';
    it(`releases an unproven ${stale} removal through fresh ${surface} processes without excluding anyone, then a new explicit removal excludes the target`, async () => {
      type Journal = { kind: string; controls: string[]; welcomes: string[]; welcomes_sent: number; expected?: GroupSessionState; target?: Record<string, unknown> };
      type RecordState = { id: string; current_epoch: number; participants: string[]; group_cursor: number;
        group_session: GroupSessionState; group_operation?: Journal; released_group_operations?: Array<Journal & { delivery: string; released_reason: string; released_at: number }> };
      const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
      const profile = join(stateDir, `${surface.toLowerCase()}-removal-release`);
      const python = process.env.QNTM_MONITOR_PYTHON || 'python3';
      const env = { ...process.env, PYTHONPATH: join(REPO_ROOT, 'python-dist/src') };
      const readRecord = (id: string): RecordState => JSON.parse(readFileSync(join(profile, 'conversations.json'), 'utf8'))
        .find((record: RecordState) => record.id === id);
      const proxy = await recordingRelay(relayUrl);
      const command = async (...args: string[]) => {
        const { stdout } = await promisify(execFile)(python, ['-m', 'qntm.cli', '--config-dir', profile,
          '--dropbox-url', proxy.url, ...args], { env, timeout: 30_000, maxBuffer: 1024 * 1024 });
        const result = JSON.parse(stdout);
        if (!result.ok) throw new Error(JSON.stringify(result));
        return result.data;
      };
      const mcp = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> => {
        const client = new Client({ name: 'fresh-removal-release', version: '1' });
        try {
          await client.connect(new StdioClientTransport({ command: python, args: ['-m', 'qntm.mcp_server'],
            env: { ...Object.fromEntries(Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
              QNTM_CONFIG_DIR: profile, QNTM_RELAY_URL: proxy.url }, stderr: 'pipe' }));
          const response = await client.callTool({ name, arguments: args });
          const result = response.structuredContent as Record<string, unknown>
            ?? JSON.parse((response.content as Array<{ text: string }>)[0].text);
          if (response.isError || result.error) throw new Error(JSON.stringify(result));
          return result;
        } finally { await client.close(); }
      };
      const retry = (id: string, release = false) => surface === 'CLI'
        ? command('group', 'retry', id, ...(release ? ['--release-unproven'] : []))
        : mcp('group_retry', { conversation: id, release_unproven: release });
      const transport = new DropboxClient(proxy.url);
      type Peer = { identity: ReturnType<typeof generateIdentity>; state: GroupSessionState; cursor: number };
      const advance = async (peer: Peer, conversationId: Uint8Array, bootstrap?: Awaited<ReturnType<DropboxClient['receiveMessages']>>) => {
        const result = bootstrap ?? await transport.receiveMessages(conversationId, peer.cursor);
        if (!bootstrap) {
          peer.state = checkGroupReplayCoverage(peer.state, peer.cursor, result.sequence, result.entries.map(row => row.seq));
          for (const row of result.entries) peer.state = checkGroupUnverifiableEpoch(peer.state, deserializeEnvelope(row.envelope), row.seq);
        }
        const texts: string[] = [], rejected: string[] = [];
        for (const row of [...result.entries].filter(row => row.seq > peer.cursor).sort((a, b) => a.seq - b.seq)) {
          const envelope = deserializeEnvelope(row.envelope);
          if (isGroupWelcomeEnvelope(envelope)) continue;
          if (bootstrap && envelope.conv_epoch < peer.state.epoch) continue;
          peer.state = checkExpiredGroupControl(peer.identity, peer.state, envelope, row.seq);
          if (peer.state.recovery || envelope.expiry_ts < Math.floor(Date.now() / 1000)) continue;
          try {
            const event = receiveGroupEvent(peer.identity, envelope, peer.state);
            peer.state = event.state;
            if (!event.duplicate && event.message.inner.body_type === 'text') texts.push(new TextDecoder().decode(event.message.inner.body));
          } catch (error) {
            if (!peer.state.removed) throw error;
            rejected.push(hex(envelope.msg_id));
          }
        }
        peer.cursor = result.sequence;
        return { texts, rejected };
      };
      const open = async (identity: ReturnType<typeof generateIdentity>, link: string): Promise<Peer> => {
        const locator = parseGroupLink(link);
        const replay = await transport.receiveMessages(locator.conversationId);
        const welcomes = replay.entries.flatMap(row => {
          try { return [{ seq: row.seq, welcome: openGroupWelcome(identity, row.envelope, locator) }]; } catch { return []; }
        });
        const { welcome, seq } = welcomes.at(-1)!;
        const state = checkGroupWelcomeReplay(groupSessionFromWelcome(identity, welcome, seq), welcome, replay.sequence, replay.entries);
        const peer: Peer = { identity, state, cursor: welcome.replayFromSequence };
        await advance(peer, locator.conversationId, replay);
        expect(peer.state.recovery).toBeNull();
        assertGroupCanSend(identity, peer.state);
        return peer;
      };
      const say = async (peer: Peer, conversationId: Uint8Array, text: string) => {
        await advance(peer, conversationId);
        assertGroupCanSend(peer.identity, peer.state);
        await transport.postMessage(conversationId, serializeEnvelope(createMessage(peer.identity, groupSessionConversation(peer.state), 'text', new TextEncoder().encode(text))));
        expect((await advance(peer, conversationId)).texts).toEqual([text]); // Consume the peer's own row.
      };
      try {
        await command('identity', 'generate');
        const survivor = generateIdentity(), target = generateIdentity();
        const created = await command('group', 'create', `${surface} ${stale} removal release`);
        const id: string = created.conversation_id, conversationId = Buffer.from(id, 'hex');
        await command('contact', 'add', 'Survivor', hex(survivor.publicKey));
        await command('contact', 'add', 'Target', hex(target.publicKey));
        expect((await command('group', 'add', id, 'Survivor')).current_epoch).toBe(1);
        const admitted = await command('group', 'add', id, 'Target');
        expect(admitted.current_epoch).toBe(2);
        const survivorPeer = await open(survivor, admitted.group_link), targetPeer = await open(target, admitted.group_link);
        expect(survivorPeer.state.epoch).toBe(2); expect(targetPeer.state.epoch).toBe(2);

        // Real crash window: the removal journal is saved with its target pin and
        // short-lived controls, and nothing is ever posted for it.
        const stagedSends = proxy.sends.length;
        const staged = await promisify(execFile)(python, [join(REPO_ROOT, 'integration/src/stage-unposted-removal.py'),
          profile, proxy.url, id, hex(target.keyID), '8'], { env, timeout: 30_000 });
        const stage = JSON.parse(staged.stdout) as { cursor: number; epoch: number; removal_id: string; rekey_id: string; removal_expires_at: number; target: Record<string, unknown> };
        expect(proxy.sends.slice(stagedSends)).toHaveLength(0);
        const original = readRecord(id).group_operation!;
        expect(original).toMatchObject({ kind: 'remove', welcomes: [], welcomes_sent: 0, target: stage.target });
        expect(original.controls).toHaveLength(2);
        expect(original.target).toMatchObject({ key_id: hex(target.keyID), public_key: hex(target.publicKey) });
        let newcomerPeer: Peer | undefined;
        const survivorRotations: string[] = [];
        if (stale === 'expired') {
          const wait = Math.max(0, stage.removal_expires_at * 1000 - Date.now() + 1100);
          expect(wait).toBeLessThanOrEqual(10_000);
          await delay(wait);
          expect(Math.floor(Date.now() / 1000)).toBeGreaterThan(stage.removal_expires_at);
        } else {
          // A later admission by the surviving peer leaves the removal's source epoch behind.
          const newcomer = generateIdentity();
          await advance(survivorPeer, conversationId);
          const addition = prepareGroupSessionAddition(survivor, survivorPeer.state, [newcomer.publicKey], undefined, undefined, survivorPeer.cursor);
          for (const control of [addition.addition, addition.rekey]) {
            await transport.postMessage(conversationId, serializeEnvelope(control));
            survivorPeer.state = receiveGroupEvent(survivor, control, survivorPeer.state).state;
          }
          survivorRotations.push(hex(addition.rekey.msg_id));
          assertGroupAdditionAccepted(survivor, survivorPeer.state, addition);
          await transport.postMessage(conversationId, serializeEnvelope(addition.welcomes[0]));
          survivorPeer.cursor = (await transport.receiveMessages(conversationId, survivorPeer.cursor)).sequence;
          newcomerPeer = await open(newcomer, createGroupLink({ conversationId, inviterPublicKey: survivor.publicKey, relayUrl: proxy.url }));
          expect(newcomerPeer.state.epoch).toBe(3);
        }

        // Plain retry preserves the stale journal; release gives up local retry only.
        const beforeRetry = proxy.sends.length;
        await expect(retry(id)).rejects.toThrow(stale === 'expired' ? /expired before its acceptance/ : /superseded before its acceptance/);
        expect(readRecord(id).group_operation).toEqual(original);
        const released = await retry(id, true);
        expect(released).toMatchObject({ released: true, reason: stale, removed: false, needs_rekey: false, released_operations: 1,
          current_epoch: stale === 'expired' ? 2 : 3, members: stale === 'expired' ? 3 : 4 });
        expect(released).not.toHaveProperty('cancelled'); expect(released).not.toHaveProperty('accepted');
        const postsDuringRelease = proxy.sends.slice(beforeRetry).length;
        expect(postsDuringRelease).toBe(0);
        const settled = readRecord(id);
        expect(settled.group_operation).toBeUndefined();
        expect(settled.released_group_operations).toEqual([{ kind: 'remove', controls: original.controls, welcomes: [], welcomes_sent: 0,
          target: original.target, delivery: 'unknown', released_reason: stale, released_at: expect.any(Number) }]);
        expect(settled.released_group_operations![0]).not.toHaveProperty('expected');
        expect(settled.participants).toContain(hex(target.keyID));
        expect(settled.group_session).toMatchObject({ needsRekey: false, removed: false, recovery: null });
        const rows = (await transport.receiveMessages(conversationId, 0)).entries.map(row => deserializeEnvelope(row.envelope));
        expect(rows.some(envelope => hex(envelope.msg_id) === stage.removal_id || hex(envelope.msg_id) === stage.rekey_id)).toBe(false);

        // No false exclusion: the target still reads and replies on current keys.
        const text = `${surface} text after release`;
        await command('send', id, text);
        expect((await advance(targetPeer, conversationId)).texts).toEqual([text]);
        expect((await advance(survivorPeer, conversationId)).texts).toEqual([text]);
        if (newcomerPeer) expect((await advance(newcomerPeer, conversationId)).texts).toEqual([text]);
        await say(targetPeer, conversationId, `${surface} target still present`);
        const received = await command('recv', id);
        expect(received.messages.filter((message: { unsafe_body?: string }) => message.unsafe_body === `${surface} target still present`)).toHaveLength(1);
        expect((await advance(survivorPeer, conversationId)).texts).toEqual([`${surface} target still present`]);
        if (newcomerPeer) expect((await advance(newcomerPeer, conversationId)).texts).toEqual([`${surface} target still present`]);

        // A separate explicit removal is a fresh current-epoch decision with its own pin.
        const beforeRemoval = proxy.sends.length;
        const removed = surface === 'CLI' ? await command('group', 'remove', id, 'Target') : await mcp('group_remove_contact', { conversation: id, contact: 'Target' });
        expect(removed).toMatchObject({ current_epoch: stale === 'expired' ? 3 : 4, members: stale === 'expired' ? 2 : 3 });
        const removalPosts = proxy.sends.slice(beforeRemoval).map(send => deserializeEnvelope(Buffer.from(send.envelope_b64, 'base64')));
        expect(removalPosts).toHaveLength(2);
        expect(removalPosts.map(envelope => hex(envelope.msg_id))).not.toContain(stage.removal_id);
        expect(removalPosts.every(envelope => envelope.conv_epoch === (stale === 'expired' ? 2 : 3))).toBe(true);
        const after = readRecord(id);
        expect(after.group_operation).toBeUndefined();
        expect(after.participants).not.toContain(hex(target.keyID));
        expect(after.released_group_operations).toEqual(settled.released_group_operations);
        const exclusion = `${surface} text after the explicit removal`;
        await command('send', id, exclusion);
        expect((await advance(survivorPeer, conversationId)).texts).toEqual([exclusion]);
        const excluded = await advance(targetPeer, conversationId);
        expect(targetPeer.state.removed).toBe(true); expect(excluded.texts).toEqual([]); expect(excluded.rejected.length).toBeGreaterThan(0);
        if (newcomerPeer) expect((await advance(newcomerPeer, conversationId)).texts).toEqual([exclusion]);
        await say(survivorPeer, conversationId, `${surface} survivor reply after exclusion`);
        const finalRecv = await command('recv', id);
        expect(finalRecv.messages.filter((message: { unsafe_body?: string }) => message.unsafe_body === `${surface} survivor reply after exclusion`)).toHaveLength(1);
        writeFileSync(join(artifactDir, `${surface.toLowerCase()}-removal-release.json`), JSON.stringify({
          conversation: id, surface, stale, releasedRemoval: stage.removal_id, releasedRekey: stage.rekey_id,
          postsDuringRelease, releaseReason: released.reason,
          explicitRemovalPosts: removalPosts.map(envelope => hex(envelope.msg_id)), survivorRotations,
          targetRemovedAfterExplicitRemoval: targetPeer.state.removed, finalEpoch: after.group_session.epoch,
          archive: after.released_group_operations!.length,
        }, null, 2));
      } finally { await proxy.stop(); }
    }, 90_000);
  }

  it('posts exactly once across the native runtime idle-connection boundary', async () => {
    // Send-time alignment deliberately exercises KJ's 5-second idle boundary.
    // Waiting five seconds *after* responses would miss the stale-socket race.
    const start = performance.now() + 150;
    const outcomes: Array<{ lane: number; round: number; sentAtMs: number; status: number; body: string; cause?: unknown }
      & Partial<TransportWitnessRecord>> = [];
    const conversations = Array.from({ length: 32 }, () => generateIdentity().keyID);
    // Tag each POST so the witness can attribute sockets and timings to it.
    // The relay ignores the header; the client and relay are unchanged.
    const witness = transportWitness('x-qntm-idle-lane', start);
    try {
      await Promise.all(conversations.map(async (cid, lane) => {
        for (let round = 0; round < 5; round++) {
          await delay(Math.max(0, start + round * 5_000 + lane * 3 - performance.now()));
          const sentAtMs = performance.now() - start;
          try {
            const response = await fetch(`${relayUrl}/v1/send`, {
              method: 'POST', headers: { 'Content-Type': 'application/json', 'x-qntm-idle-lane': `${lane}-${round}` },
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
    } finally {
      witness.stop();
    }
    for (const row of outcomes) Object.assign(row, witness.for(`${row.lane}-${row.round}`));
    writeFileSync(join(artifactDir, 'idle-boundary.json'), JSON.stringify(outcomes, null, 2));
    writeFileSync(join(artifactDir, 'idle-boundary-transport.json'), JSON.stringify(witness.summary(), null, 2));
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
