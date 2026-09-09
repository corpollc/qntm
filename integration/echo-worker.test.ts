import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createConversation, createInvite, createMessage, decryptMessage, deriveConversationKeys, deserializeEnvelope, DropboxClient, generateIdentity, serializeEnvelope } from '@corpollc/qntm';
import echo, { handleConversation, type Env } from '../echo-worker/src/index.js';
import { ManagedProcess, getFreePorts, workerTestEnv } from './src/runtime.js';

function fixture() {
  const sender = generateIdentity(), bot = generateIdentity();
  const invite = createInvite(sender, 'direct'), conv = createConversation(invite, deriveConversationKeys(invite));
  const storage = new Map<string, string>();
  const env = { RELAY_URL: 'http://relay.invalid', ECHO_KV: {
    get: async (key: string) => storage.get(key) ?? null,
    put: async (key: string, value: string) => { storage.set(key, value); },
    delete: async (key: string) => { storage.delete(key); },
  } } as unknown as Env;
  const message = (text: string, who = sender, type = 'text') => serializeEnvelope(createMessage(who, conv, type, new TextEncoder().encode(text)));
  return { sender, bot, conv, storage, env, message };
}

describe('echo delivery and public surface', () => {
  it('defers capped work without skipping relay sequence gaps', async () => {
    const f = fixture(), messages = Array.from({ length: 12 }, (_, i) => ({ seq: 100 + i * 3, envelope: f.message(`message ${i}`) }));
    const receive = vi.fn(async (_url: string, _id: string, cursor: number) => ({ messages: messages.filter(m => m.seq > cursor), sequence: 999 }));
    const sent: Uint8Array[] = [], postMessage = vi.fn(async (_id: Uint8Array, bytes: Uint8Array) => { sent.push(bytes); return 1; });
    expect(await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', receive)).toBe(10);
    expect(f.storage.get('echo-bot-cursor')).toBe('127');
    expect(await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', receive)).toBe(2);
    expect(sent.map(bytes => new TextDecoder().decode(decryptMessage(deserializeEnvelope(bytes), f.conv).inner.body))).toEqual(messages.map((_, i) => `🔒 echo: message ${i}`));
    await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', receive);
    expect(f.storage.get('echo-bot-cursor')).toBe('999');
    expect(postMessage).toHaveBeenCalledTimes(12);
  });

  it('retries the exact persisted response after a failed send without dropping later work', async () => {
    const f = fixture(), input = f.message('retry Ω');
    const receive = async (_url: string, _id: string, cursor: number) => ({ messages: cursor < 7 ? [{ seq: 7, envelope: input }] : [], sequence: 7 });
    let original: Uint8Array | undefined;
    await expect(handleConversation(f.env, f.bot, f.conv, { postMessage: async (_id, bytes) => { original = bytes; throw Error('lost response'); } }, '', receive)).rejects.toThrow('lost response');
    expect(f.storage.get('echo-bot-cursor')).toBeUndefined();
    expect(Array.from(f.storage.keys()).some(key => key.includes(':response:'))).toBe(true);
    const postMessage = vi.fn(async (_id, bytes) => { expect(Buffer.from(bytes).equals(Buffer.from(original!))).toBe(true); return 8; });
    expect(await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', receive)).toBe(1);
    expect(f.storage.get('echo-bot-cursor')).toBe('7');
    expect(Array.from(f.storage.keys()).some(key => key.includes(':response:'))).toBe(true); // TTL keeps exact response bytes available for retry.
    await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', receive);
    expect(postMessage).toHaveBeenCalledTimes(1);
  });

  it('skips self, invalid and non-text messages without logging plaintext', async () => {
    const f = fixture(), sensitive = 'PRIVATE ECHO TEST CONTENT';
    const log = vi.spyOn(console, 'log'), err = vi.spyOn(console, 'error');
    try {
      const messages = [f.message('self', f.bot), Uint8Array.of(0), f.message('gate', f.sender, 'gate.request'), f.message(sensitive)].map((envelope, i) => ({ seq: i + 1, envelope }));
      const postMessage = vi.fn(async () => 5);
      expect(await handleConversation(f.env, f.bot, f.conv, { postMessage }, '', async () => ({ messages, sequence: 4 }))).toBe(1);
      expect(JSON.stringify([...log.mock.calls, ...err.mock.calls])).not.toContain(sensitive);
    } finally { log.mockRestore(); err.mockRestore(); }
  });

  it('exposes health but no plaintext trigger or replay endpoints', async () => {
    const f = fixture();
    expect((await echo.fetch(new Request('https://echo/healthz'), f.env)).status).toBe(200);
    for (const path of ['/trigger', '/replay?conv=2&from_seq=0']) {
      expect((await echo.fetch(new Request(`https://echo${path}`, { method: 'POST' }), f.env)).status).toBe(404);
    }
  });
});

describe.sequential('actual echo Worker, cron, and relay', () => {
  const f = fixture(), processes: ManagedProcess[] = [];
  let root: string, relay: DropboxClient, echoUrl: string;
  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), 'qntm-echo-acceptance-'));
    const [relayPort, echoPort, relayInspectorPort, echoInspectorPort] = await getFreePorts(4);
    const relayUrl = `http://127.0.0.1:${relayPort}`; echoUrl = `http://127.0.0.1:${echoPort}`;
    relay = new DropboxClient(relayUrl);
    const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
    const config = join(root, 'echo.json');
    writeFileSync(config, JSON.stringify({ name: 'qntm-echo-test', main: resolve('../echo-worker/src/index.ts'), compatibility_date: '2025-09-01',
      kv_namespaces: [{ binding: 'ECHO_KV', id: 'local-echo-test' }], vars: {
        RELAY_URL: relayUrl, CONV_ID_HEX: Buffer.from(f.conv.id).toString('hex'),
        IDENTITY_PRIVATE_KEY: b64(f.bot.privateKey), IDENTITY_PUBLIC_KEY: b64(f.bot.publicKey),
        CONV_ROOT_KEY: b64(f.conv.keys.root), CONV_AEAD_KEY: b64(f.conv.keys.aeadKey), CONV_NONCE_KEY: b64(f.conv.keys.nonceKey),
      } }));
    for (const [name, port, inspector, configArgs] of [['relay', relayPort, relayInspectorPort, []], ['echo', echoPort, echoInspectorPort, ['--config', config, '--test-scheduled']]] as const) {
      processes.push(new ManagedProcess(name, ['npx', 'wrangler', 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(inspector), '--name', `${basename(root).toLowerCase()}-${name}`, '--persist-to', join(root, name), ...configArgs], resolve(name === 'relay' ? '../worker' : '../echo-worker'), workerTestEnv(root)));
    }
    await processes[0].waitForHttp(`${relayUrl}/healthz`); await processes[1].waitForHttp(`${echoUrl}/healthz`);
  }, 60_000);
  afterAll(async () => { for (const p of processes) await p.stop(); if (root) rmSync(root, { force: true, recursive: true }); });

  it('replies with a signed encrypted echo after the real scheduled handler runs', async () => {
    const sent = await relay.postMessage(f.conv.id, f.message('worker cron roundtrip Ω'));
    const trigger = await fetch(`${echoUrl}/__scheduled`);
    expect(trigger.ok).toBe(true);
    await expect.poll(async () => {
      const received = await relay.receiveMessages(f.conv.id, sent);
      return received.messages.map(bytes => decryptMessage(deserializeEnvelope(bytes), f.conv)).some(message =>
        Buffer.from(message.inner.sender_kid).equals(Buffer.from(f.bot.keyID)) && new TextDecoder().decode(message.inner.body) === '🔒 echo: worker cron roundtrip Ω');
    }, { timeout: 20_000 }).toBe(true);
    expect(processes.find(p => p.name === 'echo')!.stdout).not.toContain('worker cron roundtrip');
  }, 30_000);
});
