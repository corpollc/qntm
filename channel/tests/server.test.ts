import { expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { z } from 'zod';
import { WebSocketServer } from 'ws';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateIdentity, createInvite, deriveConversationKeys, createConversation, createMessage, serializeEnvelope, decryptMessage, createReceiveEvent, defaultTTL } from '@corpollc/qntm';
import { ChannelInbox, saveJson } from '../inbox.js';

it('hands pending and live verified events to a real MCP client after initialization', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'qntm-mcp-channel-'));
  const me = generateIdentity(), peer = generateIdentity();
  const invite = createInvite(me, 'direct');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
  const id = hex(conversation.id);
  saveJson(join(directory, 'identity.json'), { private_key: hex(me.privateKey), public_key: hex(me.publicKey), key_id: hex(me.keyID) });
  saveJson(join(directory, 'conversations.json'), [{ id, type: 'direct', current_epoch: 0,
    keys: { root: hex(conversation.keys.root), aead_key: hex(conversation.keys.aeadKey), nonce_key: hex(conversation.keys.nonceKey) },
    participants: [hex(me.publicKey), hex(peer.publicKey)] }]);
  saveJson(join(directory, 'channel.json'), { conv_id_hex: id });
  saveJson(join(directory, 'sequence_cursors.json'), { [id]: 90 });
  const envelope = (identity: typeof me, bytes: Uint8Array) => createMessage(identity, conversation, 'text', bytes, undefined, defaultTTL());
  const old = envelope(peer, new TextEncoder().encode('pending before restart'));
  const cached = envelope(peer, new TextEncoder().encode('verified CLI history'));
  const cachedWire = serializeEnvelope(cached);
  saveJson(join(directory, 'chats', `${id}.json`), [{
    msg_id: hex(cached.msg_id), direction: 'incoming', body_type: 'text', created_ts: cached.created_ts,
    receive_event: createReceiveEvent(decryptMessage(cached, conversation), 1),
    envelope_sha256: createHash('sha256').update(cachedWire).digest('hex'),
  }]);
  const inboxPath = join(directory, 'channel-inbox', `${id}.json`);
  new ChannelInbox(inboxPath).capture(4, createReceiveEvent(decryptMessage(old, conversation), 4));
  const relay = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(relay, 'listening');
  const address = relay.address() as { port: number };
  let subscribedFrom: string | null = null;
  relay.on('connection', (socket, request) => {
    subscribedFrom = new URL(request.url!, 'http://localhost').searchParams.get('from_seq');
    const live = envelope(peer, new TextEncoder().encode('live'));
    const invalidCached = { ...cached, ciphertext: new Uint8Array(cached.ciphertext) };
    invalidCached.ciphertext[0] ^= 1;
    for (const [seq, msg] of [[5, live], [6, envelope(me, new TextEncoder().encode('self'))], [7, envelope(peer, new Uint8Array([255, 0]))], [8, invalidCached], [9, cached], [10, live]] as const) {
      socket.send(JSON.stringify({ type: 'message', seq, envelope_b64: Buffer.from(serializeEnvelope(msg)).toString('base64') }));
    }
    socket.send(JSON.stringify({ type: 'ready', head_seq: 10 }));
  });
  const transport = new StdioClientTransport({ command: 'bun', args: [resolve('server.ts'), '--config-dir', directory, '--history', '0', '--dropbox-url', `http://127.0.0.1:${address.port}`], stderr: 'pipe' });
  const client = new Client({ name: 'qntm-channel-test', version: '1' });
  const notifications: Array<{ content: string; meta: Record<string, string> }> = [];
  client.setNotificationHandler(z.object({ method: z.literal('notifications/claude/channel'), params: z.object({ content: z.string(), meta: z.record(z.string(), z.string()) }) }), message => {
    notifications.push(message.params);
  });
  try {
    await client.connect(transport);
    expect((await client.listTools()).tools.map(tool => tool.name)).toEqual(['qntm_reply']);
    await expect.poll(() => notifications.length).toBe(4);
    expect(subscribedFrom).toBe('4');
    expect(notifications.map(item => item.content)).toEqual(['pending before restart', 'live', '[binary base64: /wA=]', 'verified CLI history']);
    for (const notification of notifications) {
      expect(notification.meta).toMatchObject({ conversation_id: id, sender_kid: hex(peer.keyID), content_trust: 'untrusted' });
      expect(notification.meta.event_id).toMatch(new RegExp(`^qntm:${id}:`));
      expect(JSON.parse(notification.meta.charter_info).url).toBe(`https://charter.qntm.corpo.llc/v1/chain/${hex(peer.keyID)}`);
    }
    await expect.poll(() => JSON.parse(readFileSync(inboxPath, 'utf8')).pending.length).toBe(0);
    expect(JSON.parse(readFileSync(inboxPath, 'utf8')).cursor).toBe(10);
  } finally {
    await client.close();
    for (const socket of relay.clients) socket.terminate();
    await new Promise<void>(resolve => relay.close(() => resolve()));
    rmSync(directory, { recursive: true, force: true });
  }
}, 20_000);
