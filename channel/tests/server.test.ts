import { expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { z } from 'zod';
import { WebSocketServer } from 'ws';
import { once } from 'node:events';
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
  const inboxPath = join(directory, 'channel-inbox', `${id}.json`);
  new ChannelInbox(inboxPath).capture(4, createReceiveEvent(decryptMessage(old, conversation), 4));
  const relay = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(relay, 'listening');
  const address = relay.address() as { port: number };
  let subscribedFrom: string | null = null;
  relay.on('connection', (socket, request) => {
    subscribedFrom = new URL(request.url!, 'http://localhost').searchParams.get('from_seq');
    for (const [seq, msg] of [[5, envelope(peer, new TextEncoder().encode('live'))], [6, envelope(me, new TextEncoder().encode('self'))], [7, envelope(peer, new Uint8Array([255, 0]))]] as const) {
      socket.send(JSON.stringify({ type: 'message', seq, envelope_b64: Buffer.from(serializeEnvelope(msg)).toString('base64') }));
    }
    socket.send(JSON.stringify({ type: 'ready', head_seq: 7 }));
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
    await expect.poll(() => notifications.length).toBe(3);
    expect(subscribedFrom).toBe('4');
    expect(notifications.map(item => item.content)).toEqual(['pending before restart', 'live', '[binary base64: /wA=]']);
    for (const notification of notifications) {
      expect(notification.meta).toMatchObject({ conversation_id: id, sender_kid: hex(peer.keyID), content_trust: 'untrusted' });
      expect(notification.meta.event_id).toMatch(new RegExp(`^qntm:${id}:`));
    }
    await expect.poll(() => JSON.parse(readFileSync(inboxPath, 'utf8')).pending.length).toBe(0);
    expect(JSON.parse(readFileSync(inboxPath, 'utf8')).cursor).toBe(7);
  } finally {
    await client.close();
    for (const socket of relay.clients) socket.terminate();
    await new Promise<void>(resolve => relay.close(() => resolve()));
    rmSync(directory, { recursive: true, force: true });
  }
}, 20_000);
