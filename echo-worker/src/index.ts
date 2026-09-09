/**
 * qntm Echo Bot — Cloudflare Worker
 *
 * Cron-triggered worker that polls the qntm relay for new messages
 * and echoes them back encrypted. Proves E2E encryption works 24/7
 * without any host dependency.
 *
 * Architecture:
 * - Cron Trigger fires every 60 seconds
 * - Worker polls relay for new messages since last cursor
 * - Decrypts each message, echoes it back encrypted
 * - Stores cursor in KV for persistence across invocations
 *
 * Accepts authenticated native QSP envelopes. HTTP exposes health only;
 * private conversation content is never returned by diagnostics or logged.
 */

import {
  DropboxClient,
  createMessage,
  decryptMessage,
  deserializeEnvelope,
  serializeEnvelope,
  defaultTTL,
  keyIDFromPublicKey,
} from '@corpollc/qntm';
import { readRelayBatch } from './relay';
import type { Identity, Conversation, ConversationKeys } from '@corpollc/qntm';

export interface Env {
  ECHO_KV: KVNamespace;
  IDENTITY_PRIVATE_KEY: string;  // base64
  IDENTITY_PUBLIC_KEY: string;   // base64
  CONV_AEAD_KEY: string;         // base64
  CONV_NONCE_KEY: string;        // base64
  CONV_ROOT_KEY: string;         // base64
  CONV_ID_HEX: string;
  RELAY_URL: string;
  // Additional conversations (optional)
  CONV2_AEAD_KEY?: string;
  CONV2_NONCE_KEY?: string;
  CONV2_ROOT_KEY?: string;
  CONV2_ID_HEX?: string;
  CONV3_AEAD_KEY?: string;
  CONV3_NONCE_KEY?: string;
  CONV3_ROOT_KEY?: string;
  CONV3_ID_HEX?: string;
}

const CURSOR_KEY = 'echo-bot-cursor';
const MAX_ECHO_PER_TICK = 10;  // Safety: don't echo more than 10 per cron tick

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function loadIdentity(env: Env): Identity {
  const privateKey = base64ToBytes(env.IDENTITY_PRIVATE_KEY);
  const publicKey = base64ToBytes(env.IDENTITY_PUBLIC_KEY);
  const keyID = keyIDFromPublicKey(publicKey);
  return { privateKey, publicKey, keyID };
}

function loadConversation(env: Env, identity: Identity): Conversation {
  const convId = hexToBytes(env.CONV_ID_HEX);
  const keys: ConversationKeys = {
    root: base64ToBytes(env.CONV_ROOT_KEY),
    aeadKey: base64ToBytes(env.CONV_AEAD_KEY),
    nonceKey: base64ToBytes(env.CONV_NONCE_KEY),
  };

  return {
    id: convId,
    name: 'qntm Echo Bot',
    type: 'direct',
    keys,
    participants: [identity.keyID],
    createdAt: new Date(),
    currentEpoch: 0,
  };
}

async function getCursor(kv: KVNamespace, key: string = CURSOR_KEY): Promise<number> {
  const val = await kv.get(key);
  return val ? parseInt(val, 10) : 0;
}

async function setCursor(kv: KVNamespace, cursor: number, key: string = CURSOR_KEY): Promise<void> {
  await kv.put(key, String(cursor));
}

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function loadConversations(env: Env, identity: Identity): Conversation[] {
  const conversations: Conversation[] = [];

  // Primary conversation
  conversations.push(loadConversation(env, identity));

  // Additional conversations (if configured) — supports CONV2, CONV3, etc.
  const convPrefixes = ['CONV2', 'CONV3'] as const;
  const convNames = ['qntm Echo Bot (Test)', 'APS-Corpo Live Test'];
  for (let i = 0; i < convPrefixes.length; i++) {
    const prefix = convPrefixes[i];
    const idKey = `${prefix}_ID_HEX` as keyof Env;
    const aeadKey = `${prefix}_AEAD_KEY` as keyof Env;
    const nonceKey = `${prefix}_NONCE_KEY` as keyof Env;
    const rootKey = `${prefix}_ROOT_KEY` as keyof Env;
    if (env[idKey] && env[aeadKey] && env[nonceKey] && env[rootKey]) {
      const convId = hexToBytes(env[idKey] as string);
      const keys: ConversationKeys = {
        root: base64ToBytes(env[rootKey] as string),
        aeadKey: base64ToBytes(env[aeadKey] as string),
        nonceKey: base64ToBytes(env[nonceKey] as string),
      };
      conversations.push({
        id: convId,
        name: convNames[i] || `Echo Bot (Conv ${i + 2})`,
        type: 'direct',
        keys,
        participants: [identity.keyID],
        createdAt: new Date(),
        currentEpoch: 0,
      });
    }
  }

  return conversations;
}

export async function handleConversation(
  env: Env,
  identity: Identity,
  conversation: Conversation,
  dropbox: Pick<DropboxClient, 'postMessage'>,
  cursorKeySuffix: string,
  receive = readRelayBatch,
): Promise<number> {
  const cursorKey = `${CURSOR_KEY}${cursorKeySuffix}`;
  let cursor = await getCursor(env.ECHO_KV, cursorKey), echoed = 0;
  const originalCursor = cursor;
  try {
    const result = await receive(env.RELAY_URL, bytesToHex(conversation.id), cursor);
    for (const item of result.messages) {
      if (echoed >= MAX_ECHO_PER_TICK) break;
      let body: Uint8Array | undefined, sourceId = '';
      try {
        const envelope = deserializeEnvelope(item.envelope);
        const message = decryptMessage(envelope, conversation);
        sourceId = bytesToHex(envelope.msg_id);
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(message.inner.body);
        if (!uint8ArrayEquals(message.inner.sender_kid, identity.keyID) &&
            ['text', 'text/plain'].includes(message.inner.body_type) && text.trim()) {
          body = new TextEncoder().encode(`🔒 echo: ${text}`);
        }
      } catch { /* Invalid, expired, or unsigned legacy envelopes are not echoed. */ }
      if (body) {
        // Unique keys avoid KV's same-key write limit. Preserve the encrypted
        // response for replay after a failed send or interrupted cursor write.
        const responseKey = `${cursorKey}:response:${bytesToHex(conversation.id)}:${sourceId}`;
        const saved = await env.ECHO_KV.get(responseKey);
        let bytes: Uint8Array;
        if (saved) bytes = base64ToBytes(saved);
        else {
          bytes = serializeEnvelope(createMessage(identity, conversation, 'text/plain', body, undefined, defaultTTL()));
          await env.ECHO_KV.put(responseKey, btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')), { expirationTtl: 7 * 24 * 3600 });
        }
        await dropbox.postMessage(conversation.id, bytes);
        echoed++;
      }
      cursor = item.seq;
    }
    if (result.messages.length === 0) cursor = Math.max(cursor, result.sequence);
  } finally {
    // At most one cursor write per minute, including partial progress on error.
    if (cursor > originalCursor) await setCursor(env.ECHO_KV, cursor, cursorKey);
  }
  return echoed;
}

async function handleCron(env: Env): Promise<void> {
  const identity = loadIdentity(env);
  const conversations = loadConversations(env, identity);
  const dropbox = new DropboxClient(env.RELAY_URL);

  let totalEchoed = 0;
  for (let i = 0; i < conversations.length; i++) {
    const suffix = i === 0 ? '' : `-conv${i + 1}`;
    try { totalEchoed += await handleConversation(env, identity, conversations[i], dropbox, suffix); }
    catch { console.error('[echo-bot] Delivery interrupted; saved progress will retry on the next tick'); }
  }

  if (totalEchoed > 0) {
    console.log(`[echo-bot] Total echoed across ${conversations.length} conversation(s): ${totalEchoed}`);
  }
}

export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleCron(env));
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/healthz') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'qntm-echo-bot',
        ts: Date.now(),
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};
