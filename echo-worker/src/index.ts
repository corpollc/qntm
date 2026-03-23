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
import type { Identity, Conversation, ConversationKeys } from '@corpollc/qntm';

interface Env {
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

  // Additional conversations (if configured)
  if (env.CONV2_ID_HEX && env.CONV2_AEAD_KEY && env.CONV2_NONCE_KEY && env.CONV2_ROOT_KEY) {
    const convId = hexToBytes(env.CONV2_ID_HEX);
    const keys: ConversationKeys = {
      root: base64ToBytes(env.CONV2_ROOT_KEY),
      aeadKey: base64ToBytes(env.CONV2_AEAD_KEY),
      nonceKey: base64ToBytes(env.CONV2_NONCE_KEY),
    };
    conversations.push({
      id: convId,
      name: 'qntm Echo Bot (Test)',
      type: 'direct',
      keys,
      participants: [identity.keyID],
      createdAt: new Date(),
      currentEpoch: 0,
    });
  }

  return conversations;
}

async function handleConversation(
  env: Env,
  identity: Identity,
  conversation: Conversation,
  dropbox: DropboxClient,
  cursorKeySuffix: string,
): Promise<number> {
  const cursorKey = `${CURSOR_KEY}${cursorKeySuffix}`;
  const fromSeq = await getCursor(env.ECHO_KV, cursorKey);

  const result = await dropbox.receiveMessages(conversation.id, fromSeq);

  if (result.messages.length === 0) {
    if (result.sequence > fromSeq) {
      await setCursor(env.ECHO_KV, result.sequence, cursorKey);
    }
    return 0;
  }

  const convIdHex = bytesToHex(conversation.id).slice(0, 8);
  console.log(`[echo-bot:${convIdHex}] ${result.messages.length} new message(s) from seq ${fromSeq}`);

  let echoed = 0;

  for (const envelopeBytes of result.messages) {
    if (echoed >= MAX_ECHO_PER_TICK) {
      console.log(`[echo-bot:${convIdHex}] Hit max echo limit (${MAX_ECHO_PER_TICK}), deferring rest`);
      break;
    }

    try {
      const envelope = deserializeEnvelope(envelopeBytes);
      const message = decryptMessage(envelope, conversation);

      if (uint8ArrayEquals(message.inner.sender_kid, identity.keyID)) {
        continue;
      }

      const bodyText = new TextDecoder().decode(message.inner.body);
      if (!bodyText.trim()) continue;

      const senderShort = bytesToHex(message.inner.sender_kid).slice(0, 8);
      console.log(`[echo-bot:${convIdHex}] From ${senderShort}: ${bodyText.slice(0, 100)}`);

      const echoText = `🔒 echo: ${bodyText}`;
      const echoBody = new TextEncoder().encode(echoText);
      const echoEnvelope = createMessage(
        identity,
        conversation,
        'text/plain',
        echoBody,
        undefined,
        defaultTTL(),
      );

      const echoBytes = serializeEnvelope(echoEnvelope);
      await dropbox.postMessage(conversation.id, echoBytes);
      echoed++;
      console.log(`[echo-bot:${convIdHex}] Echoed to ${senderShort}`);

    } catch (err) {
      console.error(`[echo-bot:${convIdHex}] Failed to process message:`, err);
    }
  }

  await setCursor(env.ECHO_KV, result.sequence, cursorKey);
  console.log(`[echo-bot:${convIdHex}] Cursor updated to ${result.sequence}, echoed ${echoed} message(s)`);
  return echoed;
}

async function handleCron(env: Env): Promise<void> {
  const identity = loadIdentity(env);
  const conversations = loadConversations(env, identity);
  const dropbox = new DropboxClient(env.RELAY_URL);

  let totalEchoed = 0;
  for (let i = 0; i < conversations.length; i++) {
    const suffix = i === 0 ? '' : `-conv${i + 1}`;
    totalEchoed += await handleConversation(env, identity, conversations[i], dropbox, suffix);
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

    // Manual trigger for testing
    if (url.pathname === '/trigger' && request.method === 'POST') {
      try {
        await handleCron(env);
        return new Response(JSON.stringify({ ok: true, triggered: true }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ ok: false, error: String(err) }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('qntm echo bot', { status: 200 });
  },
};
