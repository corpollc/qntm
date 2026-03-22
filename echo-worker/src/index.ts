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

async function getCursor(kv: KVNamespace): Promise<number> {
  const val = await kv.get(CURSOR_KEY);
  return val ? parseInt(val, 10) : 0;
}

async function setCursor(kv: KVNamespace, cursor: number): Promise<void> {
  await kv.put(CURSOR_KEY, String(cursor));
}

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function handleCron(env: Env): Promise<void> {
  const identity = loadIdentity(env);
  const conversation = loadConversation(env, identity);
  const dropbox = new DropboxClient(env.RELAY_URL);

  // Get cursor
  const fromSeq = await getCursor(env.ECHO_KV);

  // Poll for new messages
  const result = await dropbox.receiveMessages(conversation.id, fromSeq);

  if (result.messages.length === 0) {
    // No new messages — just update cursor if it advanced
    if (result.sequence > fromSeq) {
      await setCursor(env.ECHO_KV, result.sequence);
    }
    return;
  }

  console.log(`[echo-bot] ${result.messages.length} new message(s) from seq ${fromSeq}`);

  let echoed = 0;

  for (const envelopeBytes of result.messages) {
    if (echoed >= MAX_ECHO_PER_TICK) {
      console.log(`[echo-bot] Hit max echo limit (${MAX_ECHO_PER_TICK}), deferring rest`);
      break;
    }

    try {
      // Deserialize and decrypt
      const envelope = deserializeEnvelope(envelopeBytes);
      const message = decryptMessage(envelope, conversation);

      // Skip our own messages
      if (uint8ArrayEquals(message.inner.sender_kid, identity.keyID)) {
        continue;
      }

      // Get body text
      const bodyText = new TextDecoder().decode(message.inner.body);
      if (!bodyText.trim()) continue;

      const senderShort = bytesToHex(message.inner.sender_kid).slice(0, 8);
      console.log(`[echo-bot] From ${senderShort}: ${bodyText.slice(0, 100)}`);

      // Create echo response
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

      // Serialize and send
      const echoBytes = serializeEnvelope(echoEnvelope);
      await dropbox.postMessage(conversation.id, echoBytes);
      echoed++;
      console.log(`[echo-bot] Echoed to ${senderShort}`);

    } catch (err) {
      console.error(`[echo-bot] Failed to process message:`, err);
      // Continue processing other messages
    }
  }

  // Update cursor
  await setCursor(env.ECHO_KV, result.sequence);
  console.log(`[echo-bot] Cursor updated to ${result.sequence}, echoed ${echoed} message(s)`);
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
