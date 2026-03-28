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
 * Supports both native qntm envelopes AND bridge envelopes from
 * external integrations (APS, AgentID) that use the same XChaCha20-Poly1305
 * keys but different CBOR field names.
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
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import type { Identity, Conversation, ConversationKeys } from '@corpollc/qntm';

// ---- Minimal CBOR decoder for bridge envelope compatibility ----
// External integrations (APS, AgentID) use their own CBOR encoders with
// different field names. This decoder handles their format without requiring
// a full CBOR library dependency.

function decodeCBOR(data: Uint8Array): Record<string, unknown> {
  let offset = 0;

  function readByte(): number {
    if (offset >= data.length) throw new Error('CBOR: unexpected end');
    return data[offset++];
  }

  function readUint(additional: number): number {
    if (additional < 24) return additional;
    if (additional === 24) return readByte();
    if (additional === 25) {
      const hi = readByte(), lo = readByte();
      return (hi << 8) | lo;
    }
    if (additional === 26) {
      let val = 0;
      for (let i = 0; i < 4; i++) val = (val << 8) | readByte();
      return val;
    }
    if (additional === 27) {
      // 8-byte uint — use Number (safe for timestamps)
      let val = 0;
      for (let i = 0; i < 8; i++) val = val * 256 + readByte();
      return val;
    }
    throw new Error(`CBOR: unsupported additional info ${additional}`);
  }

  function readItem(): unknown {
    const byte = readByte();
    const major = byte >> 5;
    const additional = byte & 0x1f;

    switch (major) {
      case 0: // unsigned int
        return readUint(additional);
      case 1: // negative int
        return -1 - readUint(additional);
      case 2: { // byte string
        const len = readUint(additional);
        const bytes = data.slice(offset, offset + len);
        offset += len;
        return bytes;
      }
      case 3: { // text string
        const len = readUint(additional);
        const bytes = data.slice(offset, offset + len);
        offset += len;
        return new TextDecoder().decode(bytes);
      }
      case 4: { // array
        const len = readUint(additional);
        const arr: unknown[] = [];
        for (let i = 0; i < len; i++) arr.push(readItem());
        return arr;
      }
      case 5: { // map
        const len = readUint(additional);
        const map: Record<string, unknown> = {};
        for (let i = 0; i < len; i++) {
          const key = readItem();
          const value = readItem();
          map[String(key)] = value;
        }
        return map;
      }
      case 7: { // simple values + float
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null;
        throw new Error(`CBOR: unsupported simple value ${additional}`);
      }
      default:
        throw new Error(`CBOR: unsupported major type ${major}`);
    }
  }

  const result = readItem();
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new Error('CBOR: expected top-level map');
  }
  return result as Record<string, unknown>;
}

/**
 * Bridge envelope format used by external integrations (APS, AgentID).
 * These use the same XChaCha20-Poly1305 keys derived from the invite token
 * but wrap the ciphertext in a different CBOR structure:
 *   { v, conv, sender, seq, ts, nonce, ct, sig, aad }
 */
interface BridgeEnvelope {
  sender: Uint8Array;    // 16-byte sender ID
  nonce: Uint8Array;     // 24-byte XChaCha20 nonce
  ct: Uint8Array;        // ciphertext (XChaCha20-Poly1305)
  aad: Uint8Array;       // associated data (usually conv_id)
}

function tryDecodeBridgeEnvelope(raw: Uint8Array): BridgeEnvelope | null {
  try {
    const obj = decodeCBOR(raw);
    // Bridge envelopes have 'ct' and 'nonce' fields (not 'ciphertext' and 'msg_id')
    if (obj.ct instanceof Uint8Array && obj.nonce instanceof Uint8Array) {
      return {
        sender: obj.sender instanceof Uint8Array ? obj.sender : new Uint8Array(0),
        nonce: obj.nonce,
        ct: obj.ct,
        aad: obj.aad instanceof Uint8Array ? obj.aad : new Uint8Array(0),
      };
    }
    return null;
  } catch {
    return null;
  }
}

function decryptBridgeMessage(
  bridge: BridgeEnvelope,
  conversation: Conversation,
): { bodyText: string; senderHex: string } {
  const cipher = xchacha20poly1305(conversation.keys.aeadKey, bridge.nonce, bridge.aad);
  const plaintext = cipher.decrypt(bridge.ct);
  const bodyText = new TextDecoder().decode(plaintext);
  const senderHex = bytesToHex(bridge.sender);
  return { bodyText, senderHex };
}

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
  const convIdHex = bytesToHex(conversation.id).slice(0, 8);

  console.log(`[echo-bot:${convIdHex}] Polling from seq ${fromSeq} (cursor key: ${cursorKey})`);

  let result;
  try {
    result = await dropbox.receiveMessages(conversation.id, fromSeq);
  } catch (err) {
    console.error(`[echo-bot:${convIdHex}] receiveMessages failed:`, err);
    return 0;
  }

  console.log(`[echo-bot:${convIdHex}] Got ${result.messages.length} message(s), head_seq=${result.sequence}`);

  if (result.messages.length === 0) {
    if (result.sequence > fromSeq) {
      await setCursor(env.ECHO_KV, result.sequence, cursorKey);
    }
    return 0;
  }
  console.log(`[echo-bot:${convIdHex}] ${result.messages.length} new message(s) from seq ${fromSeq}`);

  let echoed = 0;

  for (const envelopeBytes of result.messages) {
    if (echoed >= MAX_ECHO_PER_TICK) {
      console.log(`[echo-bot:${convIdHex}] Hit max echo limit (${MAX_ECHO_PER_TICK}), deferring rest`);
      break;
    }

    try {
      let bodyText: string;
      let senderShort: string;
      let isSelfEcho = false;

      // Try native qntm envelope first
      try {
        const envelope = deserializeEnvelope(envelopeBytes);
        const message = decryptMessage(envelope, conversation);

        if (uint8ArrayEquals(message.inner.sender_kid, identity.keyID)) {
          isSelfEcho = true;
        }

        bodyText = new TextDecoder().decode(message.inner.body);
        senderShort = bytesToHex(message.inner.sender_kid).slice(0, 8);
      } catch {
        // Not a native qntm envelope — try bridge format (APS/AgentID)
        const bridge = tryDecodeBridgeEnvelope(envelopeBytes);
        if (!bridge) {
          console.error(`[echo-bot:${convIdHex}] Failed to decode message as native or bridge format`);
          continue;
        }

        const result = decryptBridgeMessage(bridge, conversation);
        bodyText = result.bodyText;
        senderShort = result.senderHex.slice(0, 8);

        // Check if sender matches our identity (unlikely for bridge messages)
        if (bridge.sender.length > 0 && uint8ArrayEquals(bridge.sender, identity.keyID)) {
          isSelfEcho = true;
        }

        console.log(`[echo-bot:${convIdHex}] Bridge message from ${senderShort}`);
      }

      if (isSelfEcho) continue;
      if (!bodyText.trim()) continue;

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

    // Manual trigger for testing — returns detailed diagnostics
    if (url.pathname === '/trigger' && request.method === 'POST') {
      const logs: string[] = [];
      const origLog = console.log;
      const origErr = console.error;
      console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); origLog(...args); };
      console.error = (...args: unknown[]) => { logs.push('[ERROR] ' + args.map(String).join(' ')); origErr(...args); };
      try {
        await handleCron(env);
        console.log = origLog;
        console.error = origErr;
        return new Response(JSON.stringify({ ok: true, triggered: true, logs }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        console.log = origLog;
        console.error = origErr;
        return new Response(JSON.stringify({ ok: false, error: String(err), stack: err instanceof Error ? err.stack : undefined, logs }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Replay messages from a specific seq for a conversation (skips cursor, no KV writes)
    if (url.pathname === '/replay' && request.method === 'POST') {
      try {
        const convIdx = parseInt(url.searchParams.get('conv') || '2', 10);
        const fromSeq = parseInt(url.searchParams.get('from_seq') || '0', 10);
        const identity = loadIdentity(env);
        const conversations = loadConversations(env, identity);
        const conv = conversations[convIdx - 1];
        if (!conv) {
          return new Response(JSON.stringify({ ok: false, error: `conv index ${convIdx} not found` }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        const dropbox = new DropboxClient(env.RELAY_URL);
        const convIdHex = bytesToHex(conv.id).slice(0, 8);
        const logs: string[] = [];
        const origLog = console.log;
        const origErr = console.error;
        console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); origLog(...args); };
        console.error = (...args: unknown[]) => { logs.push('[ERROR] ' + args.map(String).join(' ')); origErr(...args); };

        console.log(`[replay:${convIdHex}] Receiving from seq ${fromSeq}`);
        const result = await dropbox.receiveMessages(conv.id, fromSeq);
        console.log(`[replay:${convIdHex}] Got ${result.messages.length} message(s), head_seq=${result.sequence}`);

        let echoed = 0;
        for (const envelopeBytes of result.messages) {
          if (echoed >= MAX_ECHO_PER_TICK) break;
          try {
            let bodyText: string;
            let senderShort: string;
            let isSelfEcho = false;

            try {
              const envelope = deserializeEnvelope(envelopeBytes);
              const message = decryptMessage(envelope, conv);
              if (uint8ArrayEquals(message.inner.sender_kid, identity.keyID)) isSelfEcho = true;
              bodyText = new TextDecoder().decode(message.inner.body);
              senderShort = bytesToHex(message.inner.sender_kid).slice(0, 8);
              console.log(`[replay:${convIdHex}] Native message from ${senderShort}`);
            } catch (nativeErr) {
              console.log(`[replay:${convIdHex}] Native decode failed: ${nativeErr}, trying bridge...`);
              const bridge = tryDecodeBridgeEnvelope(envelopeBytes);
              if (!bridge) {
                console.error(`[replay:${convIdHex}] Bridge decode also failed`);
                continue;
              }
              const res = decryptBridgeMessage(bridge, conv);
              bodyText = res.bodyText;
              senderShort = res.senderHex.slice(0, 8);
              if (bridge.sender.length > 0 && uint8ArrayEquals(bridge.sender, identity.keyID)) isSelfEcho = true;
              console.log(`[replay:${convIdHex}] Bridge message from ${senderShort}: ${bodyText.slice(0, 80)}`);
            }

            if (isSelfEcho) { console.log(`[replay:${convIdHex}] Skipping self-echo`); continue; }
            if (!bodyText.trim()) continue;

            const echoText = `🔒 echo: ${bodyText}`;
            const echoBody = new TextEncoder().encode(echoText);
            const echoEnvelope = createMessage(identity, conv, 'text/plain', echoBody, undefined, defaultTTL());
            const echoBytes = serializeEnvelope(echoEnvelope);
            await dropbox.postMessage(conv.id, echoBytes);
            echoed++;
            console.log(`[replay:${convIdHex}] Echoed to ${senderShort}`);
          } catch (err) {
            console.error(`[replay:${convIdHex}] Message processing failed:`, err);
          }
        }

        console.log = origLog;
        console.error = origErr;
        return new Response(JSON.stringify({ ok: true, echoed, messages: result.messages.length, logs }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ ok: false, error: String(err), stack: err instanceof Error ? err.stack : undefined }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('qntm echo bot', { status: 200 });
  },
};
