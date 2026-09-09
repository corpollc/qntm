#!/usr/bin/env bun
/**
 * qntm-channel — Claude Code channel bridge for qntm conversations.
 *
 * Makes Claude a first-class qntm peer. The channel maintains a single
 * conversation slot persisted in ~/.qntm/channel.json. On first run (empty
 * slot), Claude can either join via an invite token or create a new
 * conversation and offer an invite token. Once paired, the channel subscribes
 * for messages and exposes a reply tool.
 *
 * Shares ~/.qntm/ state (identity, cursors, history, seen) with the CLI/UI
 * so Claude acts as the identity owner, not a third participant.
 *
 * Usage:
 *   bun run server.ts [--config-dir ~/.qntm] [--dropbox-url URL] [--history 20]
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  deserializeIdentity,
  createInvite,
  inviteToToken,
  inviteFromURL,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  createMessage,
  decryptMessage,
  serializeEnvelope,
  deserializeEnvelope,
  defaultTTL,
  DropboxClient,
  base64UrlEncode,
  createReceiveEvent,
} from '@corpollc/qntm';
import type { DropboxSubscription, Identity, Conversation, ReceiveEvent } from '@corpollc/qntm';

import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';
import { ChannelInbox, saveJson } from './inbox.js';
const packageVersion = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

const { values: flags } = parseArgs({
  allowPositionals: true,
  options: {
    'config-dir': { type: 'string', default: join(homedir(), '.qntm') },
    'dropbox-url': { type: 'string', default: 'https://inbox.qntm.corpo.llc' },
    'poll-interval': { type: 'string', default: '3000' },
    'help': { type: 'boolean', short: 'h' },
    'history': { type: 'string', default: '20' },
  },
});

if (flags.help) {
  console.log('Usage: bun run server.ts [--config-dir DIR] [--dropbox-url URL] [--history COUNT]\nPersistent WebSocket receive bridge for Claude Code over MCP stdio.\n--history 0 disables startup history. --poll-interval is accepted but obsolete.');
  process.exit(0);
}

const CONFIG_DIR = flags['config-dir']!;
const DROPBOX_URL = flags['dropbox-url']!;
const HISTORY_COUNT = Number(flags['history']);
if (!Number.isSafeInteger(HISTORY_COUNT) || HISTORY_COUNT < 0) throw new Error('--history must be a nonnegative integer');

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function fromBase64(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(std);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function convIdToBytes(id: number[] | string): Uint8Array {
  if (Array.isArray(id)) return new Uint8Array(id);
  return fromHex(id);
}

function convIdToHex(id: number[] | string): string {
  if (Array.isArray(id)) return toHex(new Uint8Array(id));
  return id.toLowerCase();
}

function decodeKey(s: string): Uint8Array {
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 && s.length >= 32) {
    return fromHex(s);
  }
  return fromBase64(s);
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

function loadJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, 'utf-8')) as T;
}

// ---------------------------------------------------------------------------
// Load identity
// ---------------------------------------------------------------------------

function loadIdentity(): Identity {
  const path = join(CONFIG_DIR, 'identity.json');
  if (!existsSync(path)) {
    console.error(`No identity found at ${path}. Run 'qntm identity generate' first.`);
    process.exit(1);
  }

  const raw = readFileSync(path);

  // Try CBOR first (TS client / Go CLI format)
  try {
    return deserializeIdentity(new Uint8Array(raw));
  } catch { /* fall through */ }

  // Try JSON (Python CLI format)
  try {
    const obj = JSON.parse(raw.toString('utf-8'));
    return {
      privateKey: fromHex(obj.private_key),
      publicKey: fromHex(obj.public_key),
      keyID: fromHex(obj.key_id),
    };
  } catch {
    console.error(`Failed to parse identity at ${path}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Conversation slot — persisted in ~/.qntm/channel.json
// ---------------------------------------------------------------------------

interface ChannelSlot {
  conv_id_hex: string;
}

const SLOT_PATH = join(CONFIG_DIR, 'channel.json');

function loadSlot(): ChannelSlot | null {
  return loadJson<ChannelSlot | null>(SLOT_PATH, null);
}

function saveSlot(slot: ChannelSlot): void {
  saveJson(SLOT_PATH, slot);
}

// ---------------------------------------------------------------------------
// Conversation record format (on-disk, Go/UI or Python CLI)
// ---------------------------------------------------------------------------

interface DiskConvRecord {
  id: number[] | string;
  name?: string;
  type: string;
  keys: { root: string; aead_key: string; nonce_key: string };
  participants: string[];
  created_at?: string;
  current_epoch: number;
  invite_token?: string;
}

function findConversation(idHex: string): DiskConvRecord | null {
  const convs = loadJson<DiskConvRecord[]>(join(CONFIG_DIR, 'conversations.json'), []);
  return convs.find((c) => convIdToHex(c.id) === idHex) || null;
}

function convToCrypto(rec: DiskConvRecord): Conversation {
  return {
    id: convIdToBytes(rec.id),
    type: rec.type as 'direct' | 'group' | 'announce',
    keys: {
      root: decodeKey(rec.keys.root),
      aeadKey: decodeKey(rec.keys.aead_key),
      nonceKey: decodeKey(rec.keys.nonce_key),
    },
    participants: rec.participants.map((p) => decodeKey(p)),
    currentEpoch: rec.current_epoch,
    createdAt: new Date(),
  };
}

/** Save a new Conversation object to conversations.json in Go/UI-compatible format */
function persistConversation(conv: Conversation, name: string, token?: string): void {
  const convs = loadJson<DiskConvRecord[]>(join(CONFIG_DIR, 'conversations.json'), []);
  const idHex = toHex(conv.id);

  // Don't duplicate
  if (convs.some((c) => convIdToHex(c.id) === idHex)) return;

  const record: DiskConvRecord = {
    id: Array.from(conv.id),
    name,
    type: conv.type,
    keys: {
      root: toBase64(conv.keys.root),
      aead_key: toBase64(conv.keys.aeadKey),
      nonce_key: toBase64(conv.keys.nonceKey),
    },
    participants: conv.participants.map((p) => base64UrlEncode(p)),
    created_at: new Date().toISOString(),
    current_epoch: conv.currentEpoch,
  };
  if (token) record.invite_token = token;

  convs.push(record);
  saveJson(join(CONFIG_DIR, 'conversations.json'), convs);
}

// ---------------------------------------------------------------------------
// Shared cursor & seen state
// ---------------------------------------------------------------------------

function loadCursors(): Record<string, number> {
  return loadJson(join(CONFIG_DIR, 'sequence_cursors.json'), {});
}

function saveCursors(cursors: Record<string, number>): void {
  saveJson(join(CONFIG_DIR, 'sequence_cursors.json'), cursors);
}

function loadSeen(): Record<string, Record<string, boolean>> {
  return loadJson(join(CONFIG_DIR, 'seen_messages.json'), {});
}

function saveSeen(seen: Record<string, Record<string, boolean>>): void {
  saveJson(join(CONFIG_DIR, 'seen_messages.json'), seen);
}

// ---------------------------------------------------------------------------
// Chat history
// ---------------------------------------------------------------------------

interface HistoryEntry {
  msg_id: string;
  direction: string;
  sender_kid?: string;
  body_type: string;
  unsafe_body?: string;
  unsafe_body_b64?: string;
  created_ts: number;
  body?: string;
  receive_event?: ReceiveEvent;
}

function loadHistory(convIdHex: string): HistoryEntry[] {
  const chatsDir = join(CONFIG_DIR, 'chats');
  mkdirSync(chatsDir, { recursive: true });
  return loadJson(join(chatsDir, `${convIdHex}.json`), []);
}

function saveHistory(convIdHex: string, entries: HistoryEntry[]): void {
  const chatsDir = join(CONFIG_DIR, 'chats');
  mkdirSync(chatsDir, { recursive: true });
  saveJson(join(chatsDir, `${convIdHex}.json`), entries);
}

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

function loadNames(): Record<string, string> {
  return loadJson(join(CONFIG_DIR, 'names.json'), {});
}

function resolveName(kid: string, names: Record<string, string>): string {
  if (names[kid]) return names[kid];
  for (const [k, v] of Object.entries(names)) {
    if (k.startsWith(kid) || kid.startsWith(k)) return v;
  }
  return kid.substring(0, 8);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

const identity = loadIdentity();
const dropbox = new DropboxClient(DROPBOX_URL);
const names = loadNames();
const myKidHex = toHex(identity.keyID);

// Check the slot
const slot = loadSlot();

// Active bridge state (set after pairing)
let convIdHex: string | null = null;
let convCrypto: Conversation | null = null;
let convName: string | null = null;
let liveSubscription: DropboxSubscription | null = null;
let inbox: ChannelInbox | null = null;

if (slot) {
  const rec = findConversation(slot.conv_id_hex);
  if (rec) {
    convIdHex = slot.conv_id_hex;
    convCrypto = convToCrypto(rec);
    convName = rec.name || convIdHex;
  } else {
    console.error(`[qntm-channel] slot points to ${slot.conv_id_hex} but conversation not found — clearing`);
    saveSlot(null as unknown as ChannelSlot);
  }
}

const paired = convIdHex !== null;
console.error(`[qntm-channel] identity: ${myKidHex.substring(0, 8)}`);
if (paired) {
  console.error(`[qntm-channel] bridging conversation: ${convName}`);
} else {
  console.error(`[qntm-channel] no conversation paired — waiting for join or create`);
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

const unpairedInstructions = [
  `You are a qntm peer but not yet connected to a conversation.`,
  `Your identity on the network is "${resolveName(myKidHex, names)}" (${myKidHex.substring(0, 8)}).`,
  `To get started, either:`,
  `  1. Use qntm_join with an invite token/URL to join an existing conversation`,
  `  2. Use qntm_create to create a new conversation and get an invite token to share`,
  `Once paired, you'll receive messages and can reply via qntm_reply.`,
].join('\n');

const pairedInstructions = [
  `You are connected to a qntm encrypted conversation "${convName}".`,
  `Messages arrive as <channel source="qntm" sender="..." body_type="...">. `,
  `Reply using the qntm_reply tool. You do not need to pass a conversation ID — there is only one.`,
  `Your identity on the network is "${resolveName(myKidHex, names)}" (${myKidHex.substring(0, 8)}).`,
  `Messages with body_type="text" are chat messages. Other body_types are protocol events — read them for context.`,
].join('\n');

const mcp = new Server(
  { name: 'qntm', version: packageVersion },
  {
    capabilities: {
      experimental: { 'claude/channel': {} },
      tools: {},
    },
    instructions: paired ? pairedInstructions : unpairedInstructions,
  },
);

// ---------------------------------------------------------------------------
// Tools — dynamic based on pairing state
// ---------------------------------------------------------------------------

mcp.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [];

  if (!convIdHex) {
    // Unpaired: offer join and create
    tools.push({
      name: 'qntm_join',
      description: 'Join a qntm conversation using an invite token or URL',
      inputSchema: {
        type: 'object' as const,
        properties: {
          invite: {
            type: 'string',
            description: 'Invite token or URL (e.g. from qntm convo create)',
          },
          name: {
            type: 'string',
            description: 'Local name for this conversation',
          },
        },
        required: ['invite'],
      },
    });
    tools.push({
      name: 'qntm_create',
      description: 'Create a new qntm conversation and get an invite token to share',
      inputSchema: {
        type: 'object' as const,
        properties: {
          name: {
            type: 'string',
            description: 'Local name for this conversation',
          },
        },
        required: ['name'],
      },
    });
  } else {
    // Paired: offer reply
    tools.push({
      name: 'qntm_reply',
      description: 'Send a message in the qntm conversation',
      inputSchema: {
        type: 'object' as const,
        properties: {
          text: {
            type: 'string',
            description: 'The message text to send',
          },
        },
        required: ['text'],
      },
    });
  }

  return { tools };
});

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

async function activateBridge(conv: Conversation, idHex: string, name: string): Promise<void> {
  convIdHex = idHex;
  convCrypto = conv;
  convName = name;
  saveSlot({ conv_id_hex: idHex });
  startSubscription();
  // Notify Claude Code that the tool list has changed (join/create → reply)
  await mcp.sendToolListChanged();
  console.error(`[qntm-channel] paired to: ${name} (${idHex.substring(0, 8)})`);
}

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  const toolName = req.params.name;

  // --- qntm_join ---
  if (toolName === 'qntm_join') {
    if (convIdHex) {
      return { content: [{ type: 'text', text: 'Already paired to a conversation. Restart to re-pair.' }] };
    }

    const { invite: inviteStr, name } = req.params.arguments as { invite: string; name?: string };

    const invitePayload = inviteFromURL(inviteStr);
    const keys = deriveConversationKeys(invitePayload);
    const conv = createConversation(invitePayload, keys);
    addParticipant(conv, identity.publicKey);

    const idHex = toHex(conv.id);
    const localName = name || `Channel ${idHex.substring(0, 8)}`;

    persistConversation(conv, localName, inviteStr);
    await activateBridge(conv, idHex, localName);

    return {
      content: [{ type: 'text', text: `Joined conversation "${localName}" (${idHex.substring(0, 8)}). Now listening for messages.` }],
    };
  }

  // --- qntm_create ---
  if (toolName === 'qntm_create') {
    if (convIdHex) {
      return { content: [{ type: 'text', text: 'Already paired to a conversation. Restart to re-pair.' }] };
    }

    const { name } = req.params.arguments as { name: string };

    const invitePayload = createInvite(identity, 'direct');
    const keys = deriveConversationKeys(invitePayload);
    const conv = createConversation(invitePayload, keys);
    addParticipant(conv, identity.publicKey);

    const token = inviteToToken(invitePayload);
    const idHex = toHex(conv.id);

    persistConversation(conv, name, token);
    await activateBridge(conv, idHex, name);

    return {
      content: [{ type: 'text', text: `Created conversation "${name}". Share this invite token with the other party:\n\n${token}` }],
    };
  }

  // --- qntm_reply ---
  if (toolName === 'qntm_reply') {
    if (!convIdHex || !convCrypto) {
      return { content: [{ type: 'text', text: 'Not paired to a conversation yet. Use qntm_join or qntm_create first.' }] };
    }

    const { text } = req.params.arguments as { text: string };

    const body = new TextEncoder().encode(text);
    const envelope = createMessage(identity, convCrypto, 'text', body, undefined, defaultTTL());
    const envelopeBytes = serializeEnvelope(envelope);
    const seq = await dropbox.postMessage(convCrypto.id, envelopeBytes);

    const msgIdHex = toHex(envelope.msg_id);
    const history = loadHistory(convIdHex);
    history.push({
      msg_id: msgIdHex,
      direction: 'outgoing',
      body_type: 'text',
      body: text,
      created_ts: envelope.created_ts,
    });
    saveHistory(convIdHex, history);

    console.error(`[qntm-channel] sent message (seq=${seq})`);
    return { content: [{ type: 'text', text: `sent (seq=${seq})` }] };
  }

  throw new Error(`unknown tool: ${toolName}`);
});

// ---------------------------------------------------------------------------
// Connect MCP
// ---------------------------------------------------------------------------

mcp.oninitialized = () => { if (paired) startSubscription(); };
await mcp.connect(new StdioServerTransport());

// ---------------------------------------------------------------------------
// History + live subscription (only when paired)
// ---------------------------------------------------------------------------

async function emitHistory(): Promise<void> {
  if (!convIdHex || HISTORY_COUNT === 0) return;

  const history = loadHistory(convIdHex);
  if (history.length === 0) return;

  const recent = history.slice(-HISTORY_COUNT);
  const lines = recent.map((entry) => {
    const sender =
      entry.direction === 'outgoing'
        ? 'you'
        : resolveName(entry.sender_kid || '???', names);
    const body = entry.unsafe_body || entry.body || '[binary]';
    const time = new Date(entry.created_ts * 1000).toISOString();
    return `[${time}] ${sender}: ${body}`;
  });

  await mcp.notification({
    method: 'notifications/claude/channel',
    params: {
      content: lines.join('\n'),
      meta: { context: 'history', count: String(recent.length) },
    },
  });
  console.error(`[qntm-channel] sent ${recent.length} history entries`);
}

async function deliverEvent(event: ReceiveEvent): Promise<void> {
  await mcp.notification({
    method: 'notifications/claude/channel',
    params: {
      content: event.message.unsafe_body ?? `[binary base64: ${event.message.unsafe_body_b64}]`,
      meta: {
        sender: resolveName(event.message.sender_kid, loadNames()),
        sender_kid: event.message.sender_kid,
        body_type: event.message.body_type,
        event_id: event.event_id,
        conversation_id: event.conversation_id,
        sequence: String(event.sequence),
        content_trust: 'untrusted',
      },
    },
  });
}

function drainInbox(): void {
  void inbox?.drain(deliverEvent).catch(error => {
    console.error(`[qntm-channel] notification pending; retrying: ${error}`);
  });
}

async function handleEnvelope(rawEnvBytes: Uint8Array, seq: number): Promise<void> {
  if (!convIdHex || !convCrypto || !inbox || seq <= inbox.cursor) return;
  const history = loadHistory(convIdHex);
  let event: ReceiveEvent;
  try {
    const envelope = deserializeEnvelope(rawEnvBytes);
    // A CLI receiver may already have advanced the epoch. Its verified history
    // preserves this event, but its shared cursor never acknowledges our handoff.
    const previous = history.find(entry => entry.msg_id === toHex(envelope.msg_id))?.receive_event;
    if (previous?.message.verified && previous.conversation_id === convIdHex) {
      event = { ...previous, sequence: seq, message: { ...previous.message, sequence: seq } };
    } else {
      const record = findConversation(convIdHex);
      if (record) convCrypto = convToCrypto(record);
      event = createReceiveEvent(decryptMessage(envelope, convCrypto), seq);
    }
  } catch (error) {
    console.error(`[qntm-channel] rejected envelope at sequence ${seq}: ${error}`);
    inbox.capture(seq);
    return;
  }

  const incoming = event.message.sender_kid !== myKidHex;
  // This single durable write captures the payload and advances our own cursor.
  // Shared history/seen files are conveniences, never the delivery authority.
  inbox.capture(seq, incoming ? event : undefined);
  if (!history.some(entry => entry.msg_id === event.message.message_id)) {
    history.push({
      msg_id: event.message.message_id,
      direction: incoming ? 'incoming' : 'outgoing',
      sender_kid: event.message.sender_kid,
      body_type: event.message.body_type,
      unsafe_body: event.message.unsafe_body,
      unsafe_body_b64: event.message.unsafe_body_b64,
      created_ts: event.message.created_ts,
      receive_event: event,
    });
    saveHistory(convIdHex, history);
  }
  const seen = loadSeen();
  seen[convIdHex] = { ...seen[convIdHex], [event.message.message_id]: true };
  saveSeen(seen);
  const cursors = loadCursors();
  cursors[convIdHex] = Math.max(cursors[convIdHex] || 0, seq);
  saveCursors(cursors);
  drainInbox();
}

function startSubscription(): void {
  if (!convIdHex || !convCrypto || liveSubscription) return;
  inbox = new ChannelInbox(join(CONFIG_DIR, 'channel-inbox', `${convIdHex}.json`), loadCursors()[convIdHex] || 0);
  console.error('[qntm-channel] starting live relay subscription');
  void emitHistory().catch(error => console.error(`[qntm-channel] history notification failed: ${error}`));
  drainInbox();
  const retryTimer = setInterval(drainInbox, 1000);
  retryTimer.unref();
  liveSubscription = dropbox.subscribeMessages(convCrypto.id, inbox.cursor, {
    getCursor: () => inbox!.cursor,
    onMessage: async ({ seq, envelope }) => { await handleEnvelope(envelope, seq); },
    onError: (err) => { console.error(`[qntm-channel] relay subscription error: ${err}`); },
    onReconnect: (attempt, delayMs) => {
      console.error(`[qntm-channel] relay reconnect attempt ${attempt} in ${delayMs}ms`);
    },
  });
}
