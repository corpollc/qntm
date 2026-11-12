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
import { createHash } from 'node:crypto';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  deserializeIdentity,
  validateIdentity,
  keyIDFromPublicKey,
  parseGatewayBody,
  matchesGatewayAcceptance,
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
  if (/^[0-9a-fA-F]+$/.test(s) && (s.length === 32 || s.length === 64)) {
    return fromHex(s);
  }
  return fromBase64(s);
}

const CONTROL_OR_BIDI_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/** Sanitize untrusted conversation/peer labels before inline interpolation. */
function sanitizeInlineLabel(value: string, maxLen = 120): string {
  const cleaned = value
    .replace(/[\r\n\t]+/g, ' ')
    .replace(CONTROL_OR_BIDI_RE, '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, "'")
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .trim();
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen - 1)}\u2026` : cleaned;
}

/** Prevent `<channel>` / `</channel>` tag breakout and control/bidi injection in live deliveries. */
function escapeChannelContent(value: string): string {
  return value
    .replace(CONTROL_OR_BIDI_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .replace(/<(\/?\s*channel\b)/gi, '&lt;$1');
}

/** Escape untrusted history entries onto strictly delimited single lines. */
function formatHistoryBody(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(CONTROL_OR_BIDI_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
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
    const parsed = deserializeIdentity(new Uint8Array(raw));
    validateIdentity(parsed);
    return parsed;
  } catch { /* fall through */ }

  // Try JSON (Python CLI format)
  try {
    const obj = JSON.parse(raw.toString('utf-8'));
    const parsed: Identity = {
      privateKey: fromHex(obj.private_key),
      publicKey: fromHex(obj.public_key),
      keyID: fromHex(obj.key_id),
    };
    validateIdentity(parsed);
    return parsed;
  } catch {
    console.error(`Failed to parse or validate identity at ${path}`);
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

interface DiskGatewayInfo {
  status?: string;
  keyId?: string;
  key_id?: string;
  kid?: string;
  publicKey?: string;
  public_key?: string;
  invitationId?: string;
  invitation_id?: string;
}

interface DiskConvRecord {
  id: number[] | string;
  name?: string;
  type: string;
  keys: {
    root: string;
    aead_key?: string;
    aeadKey?: string;
    nonce_key?: string;
    nonceKey?: string;
  };
  participants: string[];
  created_at?: string;
  createdAt?: string;
  current_epoch?: number;
  currentEpoch?: number;
  invite_token?: string;
  excluded?: boolean;
  removed?: boolean;
  needs_rekey?: boolean;
  needsRekey?: boolean;
  pending_control?: unknown;
  recovery_required?: boolean;
  gateway?: DiskGatewayInfo | null;
  group_control?: { removed?: boolean; needs_rekey?: boolean } | null;
  groupControl?: { removed?: boolean; needsRekey?: boolean } | null;
  session?: {
    removed?: boolean;
    needsRekey?: boolean;
    participants?: Record<string, string>;
    gateway?: {
      accepted?: boolean;
      invitation?: { body?: { invitation_id?: string; gateway_kid?: string } };
      context?: { gateway?: { kid?: string; publicKey?: string } };
    };
  } | null;
}

function findConversation(idHex: string): DiskConvRecord | null {
  const convs = loadJson<DiskConvRecord[]>(join(CONFIG_DIR, 'conversations.json'), []);
  return convs.find((c) => convIdToHex(c.id) === idHex) || null;
}

function convToCrypto(rec: DiskConvRecord): Conversation {
  const aeadRaw = rec.keys.aead_key ?? rec.keys.aeadKey;
  const nonceRaw = rec.keys.nonce_key ?? rec.keys.nonceKey;
  if (!rec.keys.root || !aeadRaw || !nonceRaw) {
    throw new Error('Conversation keys are incomplete');
  }
  return {
    id: convIdToBytes(rec.id),
    type: rec.type as 'direct' | 'group' | 'announce',
    keys: {
      root: decodeKey(rec.keys.root),
      aeadKey: decodeKey(aeadRaw),
      nonceKey: decodeKey(nonceRaw),
    },
    participants: (rec.participants || []).map((p) => decodeKey(p)),
    currentEpoch: rec.current_epoch ?? rec.currentEpoch ?? 0,
    createdAt: new Date(),
  };
}

function resolveActiveGateway(rec: DiskConvRecord | null): { kidHex: string; publicKeyHex?: string } | null {
  if (!rec) return null;
  if (rec.session?.gateway?.accepted && rec.session.gateway.context?.gateway?.kid) {
    const kidHex = toHex(decodeKey(rec.session.gateway.context.gateway.kid));
    const publicKeyHex = rec.session.gateway.context.gateway.publicKey
      ? toHex(decodeKey(rec.session.gateway.context.gateway.publicKey))
      : undefined;
    return { kidHex, publicKeyHex };
  }
  const gw = rec.gateway;
  if (gw && gw.status === 'active') {
    const rawKid = gw.keyId ?? gw.key_id ?? gw.kid;
    if (rawKid) {
      const kidHex = toHex(decodeKey(rawKid));
      const rawPk = gw.publicKey ?? gw.public_key;
      const publicKeyHex = rawPk ? toHex(decodeKey(rawPk)) : undefined;
      return { kidHex, publicKeyHex };
    }
  }
  return null;
}

function checkSendEligibility(rec: DiskConvRecord, crypto: Conversation, localIdentity: Identity): string | null {
  if (rec.excluded || rec.removed || rec.group_control?.removed || rec.groupControl?.removed || rec.session?.removed) {
    return 'Cannot reply: local identity has been removed from this conversation.';
  }
  if (rec.recovery_required) {
    return 'Cannot reply: group conversation requires key recovery.';
  }
  if (rec.needs_rekey || rec.needsRekey || rec.pending_control || rec.group_control?.needs_rekey || rec.groupControl?.needsRekey || rec.session?.needsRekey) {
    return 'Cannot reply: complete pending group key rotation before sending.';
  }
  const localKidHex = toHex(localIdentity.keyID);
  const localPkHex = toHex(localIdentity.publicKey);
  if (rec.session?.participants && Object.keys(rec.session.participants).length > 0) {
    const localKidB64 = base64UrlEncode(localIdentity.keyID);
    if (!Object.prototype.hasOwnProperty.call(rec.session.participants, localKidB64)) {
      return 'Cannot reply: local identity is not in the active session participant set.';
    }
  }
  if (rec.type === 'group' && crypto.currentEpoch > 0 && crypto.participants.length > 0) {
    const inRoster = crypto.participants.some((entry) => {
      const hex = toHex(entry);
      if (hex === localPkHex || hex === localKidHex) return true;
      if (entry.length === 32 && toHex(keyIDFromPublicKey(entry)) === localKidHex) return true;
      return false;
    });
    if (!inRoster) {
      return 'Cannot reply: local identity is not in the current group epoch roster.';
    }
  }
  return null;
}

const GATEWAY_ONLY_BODY_TYPES = new Set([
  'gate.executed',
  'gate.result',
  'gate.expired',
  'gate.invalidated',
  'gate.config',
  'gov.applied',
  'gov.invalidated',
]);

const PARTICIPANT_GATEWAY_BODY_TYPES = new Set([
  'gate.promote',
  'gate.request',
  'gate.approval',
  'gate.disapproval',
  'gate.secret',
  'gov.propose',
  'gov.approve',
  'gov.disapprove',
]);

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
  envelope_sha256?: string;
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
  const saved = loadJson<Record<string, unknown>>(join(CONFIG_DIR, 'names.json'), {});
  const names = saved.identities && typeof saved.identities === 'object' ? saved.identities : saved;
  return Object.fromEntries(Object.entries(names).filter((entry): entry is [string, string] => typeof entry[1] === 'string'));
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
    convName = sanitizeInlineLabel(rec.name || convIdHex);
  } else {
    console.error(`[qntm-channel] slot points to ${slot.conv_id_hex} but conversation not found — clearing`);
    saveSlot(null as unknown as ChannelSlot);
  }
}

const paired = convIdHex !== null;
const safeSelfName = sanitizeInlineLabel(resolveName(myKidHex, names));
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
  `Your identity on the network is "${safeSelfName}" (${myKidHex.substring(0, 8)}).`,
  `To get started, either:`,
  `  1. Use qntm_join with an invite token/URL to join an existing conversation`,
  `  2. Use qntm_create to create a new conversation and get an invite token to share`,
  `Once paired, you'll receive messages and can reply via qntm_reply.`,
].join('\n');

const pairedInstructions = [
  `You are connected to a qntm encrypted conversation "${convName ?? ''}".`,
  `Messages arrive as <channel source="qntm" sender="..." body_type="...">. `,
  `Reply using the qntm_reply tool. You do not need to pass a conversation ID — there is only one.`,
  `Your identity on the network is "${safeSelfName}" (${myKidHex.substring(0, 8)}).`,
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
  const safeName = sanitizeInlineLabel(name);
  convIdHex = idHex;
  convCrypto = conv;
  convName = safeName;
  saveSlot({ conv_id_hex: idHex });
  startSubscription();
  // Notify Claude Code that the tool list has changed (join/create → reply)
  await mcp.sendToolListChanged();
  console.error(`[qntm-channel] paired to: ${safeName} (${idHex.substring(0, 8)})`);
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
    const localName = sanitizeInlineLabel(name || `Channel ${idHex.substring(0, 8)}`) || `Channel ${idHex.substring(0, 8)}`;

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
    const safeName = sanitizeInlineLabel(name) || `Channel ${idHex.substring(0, 8)}`;

    persistConversation(conv, safeName, token);
    await activateBridge(conv, idHex, safeName);

    return {
      content: [{ type: 'text', text: `Created conversation "${safeName}". Share this invite token with the other party:\n\n${token}` }],
    };
  }

  // --- qntm_reply ---
  if (toolName === 'qntm_reply') {
    if (!convIdHex || !convCrypto) {
      return { content: [{ type: 'text', text: 'Not paired to a conversation yet. Use qntm_join or qntm_create first.' }] };
    }

    const record = findConversation(convIdHex);
    if (!record) {
      return { isError: true, content: [{ type: 'text', text: 'Conversation not found in conversations.json.' }] };
    }
    const freshCrypto = convToCrypto(record);
    const blockedReason = checkSendEligibility(record, freshCrypto, identity);
    if (blockedReason) {
      return { isError: true, content: [{ type: 'text', text: blockedReason }] };
    }
    convCrypto = freshCrypto;
    convName = sanitizeInlineLabel(record.name || convIdHex);

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

  const currentNames = loadNames();
  const recent = history.slice(-HISTORY_COUNT);
  const lines = recent.map((entry) => {
    const sender =
      entry.direction === 'outgoing'
        ? 'you'
        : sanitizeInlineLabel(resolveName(entry.sender_kid || '???', currentNames));
    const body = formatHistoryBody(entry.unsafe_body || entry.body || '[binary]');
    const time = new Date(entry.created_ts * 1000).toISOString();
    return `[${time}] ${sender}: ${body}`;
  });

  await mcp.notification({
    method: 'notifications/claude/channel',
    params: {
      content: lines.join('\n'),
      meta: { context: 'history', count: String(recent.length), content_trust: 'untrusted' },
    },
  });
  console.error(`[qntm-channel] sent ${recent.length} history entries`);
}

async function deliverEvent(event: ReceiveEvent): Promise<void> {
  const content = event.message.unsafe_body !== undefined
    ? escapeChannelContent(event.message.unsafe_body)
    : `[binary base64: ${event.message.unsafe_body_b64}]`;
  await mcp.notification({
    method: 'notifications/claude/channel',
    params: {
      content,
      meta: {
        sender: sanitizeInlineLabel(resolveName(event.message.sender_kid, loadNames())),
        sender_kid: event.message.sender_kid,
        body_type: sanitizeInlineLabel(event.message.body_type, 64),
        event_id: event.event_id,
        conversation_id: event.conversation_id,
        sequence: String(event.sequence),
        content_trust: 'untrusted',
        ...(event.message.charter_info ? { charter_info: JSON.stringify(event.message.charter_info) } : {}),
      },
    },
  });
}

function drainInbox(): void {
  void inbox?.drain(deliverEvent).catch(error => {
    console.error(`[qntm-channel] notification pending; retrying: ${error}`);
  });
}

function verifyGatewayAuthorship(
  bodyType: string,
  rawBodyBytes: Uint8Array,
  senderKidBytes: Uint8Array,
  senderPkBytes: Uint8Array,
  epoch: number,
  record: DiskConvRecord | null,
  history: HistoryEntry[],
): void {
  const senderKidHex = toHex(senderKidBytes);
  const senderPkHex = toHex(senderPkBytes);
  const senderKidB64 = base64UrlEncode(senderKidBytes);
  const senderPkB64 = base64UrlEncode(senderPkBytes);
  const activeGw = resolveActiveGateway(record);

  if (GATEWAY_ONLY_BODY_TYPES.has(bodyType)) {
    if (!activeGw || senderKidHex !== activeGw.kidHex || (activeGw.publicKeyHex && senderPkHex !== activeGw.publicKeyHex)) {
      throw new Error(`untrusted gateway event ${bodyType}`);
    }
    parseGatewayBody(bodyType, rawBodyBytes);
    return;
  }

  if (bodyType === 'gate.accept') {
    const accept = parseGatewayBody('gate.accept', rawBodyBytes);
    if (
      accept.type !== 'gate.accept' ||
      accept.conv_id !== convIdHex ||
      accept.conv_epoch !== epoch ||
      accept.gateway_kid !== senderKidB64 ||
      accept.gateway_public_key !== senderPkB64
    ) {
      throw new Error('invalid gate.accept');
    }
    const matchedHistoryInvite = history.some(
      (entry) =>
        entry.body_type === 'gate.promote' &&
        typeof entry.unsafe_body === 'string' &&
        matchesGatewayAcceptance(accept, senderKidB64, entry.msg_id, entry.unsafe_body),
    );
    const pendingInviteId =
      record?.gateway?.invitationId ??
      record?.gateway?.invitation_id ??
      record?.session?.gateway?.invitation?.body?.invitation_id;
    const pendingGwKid =
      record?.gateway?.keyId ??
      record?.gateway?.key_id ??
      record?.gateway?.kid ??
      record?.session?.gateway?.invitation?.body?.gateway_kid ??
      record?.session?.gateway?.context?.gateway?.kid;
    const matchedDiskGateway = Boolean(
      (pendingInviteId && pendingInviteId === accept.invitation_id) ||
      (pendingGwKid && toHex(decodeKey(pendingGwKid)) === senderKidHex),
    );
    if (!matchedHistoryInvite && !matchedDiskGateway) {
      throw new Error('unsolicited gate.accept');
    }
    return;
  }

  if (PARTICIPANT_GATEWAY_BODY_TYPES.has(bodyType)) {
    if (activeGw && senderKidHex === activeGw.kidHex) {
      throw new Error('gateway cannot author participant workflow event');
    }
    const parsed = parseGatewayBody(bodyType, rawBodyBytes);
    if (bodyType !== 'gate.promote') {
      if (!activeGw) {
        throw new Error(`gateway workflow event ${bodyType} requires an active gateway`);
      }
      if ('signer_kid' in parsed && parsed.signer_kid !== senderKidB64) {
        throw new Error('workflow signer_kid mismatch');
      }
    }
    return;
  }

  if (bodyType.startsWith('gate.') || bodyType.startsWith('gov.')) {
    throw new Error(`unsupported gateway body_type ${bodyType}`);
  }
}

async function handleEnvelope(rawEnvBytes: Uint8Array, seq: number): Promise<void> {
  if (!convIdHex || !convCrypto || !inbox || seq <= inbox.cursor) return;
  const history = loadHistory(convIdHex);
  const envelopeHash = createHash('sha256').update(rawEnvBytes).digest('hex');
  let event: ReceiveEvent;
  try {
    const envelope = deserializeEnvelope(rawEnvBytes);
    const record = findConversation(convIdHex);
    if (record) {
      convCrypto = convToCrypto(record);
      convName = sanitizeInlineLabel(record.name || convIdHex);
    }
    // A CLI receiver may already have advanced the epoch. Its verified history
    // preserves this event, but its shared cursor never acknowledges our handoff.
    const saved = history.find(entry => entry.msg_id === toHex(envelope.msg_id));
    const previous = saved?.receive_event;
    if (saved?.envelope_sha256 === envelopeHash && previous?.message.verified && previous.conversation_id === convIdHex) {
      if (GATEWAY_ONLY_BODY_TYPES.has(previous.message.body_type)) {
        const activeGw = resolveActiveGateway(record);
        if (!activeGw || previous.message.sender_kid !== activeGw.kidHex) {
          throw new Error(`untrusted cached gateway event ${previous.message.body_type}`);
        }
      }
      event = { ...previous, sequence: seq, message: { ...previous.message, sequence: seq } };
    } else {
      if (envelope.conv_epoch !== convCrypto.currentEpoch) {
        throw new Error(`epoch mismatch: expected ${convCrypto.currentEpoch}, got ${envelope.conv_epoch}`);
      }
      const decrypted = decryptMessage(envelope, convCrypto);
      if (!decrypted.verified) {
        throw new Error('unverified message signature');
      }
      if (toHex(keyIDFromPublicKey(decrypted.inner.sender_ik_pk)) !== toHex(decrypted.inner.sender_kid)) {
        throw new Error('sender key_id mismatch');
      }
      verifyGatewayAuthorship(
        decrypted.inner.body_type || 'text',
        decrypted.inner.body,
        decrypted.inner.sender_kid,
        decrypted.inner.sender_ik_pk,
        envelope.conv_epoch,
        record,
        history,
      );
      event = createReceiveEvent(decrypted, seq);
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
      envelope_sha256: envelopeHash,
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
