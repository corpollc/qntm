/**
 * Identity and conversation persistence for the TUI chat client.
 *
 * Data lives in ~/.qntm-human/ by default (separate from the agent's ~/.qntm/).
 * Layout mirrors the AIM UI server's profile storage but simplified for a
 * single-profile terminal client.
 */

import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  generateIdentity as clientGenerateIdentity,
  validateIdentity,
  createGatewaySession,
  createInvite,
  inviteToToken,
  inviteFromURL,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  type Identity,
  type Conversation,
  type GatewaySessionState,
  type ConversationEvent,
  type GatewayBootstrapRequest,
} from '@corpollc/qntm';

// ─── Hex helpers ───────────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw new Error('Invalid hex encoding');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ─── Serialised types (JSON on disk) ───────────────────────────────────

export interface StoredConversation {
  id: string;
  name: string;
  type: 'direct' | 'group' | 'announce';
  keys: {
    root: string;
    aeadKey: string;
    nonceKey: string;
  };
  participants: string[];
  createdAt: string;
  inviteToken?: string;
  currentEpoch: number;
  /** Keys, verified protocol state, history and receive cursor share one commit. */
  session?: GatewaySessionState;
  cursor?: number;
  messages?: StoredMessage[];
  pendingGatewayBootstrap?: { url: string; request: GatewayBootstrapRequest };

}

export interface StoredMessage {
  id: string;
  conversationId: string;
  direction: 'incoming' | 'outgoing';
  sender: string;
  senderKey: string;
  bodyType: string;
  text: string;
  createdAt: string;
  gatewayVerified?: boolean;
}

export interface StoreData {
  name: string;
  dropboxUrl: string;
  contacts: Record<string, string>; // kid -> display name
}

// ─── Store class ───────────────────────────────────────────────────────

export class Store {
  readonly configDir: string;
  readonly dropboxUrl: string;

  constructor(configDir: string, dropboxUrl: string) {
    this.configDir = configDir;
    this.dropboxUrl = dropboxUrl;
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
    fs.chmodSync(configDir, 0o700);
  }

  private writeJSON(filename: string, data: unknown): void {
    const temporary = `${filename}.${randomUUID()}.tmp`;
    try {
      const fd = fs.openSync(temporary, 'wx', 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify(data, null, 2) + '\n', 'utf8');
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      fs.renameSync(temporary, filename);
    } finally { fs.rmSync(temporary, { force: true }); }
  }

  // --- Identity ---

  private identityPath(): string {
    return path.join(this.configDir, 'identity.json');
  }

  hasIdentity(): boolean {
    return fs.existsSync(this.identityPath());
  }

  loadIdentity(): Identity | null {
    if (!this.hasIdentity()) return null;
    const raw = JSON.parse(fs.readFileSync(this.identityPath(), 'utf8'));
    const identity = {
      privateKey: hexToBytes(raw.private_key),
      publicKey: hexToBytes(raw.public_key),
      keyID: hexToBytes(raw.key_id),
    };
    validateIdentity(identity);
    return identity;
  }

  saveIdentity(identity: Identity): void {
    const data = {
      private_key: bytesToHex(identity.privateKey),
      public_key: bytesToHex(identity.publicKey),
      key_id: bytesToHex(identity.keyID),
    };
    validateIdentity(identity);
    this.writeJSON(this.identityPath(), data);
  }

  generateIdentity(): Identity {
    const identity = clientGenerateIdentity();
    this.saveIdentity(identity);
    return identity;
  }

  // --- Store metadata (name, contacts) ---

  private storePath(): string {
    return path.join(this.configDir, 'store.json');
  }

  loadStoreData(): StoreData {
    if (!fs.existsSync(this.storePath())) {
      return { name: '', dropboxUrl: this.dropboxUrl, contacts: {} };
    }
    const raw = JSON.parse(fs.readFileSync(this.storePath(), 'utf8'));
    return {
      name: raw.name || '',
      dropboxUrl: raw.dropboxUrl || this.dropboxUrl,
      contacts: raw.contacts || {},
    };
  }

  saveStoreData(data: StoreData): void {
    this.writeJSON(this.storePath(), data);
  }

  setName(name: string): void {
    const data = this.loadStoreData();
    data.name = name;
    this.saveStoreData(data);
  }

  getName(): string {
    return this.loadStoreData().name;
  }

  setContact(kid: string, name: string): void {
    const data = this.loadStoreData();
    data.contacts[kid.toLowerCase()] = name;
    this.saveStoreData(data);
  }

  resolveContact(kid: string): string {
    const data = this.loadStoreData();
    return data.contacts[kid.toLowerCase()] || '';
  }

  // --- Conversations ---

  private conversationsPath(): string {
    return path.join(this.configDir, 'conversations.json');
  }

  loadConversations(): StoredConversation[] {
    if (!fs.existsSync(this.conversationsPath())) return [];
    const raw = JSON.parse(fs.readFileSync(this.conversationsPath(), 'utf8'));
    return Array.isArray(raw) ? raw : [];
  }

  saveConversations(conversations: StoredConversation[]): void {
    this.writeJSON(this.conversationsPath(), conversations);
  }

  findConversation(convId: string): StoredConversation | null {
    return this.loadConversations().find((c) => c.id === convId) || null;
  }

  getConversationCrypto(convId: string): Conversation | null {
    const conv = this.findConversation(convId);
    if (!conv) return null;
    const conversation: Conversation = {
      id: hexToBytes(conv.id),
      type: conv.type,
      keys: {
        root: hexToBytes(conv.keys.root),
        aeadKey: hexToBytes(conv.keys.aeadKey),
        nonceKey: hexToBytes(conv.keys.nonceKey),
      },
      participants: conv.participants.map((p) => hexToBytes(p)),
      createdAt: new Date(conv.createdAt || Date.now()),
      currentEpoch: conv.currentEpoch ?? 0,
    };
    if (conversation.id.length !== 16 || !Number.isSafeInteger(conversation.currentEpoch) || conversation.currentEpoch < 0 ||
        Object.values(conversation.keys).some(key => key.length !== 32) || conversation.participants.some(kid => kid.length !== 16)) {
      throw new Error('Invalid saved conversation keys, participant IDs or epoch');
    }
    return conversation;
  }

  createInvite(identity: Identity, name?: string): { token: string; convId: string } {
    const invite = createInvite(identity, 'direct');
    const token = inviteToToken(invite);
    const convIdHex = bytesToHex(invite.conv_id);

    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    addParticipant(conv, identity.publicKey);

    const conversations = this.loadConversations();
    conversations.push({
      id: convIdHex,
      name: name || `Chat ${convIdHex.slice(0, 8)}`,
      type: 'direct',
      keys: {
        root: bytesToHex(keys.root),
        aeadKey: bytesToHex(keys.aeadKey),
        nonceKey: bytesToHex(keys.nonceKey),
      },
      participants: conv.participants.map((p) => bytesToHex(p)),
      createdAt: new Date().toISOString(),
      currentEpoch: 0,
      session: createGatewaySession(conv, [identity.publicKey]),
      inviteToken: token,
    });
    this.saveConversations(conversations);

    return { token, convId: convIdHex };
  }

  acceptInvite(identity: Identity, token: string, name?: string): string {
    const invite = inviteFromURL(token);
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    addParticipant(conv, identity.publicKey);

    const convIdHex = bytesToHex(invite.conv_id);

    const conversations = this.loadConversations();
    const existing = conversations.find((c) => c.id === convIdHex);
    if (existing) return convIdHex;

    conversations.push({
      id: convIdHex,
      name: name || `Chat ${convIdHex.slice(0, 8)}`,
      type: invite.type,
      keys: {
        root: bytesToHex(keys.root),
        aeadKey: bytesToHex(keys.aeadKey),
        nonceKey: bytesToHex(keys.nonceKey),
      },
      participants: conv.participants.map((p) => bytesToHex(p)),
      createdAt: new Date().toISOString(),
      currentEpoch: 0,
      session: createGatewaySession(conv, [invite.inviter_ik_pk, identity.publicKey]),
      inviteToken: inviteToToken(invite),
    });
    this.saveConversations(conversations);

    return convIdHex;
  }

  /** Existing installations keep their history/cursor files until first update.
   * No gateway authority is inferred from display history or unverified JSON. */
  gatewaySession(convId: string, identity: Identity): GatewaySessionState {
    const stored = this.findConversation(convId);
    if (!stored) throw new Error('Unknown conversation');
    if (stored.session) return stored.session;
    const conversation = this.getConversationCrypto(convId)!;
    const keys: Uint8Array[] = [];
    if (conversation.participants.some(kid => bytesToHex(kid) === bytesToHex(identity.keyID))) keys.push(identity.publicKey);
    if (stored.inviteToken) keys.push(inviteFromURL(stored.inviteToken).inviter_ik_pk);
    return createGatewaySession(conversation, keys);
  }

  updateConversation(convId: string, update: (stored: StoredConversation) => void): void {
    const conversations = this.loadConversations();
    const stored = conversations.find(c => c.id === convId);
    if (!stored) throw new Error('Unknown conversation');
    stored.messages ??= this.loadHistory(convId);
    stored.cursor ??= this.loadCursor(convId);
    update(stored);
    this.saveConversations(conversations);
  }

  commitReceived(convId: string, event: ConversationEvent, message?: StoredMessage, seq?: number): void {
    this.updateConversation(convId, stored => {
      stored.session = event.state;
      stored.keys = { root: bytesToHex(event.conversation.keys.root), aeadKey: bytesToHex(event.conversation.keys.aeadKey), nonceKey: bytesToHex(event.conversation.keys.nonceKey) };
      stored.currentEpoch = event.conversation.currentEpoch;
      stored.participants = event.conversation.participants.map(bytesToHex);
      if (message) stored.messages = this.mergeHistory(stored.messages!, message);
      if (seq !== undefined) {
        if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('Invalid receive sequence');
        stored.cursor = Math.max(stored.cursor!, seq);
      }
      if (event.state.gateway?.accepted) delete stored.pendingGatewayBootstrap;
    });
  }

  private mergeHistory(history: StoredMessage[], message: StoredMessage): StoredMessage[] {
    // Distinct message IDs remain distinct even when the text and time match.
    const found = history.findIndex(m => m.id === message.id);
    if (found >= 0) history[found] = message;
    else history.push(message);
    return history.slice(-1000);
  }

  // --- Cursors ---

  private cursorsPath(): string {
    return path.join(this.configDir, 'cursors.json');
  }

  loadCursor(convId: string): number {
    const stored = this.findConversation(convId);
    if (stored?.cursor !== undefined) return stored.cursor;
    if (!fs.existsSync(this.cursorsPath())) return 0;
    const raw = JSON.parse(fs.readFileSync(this.cursorsPath(), 'utf8'));
    return raw[convId] || 0;
  }

  saveCursor(convId: string, seq: number): void {
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('Invalid receive sequence');
    if (this.findConversation(convId)) {
      this.updateConversation(convId, stored => { stored.cursor = Math.max(stored.cursor!, seq); });
      return;
    }
    const raw = fs.existsSync(this.cursorsPath()) ? JSON.parse(fs.readFileSync(this.cursorsPath(), 'utf8')) : {};
    raw[convId] = Math.max(raw[convId] || 0, seq);
    this.writeJSON(this.cursorsPath(), raw);
  }

  // --- Message history ---

  private historyPath(): string {
    return path.join(this.configDir, 'history.json');
  }

  loadHistory(convId: string): StoredMessage[] {
    const stored = this.findConversation(convId);
    if (stored?.messages) return stored.messages;
    if (!fs.existsSync(this.historyPath())) return [];
    const raw = JSON.parse(fs.readFileSync(this.historyPath(), 'utf8'));
    return raw[convId] || [];
  }

  appendHistory(convId: string, message: StoredMessage): void {
    if (this.findConversation(convId)) {
      this.updateConversation(convId, stored => { stored.messages = this.mergeHistory(stored.messages!, message); });
      return;
    }
    const raw = fs.existsSync(this.historyPath()) ? JSON.parse(fs.readFileSync(this.historyPath(), 'utf8')) : {};
    raw[convId] = this.mergeHistory(raw[convId] || [], message);
    this.writeJSON(this.historyPath(), raw);
  }
}
