/**
 * Identity and conversation persistence for the TUI chat client.
 *
 * Data lives in ~/.qntm-human/ by default (separate from the agent's ~/.qntm/).
 * Layout mirrors the AIM UI server's profile storage but simplified for a
 * single-profile terminal client.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  generateIdentity as clientGenerateIdentity,
  keyIDToString,
  keyIDFromPublicKey,
  serializeIdentity,
  deserializeIdentity,
  createInvite,
  inviteToToken,
  inviteFromURL,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  type Identity,
  type Conversation,
  type ConversationKeys,
} from '@corpollc/qntm';

// ─── Hex helpers ───────────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
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
    fs.mkdirSync(configDir, { recursive: true });
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
    return {
      privateKey: hexToBytes(raw.private_key),
      publicKey: hexToBytes(raw.public_key),
      keyID: hexToBytes(raw.key_id),
    };
  }

  saveIdentity(identity: Identity): void {
    const data = {
      private_key: bytesToHex(identity.privateKey),
      public_key: bytesToHex(identity.publicKey),
      key_id: bytesToHex(identity.keyID),
    };
    fs.writeFileSync(this.identityPath(), JSON.stringify(data, null, 2) + '\n', 'utf8');
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
    fs.writeFileSync(this.storePath(), JSON.stringify(data, null, 2) + '\n', 'utf8');
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
    fs.writeFileSync(
      this.conversationsPath(),
      JSON.stringify(conversations, null, 2) + '\n',
      'utf8',
    );
  }

  findConversation(convId: string): StoredConversation | null {
    return this.loadConversations().find((c) => c.id === convId) || null;
  }

  getConversationCrypto(convId: string): Conversation | null {
    const conv = this.findConversation(convId);
    if (!conv) return null;
    return {
      id: hexToBytes(conv.id),
      type: conv.type,
      keys: {
        root: hexToBytes(conv.keys.root),
        aeadKey: hexToBytes(conv.keys.aeadKey),
        nonceKey: hexToBytes(conv.keys.nonceKey),
      },
      participants: conv.participants.map((p) => hexToBytes(p)),
      createdAt: new Date(conv.createdAt || Date.now()),
      currentEpoch: conv.currentEpoch || 0,
    };
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
      type: (invite as any).type || 'direct',
      keys: {
        root: bytesToHex(keys.root),
        aeadKey: bytesToHex(keys.aeadKey),
        nonceKey: bytesToHex(keys.nonceKey),
      },
      participants: conv.participants.map((p) => bytesToHex(p)),
      createdAt: new Date().toISOString(),
      currentEpoch: 0,
    });
    this.saveConversations(conversations);

    return convIdHex;
  }

  // --- Cursors ---

  private cursorsPath(): string {
    return path.join(this.configDir, 'cursors.json');
  }

  loadCursor(convId: string): number {
    if (!fs.existsSync(this.cursorsPath())) return 0;
    const raw = JSON.parse(fs.readFileSync(this.cursorsPath(), 'utf8'));
    return raw[convId] || 0;
  }

  saveCursor(convId: string, seq: number): void {
    let raw: Record<string, number> = {};
    if (fs.existsSync(this.cursorsPath())) {
      raw = JSON.parse(fs.readFileSync(this.cursorsPath(), 'utf8'));
    }
    raw[convId] = seq;
    fs.writeFileSync(this.cursorsPath(), JSON.stringify(raw, null, 2) + '\n', 'utf8');
  }

  // --- Message history ---

  private historyPath(): string {
    return path.join(this.configDir, 'history.json');
  }

  loadHistory(convId: string): StoredMessage[] {
    if (!fs.existsSync(this.historyPath())) return [];
    const raw = JSON.parse(fs.readFileSync(this.historyPath(), 'utf8'));
    return raw[convId] || [];
  }

  appendHistory(convId: string, message: StoredMessage): void {
    let raw: Record<string, StoredMessage[]> = {};
    if (fs.existsSync(this.historyPath())) {
      raw = JSON.parse(fs.readFileSync(this.historyPath(), 'utf8'));
    }
    if (!raw[convId]) raw[convId] = [];

    // Deduplicate
    const bucket = raw[convId];
    const isDupe = bucket.some(
      (m) =>
        m.direction === message.direction &&
        m.sender === message.sender &&
        m.bodyType === message.bodyType &&
        m.text === message.text &&
        Math.abs(Date.parse(m.createdAt) - Date.parse(message.createdAt)) < 1500,
    );
    if (isDupe) return;

    bucket.push(message);
    if (bucket.length > 1000) bucket.splice(0, bucket.length - 1000);
    fs.writeFileSync(this.historyPath(), JSON.stringify(raw, null, 2) + '\n', 'utf8');
  }
}
