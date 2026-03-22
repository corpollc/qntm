import { DropboxClient, type Conversation, type Identity, type DropboxSubscription } from "@corpollc/qntm";
import { registerChannel, type ChannelOpts } from "./registry.js";
import { createFileCursorStore, type ConversationCursorStore } from "../state.js";
import {
  decodeInboundEnvelope,
  decodeQntmBody,
  loadQntmConversationFromDir,
  resolveQntmIdentity,
  sendQntmText,
  toHex,
  type QntmClientLike,
} from "../qntm.js";
import type { Channel, NewMessage, RegisteredGroup } from "../types.js";

const CHANNEL_NAME = "qntm";
const DEFAULT_RELAY_URL = "https://inbox.qntm.corpo.llc";
const JID_PREFIX = "qntm:";

export type QntmChannelDeps = {
  env?: NodeJS.ProcessEnv;
  stateDir?: string;
  createClient?: (baseUrl: string) => QntmClientLike;
  cursorStore?: ConversationCursorStore;
  log?: Pick<Console, "info" | "warn" | "error">;
};

type RegisteredQntmGroup = {
  jid: string;
  conversationId: string;
  group: RegisteredGroup;
};

function normalizeConversationId(conversationId: string): string {
  return conversationId.trim().toLowerCase();
}

function parseConversationIdFromJid(jid: string): string | null {
  if (!jid.toLowerCase().startsWith(JID_PREFIX)) {
    return null;
  }
  const conversationId = jid.slice(JID_PREFIX.length).trim();
  return conversationId ? normalizeConversationId(conversationId) : null;
}

function resolveRegisteredQntmGroups(registeredGroups: Record<string, RegisteredGroup>): RegisteredQntmGroup[] {
  return Object.entries(registeredGroups)
    .map(([jid, group]) => {
      const conversationId = parseConversationIdFromJid(jid);
      if (!conversationId) {
        return null;
      }
      return {
        jid,
        conversationId,
        group,
      };
    })
    .filter((entry): entry is RegisteredQntmGroup => Boolean(entry));
}

function decodeByteField(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (
    Array.isArray(value) &&
    value.every(
      (entry) =>
        typeof entry === "number" &&
        Number.isInteger(entry) &&
        entry >= 0 &&
        entry <= 255,
    )
  ) {
    return Uint8Array.from(value);
  }
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = new Uint8Array(trimmed.length / 2);
    for (let index = 0; index < trimmed.length; index += 2) {
      bytes[index / 2] = Number.parseInt(trimmed.slice(index, index + 2), 16);
    }
    return bytes;
  }
  return null;
}

function toComparableHex(value: unknown): string | null {
  const bytes = decodeByteField(value);
  return bytes ? toHex(bytes) : null;
}

function isSelfAuthoredMessage(
  message: { inner: { sender_kid: unknown; sender_ik_pk: unknown } },
  identity: Identity,
): boolean {
  const senderKeyId = toComparableHex(message.inner.sender_kid);
  if (senderKeyId && senderKeyId === toComparableHex(identity.keyID)) {
    return true;
  }

  const senderPublicKey = toComparableHex(message.inner.sender_ik_pk);
  return Boolean(senderPublicKey && senderPublicKey === toComparableHex(identity.publicKey));
}

function describeSender(senderKeyId: string): string {
  return `sender:${senderKeyId.slice(0, 8)}`;
}

export class QntmChannel implements Channel {
  readonly name = CHANNEL_NAME;

  private readonly opts: ChannelOpts;
  private readonly identityDir: string;
  private readonly client: QntmClientLike;
  private readonly cursorStore: ConversationCursorStore;
  private readonly log: Pick<Console, "info" | "warn" | "error">;

  private connected = false;
  private identity: Identity | null = null;
  private readonly conversations = new Map<string, Conversation>();
  private readonly subscriptions = new Map<string, DropboxSubscription>();

  constructor(
    opts: ChannelOpts,
    params: {
      identityDir: string;
      relayUrl: string;
      client: QntmClientLike;
      cursorStore: ConversationCursorStore;
      log: Pick<Console, "info" | "warn" | "error">;
    },
  ) {
    this.opts = opts;
    this.identityDir = params.identityDir;
    this.client = params.client;
    this.cursorStore = params.cursorStore;
    this.log = params.log;
  }

  private ensureIdentity(): Identity {
    if (this.identity) {
      return this.identity;
    }
    const resolved = resolveQntmIdentity({ identityDir: this.identityDir });
    if (!resolved.identity) {
      throw new Error("qntm identity is not configured");
    }
    this.identity = resolved.identity;
    return this.identity;
  }

  private loadConversation(conversationId: string): Conversation {
    const normalized = normalizeConversationId(conversationId);
    const cached = this.conversations.get(normalized);
    if (cached) {
      return cached;
    }
    const conversation = loadQntmConversationFromDir(this.identityDir, normalized);
    this.conversations.set(normalized, conversation);
    return conversation;
  }

  private async handleInbound(params: {
    jid: string;
    conversationId: string;
    group: RegisteredGroup;
    envelopeBytes: Uint8Array;
  }): Promise<void> {
    const identity = this.ensureIdentity();
    const conversation = this.loadConversation(params.conversationId);
    const message = decodeInboundEnvelope({
      identity,
      conversation,
      envelopeBytes: params.envelopeBytes,
    });

    if (isSelfAuthoredMessage(message, identity)) {
      return;
    }

    const senderKeyId = toComparableHex(message.inner.sender_kid) ?? "unknown";
    const senderName = describeSender(senderKeyId);
    const { bodyForAgent } = decodeQntmBody(message.inner.body_type, message.inner.body);
    const timestamp = new Date(message.envelope.created_ts * 1000).toISOString();
    const outbound: NewMessage = {
      id: toHex(message.envelope.msg_id),
      chat_jid: params.jid,
      sender: `${JID_PREFIX}${senderKeyId}`,
      sender_name: senderName,
      content: bodyForAgent,
      timestamp,
      is_from_me: false,
      is_bot_message: false,
    };

    this.opts.onChatMetadata(
      params.jid,
      timestamp,
      conversation.name ?? params.group.name,
      CHANNEL_NAME,
      conversation.type === "group",
    );
    this.opts.onMessage(params.jid, outbound);
  }

  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    this.ensureIdentity();
    const qntmGroups = resolveRegisteredQntmGroups(this.opts.registeredGroups());
    for (const entry of qntmGroups) {
      if (this.subscriptions.has(entry.conversationId)) {
        continue;
      }
      const conversation = this.loadConversation(entry.conversationId);
      const initialCursor = await this.cursorStore.getCursor({
        conversationId: entry.conversationId,
      });
      const subscription = this.client.subscribeMessages(conversation.id, initialCursor, {
        getCursor: () =>
          this.cursorStore.getCursor({
            conversationId: entry.conversationId,
          }),
        onMessage: async ({ seq, envelope }) => {
          try {
            await this.handleInbound({
              jid: entry.jid,
              conversationId: entry.conversationId,
              group: entry.group,
              envelopeBytes: envelope,
            });
          } catch (error) {
            this.log.warn(
              `qntm: failed to process inbound message for ${entry.conversationId}: ${String(error)}`,
            );
          } finally {
            await this.cursorStore.setCursor({
              conversationId: entry.conversationId,
              sequence: seq,
            });
          }
        },
        onError: (error) => {
          this.log.warn(`qntm: subscription error for ${entry.conversationId}: ${error.message}`);
        },
      });
      this.subscriptions.set(entry.conversationId, subscription);
    }

    this.connected = true;
  }

  async sendMessage(jid: string, text: string): Promise<void> {
    const conversationId = parseConversationIdFromJid(jid);
    if (!conversationId) {
      throw new Error(`invalid qntm JID: ${jid}`);
    }
    const trimmed = text.trim();
    if (!trimmed) {
      return;
    }
    const identity = this.ensureIdentity();
    const conversation = this.loadConversation(conversationId);
    await sendQntmText({
      client: this.client,
      identity,
      conversation,
      text: trimmed,
    });
  }

  isConnected(): boolean {
    return this.connected;
  }

  ownsJid(jid: string): boolean {
    return parseConversationIdFromJid(jid) !== null;
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    const subscriptions = [...this.subscriptions.values()];
    this.subscriptions.clear();
    for (const subscription of subscriptions) {
      subscription.close();
      await subscription.closed.catch(() => undefined);
    }
  }
}

export function createQntmChannelFactory(deps?: QntmChannelDeps) {
  return (opts: ChannelOpts): Channel | null => {
    const env = deps?.env ?? process.env;
    const identityDir = env.QNTM_IDENTITY_DIR?.trim();
    if (!identityDir) {
      return null;
    }
    const relayUrl = env.QNTM_RELAY_URL?.trim() || DEFAULT_RELAY_URL;
    const cursorStore =
      deps?.cursorStore ??
      createFileCursorStore({
        stateDir: deps?.stateDir,
      });
    const client = deps?.createClient?.(relayUrl) ?? new DropboxClient(relayUrl);
    return new QntmChannel(opts, {
      identityDir,
      relayUrl,
      client,
      cursorStore,
      log: deps?.log ?? console,
    });
  };
}

registerChannel(CHANNEL_NAME, createQntmChannelFactory());

export const __testing = {
  parseConversationIdFromJid,
  resolveRegisteredQntmGroups,
  describeSender,
};
