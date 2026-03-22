import { DropboxClient, base64UrlDecode, decryptMessage, deserializeEnvelope } from "@corpollc/qntm";
import {
  type ChannelRuntime,
  createNormalizedOutboundDeliverer,
  createReplyPrefixOptions,
  type OpenClawConfig,
} from "openclaw/plugin-sdk";
import { CHANNEL_ID } from "./shared.js";
import { createFileCursorStore, type ConversationCursorStore } from "./state.js";
import { decodeQntmBody, flattenQntmReplyPayload, sendQntmText, toHex, type QntmClientLike } from "./qntm.js";
import type {
  QntmRootConfig,
  QntmRuntimeStatus,
  ResolvedQntmAccount,
  ResolvedQntmBinding,
} from "./types.js";

type StatusSink = (patch: QntmRuntimeStatus) => void;

export type QntmMonitorDeps = {
  createClient?: (baseUrl: string) => QntmClientLike;
  cursorStore?: ConversationCursorStore;
  now?: () => number;
};

export type QntmMonitor = {
  stop: () => void;
};

type QntmSubscriptionHandle = {
  close: (code?: number, reason?: string) => void;
};

function describeSender(senderKeyId: string): string {
  return `sender:${senderKeyId.slice(0, 8)}`;
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
  try {
    return base64UrlDecode(trimmed);
  } catch {
    return null;
  }
}

function toComparableHex(value: unknown): string | null {
  const bytes = decodeByteField(value);
  return bytes ? toHex(bytes) : null;
}

function isSelfAuthoredMessage(
  message: { inner: { sender_kid: unknown; sender_ik_pk: unknown } },
  identity: { keyID: Uint8Array; publicKey: Uint8Array },
): boolean {
  const senderKeyId = toComparableHex(message.inner.sender_kid);
  if (senderKeyId && senderKeyId === toComparableHex(identity.keyID)) {
    return true;
  }

  const senderPublicKey = toComparableHex(message.inner.sender_ik_pk);
  return Boolean(senderPublicKey && senderPublicKey === toComparableHex(identity.publicKey));
}

async function dispatchInboundMessage(params: {
  account: ResolvedQntmAccount;
  binding: ResolvedQntmBinding;
  envelopeBytes: Uint8Array;
  client: QntmClientLike;
  cfg: QntmRootConfig;
  channelRuntime: ChannelRuntime;
  log?: { error?: (message: string) => void };
  statusSink?: StatusSink;
  now: () => number;
}): Promise<void> {
  if (!params.account.identity) {
    return;
  }

  let message;
  try {
    const envelope = deserializeEnvelope(params.envelopeBytes);
    message = decryptMessage(envelope, params.binding.conversation);
  } catch (error) {
    params.log?.error?.(`qntm: failed to decrypt inbound envelope: ${String(error)}`);
    return;
  }

  if (isSelfAuthoredMessage(message, params.account.identity)) {
    return;
  }
  const senderKeyId = toComparableHex(message.inner.sender_kid) ?? "unknown";

  const senderDisplay = describeSender(senderKeyId);
  const { rawBody, bodyForAgent } = decodeQntmBody(message.inner.body_type, message.inner.body);
  const route = params.channelRuntime.routing.resolveAgentRoute({
    cfg: params.cfg,
    channel: CHANNEL_ID,
    accountId: params.account.accountId,
    peer: {
      kind: params.binding.chatType,
      id: params.binding.conversationId,
    },
  });
  const sessionKey = route.sessionKey;
  const lastRouteSessionKey =
    route.lastRoutePolicy === "main" ? route.mainSessionKey : route.sessionKey;
  const storePath = params.channelRuntime.session.resolveStorePath(params.cfg.session?.store, {
    agentId: route.agentId,
  });
  const previousTimestamp = params.channelRuntime.session.readSessionUpdatedAt({
    storePath,
    sessionKey,
  });
  const body = params.channelRuntime.reply.formatAgentEnvelope({
    channel: "qntm",
    from:
      params.binding.chatType === "group"
        ? `${senderDisplay} in ${params.binding.label}`
        : senderDisplay,
    timestamp: message.envelope.created_ts * 1000,
    previousTimestamp,
    envelope: params.channelRuntime.reply.resolveEnvelopeFormatOptions(params.cfg),
    body: bodyForAgent,
  });

  const ctx = params.channelRuntime.reply.finalizeInboundContext({
    Body: body,
    BodyForAgent: bodyForAgent,
    RawBody: rawBody,
    CommandBody: rawBody,
    From: `qntm:${senderKeyId}`,
    To: `qntm:${params.binding.conversationId}`,
    SessionKey: sessionKey,
    AccountId: route.accountId,
    ChatType: params.binding.chatType,
    ConversationLabel: params.binding.label,
    GroupSubject: params.binding.chatType === "group" ? params.binding.label : undefined,
    GroupChannel: params.binding.chatType === "group" ? params.binding.label : undefined,
    SenderName: senderDisplay,
    SenderId: senderKeyId,
    Timestamp: message.envelope.created_ts * 1000,
    MessageSid: toHex(message.envelope.msg_id),
    NativeChannelId: params.binding.conversationId,
    Provider: CHANNEL_ID,
    Surface: CHANNEL_ID,
    OriginatingChannel: CHANNEL_ID,
    OriginatingTo: `qntm:${params.binding.conversationId}`,
    CommandAuthorized: false,
    ...(message.inner.body_type !== "text"
      ? { UntrustedContext: [`qntm body_type=${message.inner.body_type}`] }
      : {}),
  });

  params.statusSink?.({
    lastInboundAt: message.envelope.created_ts * 1000,
    lastError: null,
  });

  await params.channelRuntime.session.recordInboundSession({
    storePath,
    sessionKey,
    ctx,
    createIfMissing: true,
    updateLastRoute: {
      sessionKey: lastRouteSessionKey,
      channel: CHANNEL_ID,
      to: `qntm:${params.binding.conversationId}`,
      accountId: route.accountId,
    },
    onRecordError: (error) => {
      params.log?.error?.(`qntm: failed updating session meta: ${String(error)}`);
    },
  });

  const deliver = createNormalizedOutboundDeliverer(async (payload) => {
    const text = flattenQntmReplyPayload(payload);
    if (!text.trim()) {
      return;
    }
    await sendQntmText({
      client: params.client,
      identity: params.account.identity!,
      conversation: params.binding.conversation,
      text,
    });
    params.statusSink?.({
      lastOutboundAt: params.now(),
      lastError: null,
    });
  });
  const { onModelSelected, ...prefixOptions } = createReplyPrefixOptions({
    cfg: params.cfg as QntmRootConfig,
    agentId: route.agentId,
    channel: CHANNEL_ID,
    accountId: route.accountId,
  });

  await params.channelRuntime.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx,
    cfg: params.cfg,
    dispatcherOptions: {
      ...prefixOptions,
      deliver,
      onError: (error, info) => {
        params.log?.error?.(`qntm ${info.kind} reply failed: ${String(error)}`);
      },
    },
    replyOptions: {
      onModelSelected,
    },
  });
}

export async function monitorQntmAccount(params: {
  account: ResolvedQntmAccount;
  cfg: OpenClawConfig;
  channelRuntime: ChannelRuntime;
  abortSignal: AbortSignal;
  statusSink?: StatusSink;
  log?: {
    info?: (message: string) => void;
    error?: (message: string) => void;
  };
  deps?: QntmMonitorDeps;
}): Promise<QntmMonitor> {
  const createClient = params.deps?.createClient ?? ((baseUrl: string) => new DropboxClient(baseUrl));
  const now = params.deps?.now ?? (() => Date.now());
  const cursorStore =
    params.deps?.cursorStore ??
    createFileCursorStore({
      now,
    });
  const client = createClient(params.account.relayUrl);
  const subscriptions: QntmSubscriptionHandle[] = [];
  let stopped = false;

  try {
    for (const binding of params.account.bindings.filter((entry) => entry.enabled)) {
      const initialCursor = await cursorStore.getCursor({
        accountId: params.account.accountId,
        conversationId: binding.conversationId,
      });
      const subscription = client.subscribeMessages(binding.conversation.id, initialCursor, {
        getCursor: async () =>
          await cursorStore.getCursor({
            accountId: params.account.accountId,
            conversationId: binding.conversationId,
          }),
        onMessage: async ({ seq, envelope }) => {
          try {
            await dispatchInboundMessage({
              account: params.account,
              binding,
              envelopeBytes: envelope,
              client,
              cfg: params.cfg as QntmRootConfig,
              channelRuntime: params.channelRuntime,
              log: params.log,
              statusSink: params.statusSink,
              now,
            });
          } finally {
            await cursorStore.setCursor({
              accountId: params.account.accountId,
              conversationId: binding.conversationId,
              sequence: seq,
            });
          }
        },
        onError: (error) => {
          params.statusSink?.({
            lastError: String(error),
          });
          params.log?.error?.(
            `qntm: subscription error for ${binding.conversationId}: ${String(error)}`,
          );
        },
        onReconnect: (attempt, delayMs) => {
          params.log?.info?.(
            `qntm: reconnect ${binding.conversationId} attempt ${attempt} in ${delayMs}ms`,
          );
        },
      });
      subscriptions.push(subscription);
    }
  } catch (error) {
    for (const subscription of subscriptions) {
      subscription.close(1011, "qntm monitor startup failed");
    }
    throw error;
  }

  return {
    stop: () => {
      if (stopped) {
        return;
      }
      stopped = true;
      for (const subscription of subscriptions) {
        subscription.close(1000, "qntm monitor stopped");
      }
      params.statusSink?.({
        running: false,
        lastStopAt: now(),
      });
    },
  };
}
