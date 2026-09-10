import { QntmGroupStore, groupDispatchDisposition, type GroupRow } from "./group-store.js";
import { DropboxClient, base64UrlEncode } from "@corpollc/qntm";
import type { PluginRuntime, OpenClawConfig } from "openclaw/plugin-sdk/channel-core";
import { createNormalizedOutboundDeliverer } from "openclaw/plugin-sdk/reply-payload";
import { createReplyPrefixOptions, createChannelIngressMonitor, bindIngressLifecycleToReplyOptions,
  type ChannelIngressMonitorLifecycle, type ChannelIngressMonitorDeliveryResult,
} from "openclaw/plugin-sdk/channel-outbound";
type ChannelRuntime = PluginRuntime["channel"];
import { CHANNEL_ID } from "./shared.js";
import { QntmCheckpointStore, inboundId, validateInbound, type QntmInbound } from "./checkpoint.js";
import { receiveQntmEnvelope } from "./receive.js";
import { QntmIngressQueue } from "./ingress-queue.js";
import { decodeQntmBody, flattenQntmReplyPayload, sendQntmText, type QntmClientLike } from "./qntm.js";
import type {
  QntmRootConfig,
  QntmRuntimeStatus,
  ResolvedQntmAccount,
  ResolvedQntmBinding,
} from "./types.js";

type StatusSink = (patch: QntmRuntimeStatus) => void;

export type QntmMonitorDeps = {
  createClient?: (baseUrl: string) => QntmClientLike;
  checkpointStore?: QntmCheckpointStore;
  createIngress?: (deliver: (message: QntmInbound, lifecycle: ChannelIngressMonitorLifecycle) => Promise<ChannelIngressMonitorDeliveryResult>) => QntmIngress;
  now?: () => number;
};

export type QntmIngress = {
  admit(message: QntmInbound): Promise<unknown>;
  start(): void;
  stop(): Promise<void>;
};
export type QntmMonitor = { stop(): Promise<void> };

type QntmSubscriptionHandle = {
  close: (code?: number, reason?: string) => void;
};

function describeSender(senderKeyId: string): string {
  return `sender:${senderKeyId.slice(0, 8)}`;
}

async function dispatchInboundMessage(params: {
  account: ResolvedQntmAccount;
  binding: ResolvedQntmBinding;
  inbound: QntmInbound;
  store: QntmCheckpointStore;
  lifecycle: ChannelIngressMonitorLifecycle;
  client: QntmClientLike;
  cfg: QntmRootConfig;
  channelRuntime: ChannelRuntime;
  log?: { error?: (message: string) => void };
  statusSink?: StatusSink;
  now: () => number;
}): Promise<ChannelIngressMonitorDeliveryResult> {
  const ordinary = params.binding.ordinaryGroup ? new QntmGroupStore(params.account, params.binding) : undefined;
  if (ordinary) {
    const state = ordinary.load();
    const disposition = groupDispatchDisposition(state, params.inbound.messageId);
    if (disposition !== 'dispatch') return { kind: disposition === 'defer' ? 'deferred' : 'completed' };
  } else if (params.store.load(params.binding).session.removed) return { kind: "completed" };
  const senderKeyId = params.inbound.senderKid;
  const senderDisplay = describeSender(senderKeyId);
  const { rawBody, bodyForAgent } = decodeQntmBody(params.inbound.bodyType, new TextEncoder().encode(params.inbound.text));
  let deferred = false;
  const lifecycle: ChannelIngressMonitorLifecycle = {
    ...params.lifecycle,
    onAdopted: async () => { deferred = false; await params.lifecycle.onAdopted(); },
    onDeferred: () => { deferred = true; params.lifecycle.onDeferred(); },
  };
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
    timestamp: params.inbound.createdAt,
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
    Timestamp: params.inbound.createdAt,
    MessageSid: params.inbound.messageId,
    NativeChannelId: params.binding.conversationId,
    Provider: CHANNEL_ID,
    Surface: CHANNEL_ID,
    OriginatingChannel: CHANNEL_ID,
    OriginatingTo: `qntm:${params.binding.conversationId}`,
    CommandAuthorized: false,
    UntrustedContext: [`qntm body_type=${params.inbound.bodyType}; gateway_event_verified=${params.inbound.gatewayVerified}`],
  });

  params.statusSink?.({
    lastInboundAt: params.inbound.createdAt,
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
      throw error;
    },
  });

  const deliver = createNormalizedOutboundDeliverer(async (payload) => {
    const text = flattenQntmReplyPayload(payload);
    if (!text.trim()) {
      return;
    }
    if (ordinary) {
      await ordinary.send(text);
      params.statusSink?.({ lastOutboundAt: params.now(), lastError: null });
      return;
    }
    const latest = params.store.load(params.binding);
    if (latest.session.removed) throw new Error("qntm identity has been removed from this conversation");
    await sendQntmText({
      client: params.client,
      identity: params.account.identity!,
      conversation: latest.conversation,
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
        params.statusSink?.({ lastError: "qntm reply delivery failed; outcome may be unknown" });
        params.log?.error?.("qntm reply delivery failed; outcome may be unknown");
      },
    },
    replyOptions: {
      onModelSelected,
      ...bindIngressLifecycleToReplyOptions(lifecycle),
    },
  });
  return { kind: deferred ? "deferred" : "completed" };
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
  params.abortSignal.throwIfAborted();
  if (!params.account.identity || !params.account.configured) throw new Error("qntm account is not configured");
  const createClient = params.deps?.createClient ?? ((baseUrl: string) => new DropboxClient(baseUrl));
  const now = params.deps?.now ?? (() => Date.now());
  const store = params.deps?.checkpointStore ?? new QntmCheckpointStore(params.account);
  const client = createClient(params.account.relayUrl);
  const bindings = params.account.bindings.filter(binding => binding.enabled);
  if (new Set(bindings.map(binding => binding.conversationId)).size !== bindings.length) {
    throw new Error("qntm conversation has multiple enabled bindings in one account");
  }
  const groups = new Map(bindings.filter(binding => binding.ordinaryGroup).map(binding => [binding.conversationId, new QntmGroupStore(params.account, binding)]));
  const replaying = new Set<string>();
  const report = () => {
    params.statusSink?.({ lastError: "qntm pending host delivery failed; retained for retry" });
    params.log?.error?.("qntm pending host delivery failed; retained for retry");
  };
  const deliver = async (message: QntmInbound, lifecycle: ChannelIngressMonitorLifecycle): Promise<ChannelIngressMonitorDeliveryResult> => {
    const binding = bindings.find(binding => binding.conversationId === message.conversationId);
    // A removed binding cannot dispatch under another conversation's route.
    if (!binding) return { kind: "completed" };
    return await dispatchInboundMessage({ ...params, binding, inbound: validateInbound(message), store,
      lifecycle, client, cfg: params.cfg as QntmRootConfig, now });
  };
  let ingress: QntmIngress;
  if (params.deps?.createIngress) ingress = params.deps.createIngress(deliver);
  else {
    const queue = new QntmIngressQueue(params.account.accountId);
    const monitor = createChannelIngressMonitor({
      queue,
      inspect: (input: QntmInbound) => { const value = validateInbound(input); return { eventId: inboundId(value), laneKey: value.conversationId }; },
      payload: {
        version: 1, serialize: (input: QntmInbound) => input, deserialize: validateInbound,
        encode: envelope => envelope, decode: input => input,
        createClaimError: () => new Error("Invalid persisted qntm ingress record"),
      },
      deliver,
      pollIntervalMs: 250,
      retention: { pruneIntervalMs: 3_600_000, completedTtlMs: 7 * 86400_000, completedMaxEntries: 8192,
        failedTtlMs: 7 * 86400_000, failedMaxEntries: 1024 },
      waitForDeliveryIdleOnStop: false,
      deferredClaims: "settle-on-abort",
      abortSignal: params.abortSignal,
      onError: report,
    });
    ingress = {
      ...monitor,
      stop: async () => {
        await monitor.stop();
        // Adopted turns may still be settling. Keep their claim storage alive
        // without blocking the host's shutdown on a model/provider response.
        void monitor.waitForIdle().finally(() => queue.close()).catch(report);
      },
    };
  }
  const subscriptions: QntmSubscriptionHandle[] = [];
  let stopped = false;
  let flushing: Promise<void> | undefined;
  const flush = (): Promise<void> => {
    if (flushing) return flushing;
    if (stopped) return Promise.resolve();
    flushing = (async () => {
      for (const binding of bindings) {
        const ordinary = groups.get(binding.conversationId), checkpoint = ordinary?.load();
        if (ordinary && (replaying.has(binding.conversationId) || !checkpoint?.session || checkpoint.session.recovery || checkpoint.session.removed || checkpoint.session.needsRekey || checkpoint.operation)) continue;
        for (const message of (checkpoint ?? store.load(binding)).outbox) {
          if (stopped) return;
          await ingress.admit(message);
          // If this write fails, the next admission hits qntm's durable
          // duplicate record; the original plaintext pending entry is retained.
          if (ordinary) await ordinary.removeOutbox(inboundId(message));
          else store.removeOutbox(binding, inboundId(message));
        }
      }
    })().finally(() => { flushing = undefined; });
    return flushing;
  };
  const timer = setInterval(() => { void flush().catch(report); }, 1000);
  timer.unref();
  try {
    ingress.start();
    for (const ordinary of groups.values()) {
      replaying.add(ordinary.binding.conversationId);
      await ordinary.exclusive(async () => {
        await ordinary.sync();
        if ((ordinary.load().session?.recovery || ordinary.load().session?.removed) && ordinary.binding.groupLink) {
          try { await ordinary.open(); } catch { /* Still waiting for a valid pinned recovery or readmission welcome. */ }
        }
      });
    }
    await flush().catch(report);
    for (const binding of bindings) {
      const ordinary = groups.get(binding.conversationId);
      if (ordinary) {
        let batch: GroupRow[] = [], live = false;
        subscriptions.push(client.subscribeMessages(binding.conversation.id, ordinary.load().cursor, {
          getCursor: () => ordinary.load().cursor,
          onOpen: () => { batch = []; live = false; replaying.add(binding.conversationId); },
          onClose: () => { live = false; replaying.add(binding.conversationId); },
          onMessage: async ({ seq, envelope }) => {
            if (stopped) return;
            const row = { seq, wire: base64UrlEncode(envelope) };
            if (!live) {
              batch.push(row);
              if (batch.length > 256 || batch.reduce((sum, item) => sum + item.wire.length, 0) > 6 * 1024 * 1024) throw new Error('qntm replay batch exceeds its safety limit');
            } else {
              await ordinary.exclusive(async () => {
                ordinary.receive([row], Math.max(seq, ordinary.load().cursor));
                if ((ordinary.load().session?.recovery || ordinary.load().session?.removed) && ordinary.binding.groupLink) {
                  try { await ordinary.open(); } catch { /* Recovery remains durable until a valid welcome arrives. */ }
                }
              });
              await flush().catch(report);
            }
          },
          onReady: async (head: number) => {
            await ordinary.exclusive(async () => ordinary.receive(batch, Math.max(head, ordinary.load().cursor)));
            batch = []; live = true; replaying.delete(binding.conversationId);
            if (ordinary.load().session?.recovery) params.statusSink?.({ lastError: 'qntm group requires a challenged welcome; inspect qntm_group status' });
            await flush().catch(report);
          },
          onError: () => { live = false; replaying.add(binding.conversationId); params.statusSink?.({ lastError: 'qntm group subscription failed; reconnecting from durable checkpoint' }); },
        }));
        continue;
      }
      const initialCursor = store.load(binding).cursor;
      subscriptions.push(client.subscribeMessages(binding.conversation.id, initialCursor, {
        getCursor: () => store.load(binding).cursor,
        onMessage: async ({ seq, envelope }) => {
          if (stopped) return;
          if (receiveQntmEnvelope(store, binding, seq, envelope) === "invalid") {
            params.log?.error?.("qntm: rejected malformed, oversized, unauthenticated, expired or wrong-epoch message");
          }
          await flush().catch(report);
        },
        onError: () => {
          params.statusSink?.({ lastError: "qntm subscription failed; reconnecting from durable checkpoint" });
          params.log?.error?.("qntm subscription failed; reconnecting from durable checkpoint");
        },
        onReconnect: (attempt, delayMs) => params.log?.info?.(`qntm: reconnect attempt ${attempt} in ${delayMs}ms`),
      }));
    }
  } catch (error) {
    stopped = true;
    clearInterval(timer);
    for (const subscription of subscriptions) subscription.close(1011, "qntm monitor startup failed");
    await ingress.stop();
    throw error;
  }
  return {
    stop: async () => {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
      for (const subscription of subscriptions) subscription.close(1000, "qntm monitor stopped");
      await flushing?.catch(report);
      await ingress.stop();
      params.statusSink?.({ running: false, lastStopAt: now() });
    },
  };
}
