import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from "./account-id.js";

export type RoutePeerKind = "direct" | "group" | "channel";

export type RoutePeer = {
  kind: RoutePeerKind;
  id: string;
};

export type OpenClawConfig = {
  channels?: Record<string, unknown>;
  session?: {
    store?: unknown;
    dmScope?: "main" | "per-peer" | "per-channel-peer" | "per-account-channel-peer";
  };
  [key: string]: unknown;
};

export type ChannelOutboundSessionRoute = {
  sessionKey: string;
  baseSessionKey: string;
  peer: RoutePeer;
  chatType: RoutePeerKind;
  from: string;
  to: string;
  threadId?: string | number;
};

type AgentRoute = {
  agentId: string;
  channel: string;
  accountId: string;
  sessionKey: string;
  mainSessionKey: string;
  lastRoutePolicy: string;
  matchedBy: string;
};

type ChannelRuntime = {
  routing: {
    resolveAgentRoute: (params: {
      cfg: OpenClawConfig;
      channel: string;
      accountId?: string | null;
      peer: RoutePeer;
    }) => AgentRoute;
    buildAgentSessionKey?: typeof buildAgentSessionKey;
  };
  session: {
    resolveStorePath: (store: unknown, params: { agentId: string }) => string;
    readSessionUpdatedAt: (params: { storePath: string; sessionKey: string }) => number | undefined;
    recordInboundSession: (params: {
      storePath: string;
      sessionKey: string;
      ctx: Record<string, unknown>;
      createIfMissing?: boolean;
      updateLastRoute?: Record<string, unknown>;
      onRecordError?: (error: unknown) => void;
    }) => Promise<void>;
  };
  reply: {
    resolveEnvelopeFormatOptions: (cfg: OpenClawConfig) => unknown;
    formatAgentEnvelope: (params: {
      channel: string;
      from: string;
      timestamp: number;
      previousTimestamp?: number;
      envelope: unknown;
      body: string;
    }) => string;
    finalizeInboundContext: <T extends Record<string, unknown>>(ctx: T) => T;
    dispatchReplyWithBufferedBlockDispatcher: (params: {
      ctx: Record<string, unknown>;
      cfg: OpenClawConfig;
      dispatcherOptions: {
        deliver: (payload: unknown) => Promise<void>;
        onError?: (error: unknown, info: { kind: string }) => void;
        [key: string]: unknown;
      };
    }) => Promise<unknown>;
  };
};

export type PluginRuntime = {
  channel: ChannelRuntime;
};

type AccountSnapshot = {
  configured?: boolean;
  running?: boolean;
  lastStartAt?: number | null;
  lastStopAt?: number | null;
  lastError?: string | null;
  lastInboundAt?: number | null;
  lastOutboundAt?: number | null;
  [key: string]: unknown;
};

type ChannelConfigAdapter<TResolvedAccount> = {
  listAccountIds?: (cfg: OpenClawConfig) => string[];
  resolveAccount?: (cfg: OpenClawConfig, accountId?: string | null) => TResolvedAccount;
  defaultAccountId?: (cfg: OpenClawConfig) => string;
  clearBaseFields?: string[];
  isEnabled?: (account: TResolvedAccount) => boolean;
  isConfigured?: (account: TResolvedAccount) => boolean;
  unconfiguredReason?: (account: TResolvedAccount, cfg?: OpenClawConfig) => string | undefined;
  describeAccount?: (account: TResolvedAccount) => Record<string, unknown>;
  resolveDefaultTo?: (params: {
    cfg: OpenClawConfig;
    accountId?: string | null;
  }) => string | undefined;
  [key: string]: unknown;
};

type TargetKind = "user" | "group" | "channel";

export type ChannelPlugin<TResolvedAccount = unknown> = {
  id: string;
  meta?: Record<string, unknown>;
  capabilities?: Record<string, unknown>;
  reload?: Record<string, unknown>;
  configSchema?: unknown;
  config?: ChannelConfigAdapter<TResolvedAccount>;
  setup?: unknown;
  agentPrompt?: {
    messageToolHints?: () => string[];
  };
  messaging?: {
    normalizeTarget?: (raw: string) => string | undefined;
    parseExplicitTarget?: (params: { raw: string }) => { to: string } | null;
    inferTargetChatType?: (params: {
      to: string;
      accountId?: string | null;
      cfg: OpenClawConfig;
    }) => "direct" | "group" | undefined;
    targetResolver?: {
      looksLikeId?: (raw: string, normalized?: string) => boolean;
      hint?: string;
      resolveTarget?: (params: {
        cfg: OpenClawConfig;
        accountId?: string | null;
        normalized: string;
        preferredKind?: TargetKind;
      }) => Promise<
        | {
            to: string;
            kind: TargetKind;
            display?: string;
            source?: string;
          }
        | null
      >;
    };
    formatTargetDisplay?: (params: { target: string; display?: string }) => string;
    resolveOutboundSessionRoute?: (params: {
      cfg: OpenClawConfig;
      agentId: string;
      accountId?: string | null;
      target: string;
      resolvedTarget?: { to: string } | null;
    }) => Promise<ChannelOutboundSessionRoute | null> | ChannelOutboundSessionRoute | null;
  };
  resolver?: {
    resolveTargets?: (params: {
      cfg: OpenClawConfig;
      accountId?: string | null;
      inputs: string[];
      kind?: TargetKind;
    }) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>;
  };
  directory?: {
    listPeers?: (params: {
      cfg: OpenClawConfig;
      accountId?: string | null;
    }) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>;
    listGroups?: (params: {
      cfg: OpenClawConfig;
      accountId?: string | null;
    }) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>;
  };
  outbound?: {
    deliveryMode?: string;
    textChunkLimit?: number;
    sendText?: (params: {
      cfg: OpenClawConfig;
      to: string;
      text: string;
      accountId?: string | null;
    }) => Promise<Record<string, unknown>>;
    sendMedia?: (params: {
      cfg: OpenClawConfig;
      to: string;
      text: string;
      mediaUrl: string;
      accountId?: string | null;
    }) => Promise<Record<string, unknown>>;
    [key: string]: unknown;
  };
  status?: {
    defaultRuntime?: Record<string, unknown>;
    buildChannelSummary?: (params: {
      account: TResolvedAccount;
      snapshot: AccountSnapshot;
    }) => Record<string, unknown>;
    buildAccountSnapshot?: (params: {
      account: TResolvedAccount;
    }) => Record<string, unknown>;
  };
  gateway?: {
    startAccount?: (ctx: {
      account: TResolvedAccount;
      cfg: OpenClawConfig;
      abortSignal: AbortSignal;
      channelRuntime?: ChannelRuntime;
      setStatus: (snapshot: Record<string, unknown>) => void;
      log?: {
        info?: (message: string) => void;
        error?: (message: string) => void;
      };
    }) => Promise<void>;
  };
  [key: string]: unknown;
};

export function buildChannelConfigSchema<T>(schema: T): T {
  return schema;
}

export function buildAgentSessionKey(params: {
  agentId: string;
  channel: string;
  accountId?: string | null;
  peer: RoutePeer;
  dmScope?: "main" | "per-peer" | "per-channel-peer" | "per-account-channel-peer";
}): string {
  const normalizedAccountId = normalizeAccountId(params.accountId);
  if (params.peer.kind !== "direct") {
    return ["agent", params.agentId, params.channel, params.peer.kind, params.peer.id]
      .join(":")
      .toLowerCase();
  }
  switch (params.dmScope ?? "main") {
    case "main":
      return ["agent", params.agentId, "main"].join(":").toLowerCase();
    case "per-peer":
      return ["agent", params.agentId, "direct", params.peer.id].join(":").toLowerCase();
    case "per-channel-peer":
      return ["agent", params.agentId, params.channel, "direct", params.peer.id]
        .join(":")
        .toLowerCase();
    case "per-account-channel-peer":
      return [
        "agent",
        params.agentId,
        params.channel,
        normalizedAccountId,
        "direct",
        params.peer.id,
      ]
        .join(":")
        .toLowerCase();
  }
}

export function defineChannelPluginEntry<TPlugin extends ChannelPlugin>(params: {
  id: string;
  name: string;
  description: string;
  plugin: TPlugin;
  setRuntime?: (runtime: PluginRuntime) => void;
}) {
  return params;
}

export function defineSetupPluginEntry<TPlugin>(plugin: TPlugin) {
  return { plugin };
}

export { DEFAULT_ACCOUNT_ID };
