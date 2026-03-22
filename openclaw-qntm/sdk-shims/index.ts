import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from "./account-id.js";
import { createAccountListHelpers } from "./account-helpers.js";
import {
  createNormalizedOutboundDeliverer,
  type OutboundReplyPayload,
} from "./reply-payload.js";

export { DEFAULT_ACCOUNT_ID, normalizeAccountId };
export { createAccountListHelpers };
export { createNormalizedOutboundDeliverer };
export type { OutboundReplyPayload };

export type RoutePeerKind = "direct" | "group" | "channel" | "thread";

export type RoutePeer = {
  kind: RoutePeerKind;
  id: string;
};

export type OpenClawConfig = {
  channels?: Record<string, unknown>;
  session?: {
    store?: unknown;
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
  accountId: string;
  sessionKey: string;
};

export type ChannelAccountSnapshot = {
  configured?: boolean;
  running?: boolean;
  lastStartAt?: number | null;
  lastStopAt?: number | null;
  lastError?: string | null;
  lastInboundAt?: number | null;
  lastOutboundAt?: number | null;
  [key: string]: unknown;
};

export type ChannelLogSink = {
  debug?: (message: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

type ChannelRuntime = {
  routing: {
    resolveAgentRoute: (params: {
      cfg: OpenClawConfig;
      channel: string;
      accountId?: string | null;
      peer: RoutePeer;
    }) => AgentRoute;
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
      replyOptions?: Record<string, unknown>;
    }) => Promise<unknown>;
  };
};

export type PluginRuntime = {
  channel: ChannelRuntime;
};

export type RuntimeEnv = PluginRuntime;

export type OpenClawPluginApi = {
  runtime: PluginRuntime;
  registerChannel: (params: { plugin: ChannelPlugin; dock?: unknown }) => void;
};

type ChannelConfigAdapter<TResolvedAccount> = {
  listAccountIds?: (cfg: OpenClawConfig) => string[];
  resolveAccount?: (cfg: OpenClawConfig, accountId?: string | null) => TResolvedAccount;
  defaultAccountId?: (cfg: OpenClawConfig) => string;
  clearBaseFields?: string[];
  isEnabled?: (account: TResolvedAccount, cfg: OpenClawConfig) => boolean;
  isConfigured?: (account: TResolvedAccount, cfg: OpenClawConfig) => boolean;
  unconfiguredReason?: (account: TResolvedAccount, cfg?: OpenClawConfig) => string | undefined;
  describeAccount?: (account: TResolvedAccount, cfg: OpenClawConfig) => Record<string, unknown>;
  resolveDefaultTo?: (params: {
    cfg: OpenClawConfig;
    accountId?: string | null;
  }) => string | undefined;
  [key: string]: unknown;
};

type TargetKind = "user" | "group" | "channel";

export type ChannelPlugin<TResolvedAccount = unknown, TProbe = unknown> = {
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
      runtime?: RuntimeEnv;
    }) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>;
    listGroups?: (params: {
      cfg: OpenClawConfig;
      accountId?: string | null;
      runtime?: RuntimeEnv;
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
      replyToId?: string;
    }) => Promise<Record<string, unknown>>;
    sendMedia?: (params: {
      cfg: OpenClawConfig;
      to: string;
      text: string;
      mediaUrl: string;
      accountId?: string | null;
      replyToId?: string;
    }) => Promise<Record<string, unknown>>;
    [key: string]: unknown;
  };
  status?: {
    defaultRuntime?: Record<string, unknown>;
    probeAccount?: (params: {
      cfg: OpenClawConfig;
      account: TResolvedAccount;
      timeoutMs?: number;
    }) => Promise<TProbe> | TProbe;
    buildChannelSummary?: (params: {
      account: TResolvedAccount;
      snapshot: ChannelAccountSnapshot;
      runtime?: ChannelAccountSnapshot;
      probe?: TProbe;
    }) => Record<string, unknown>;
    buildAccountSnapshot?: (params: {
      account: TResolvedAccount;
      runtime?: ChannelAccountSnapshot;
      probe?: TProbe;
    }) => Record<string, unknown>;
  };
  gateway?: {
    startAccount?: (ctx: {
      cfg: OpenClawConfig;
      accountId: string;
      account: TResolvedAccount;
      runtime: RuntimeEnv;
      abortSignal: AbortSignal;
      log?: ChannelLogSink;
      getStatus: () => ChannelAccountSnapshot;
      setStatus: (snapshot: ChannelAccountSnapshot) => void;
    }) => Promise<unknown>;
    stopAccount?: (ctx: {
      cfg: OpenClawConfig;
      accountId: string;
      account: TResolvedAccount;
      runtime: RuntimeEnv;
      log?: ChannelLogSink;
    }) => Promise<void>;
    logoutAccount?: (ctx: {
      cfg: OpenClawConfig;
      accountId: string;
      account: TResolvedAccount;
      runtime: RuntimeEnv;
      log?: ChannelLogSink;
    }) => Promise<Record<string, unknown>>;
  };
  [key: string]: unknown;
};

export function emptyPluginConfigSchema() {
  return {
    safeParse(value: unknown) {
      if (value === undefined) {
        return { success: true, data: undefined };
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return {
          success: false,
          error: { issues: [{ path: [], message: "expected config object" }] },
        };
      }
      if (Object.keys(value).length > 0) {
        return {
          success: false,
          error: { issues: [{ path: [], message: "config must be empty" }] },
        };
      }
      return { success: true, data: value };
    },
    jsonSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  };
}

export function buildChannelConfigSchema<T>(schema: T): T {
  return schema;
}

export function setAccountEnabledInConfigSection(params: {
  cfg: OpenClawConfig;
  sectionKey: string;
  accountId: string;
  enabled: boolean;
  allowTopLevel?: boolean;
}): OpenClawConfig {
  const accountId = normalizeAccountId(params.accountId);
  const channels = params.cfg.channels ?? {};
  const base = (channels[params.sectionKey] ?? {}) as {
    accounts?: Record<string, Record<string, unknown>>;
    enabled?: boolean;
  };
  const hasAccounts = Boolean(base.accounts);
  if (params.allowTopLevel && accountId === DEFAULT_ACCOUNT_ID && !hasAccounts) {
    return {
      ...params.cfg,
      channels: {
        ...channels,
        [params.sectionKey]: {
          ...base,
          enabled: params.enabled,
        },
      },
    };
  }

  const accounts = { ...(base.accounts ?? {}) };
  accounts[accountId] = {
    ...(accounts[accountId] ?? {}),
    enabled: params.enabled,
  };
  return {
    ...params.cfg,
    channels: {
      ...channels,
      [params.sectionKey]: {
        ...base,
        accounts,
      },
    },
  };
}

export function deleteAccountFromConfigSection(params: {
  cfg: OpenClawConfig;
  sectionKey: string;
  accountId: string;
  clearBaseFields?: string[];
}): OpenClawConfig {
  const accountId = normalizeAccountId(params.accountId);
  const channels = params.cfg.channels ?? {};
  const base = channels[params.sectionKey] as
    | ({
        accounts?: Record<string, Record<string, unknown>>;
      } & Record<string, unknown>)
    | undefined;
  if (!base) {
    return params.cfg;
  }

  const accounts = base.accounts ? { ...base.accounts } : {};
  if (accountId !== DEFAULT_ACCOUNT_ID) {
    delete accounts[accountId];
    return {
      ...params.cfg,
      channels: {
        ...channels,
        [params.sectionKey]: {
          ...base,
          accounts: Object.keys(accounts).length > 0 ? accounts : undefined,
        },
      },
    };
  }

  if (Object.keys(accounts).length > 0) {
    delete accounts[accountId];
    const nextBase = { ...base };
    for (const field of params.clearBaseFields ?? []) {
      nextBase[field] = undefined;
    }
    return {
      ...params.cfg,
      channels: {
        ...channels,
        [params.sectionKey]: {
          ...nextBase,
          accounts: Object.keys(accounts).length > 0 ? accounts : undefined,
        },
      },
    };
  }

  const nextChannels = { ...channels };
  delete nextChannels[params.sectionKey];
  const nextCfg = { ...params.cfg };
  if (Object.keys(nextChannels).length > 0) {
    nextCfg.channels = nextChannels;
  } else {
    delete nextCfg.channels;
  }
  return nextCfg;
}

export function createReplyPrefixOptions(_params: {
  cfg: OpenClawConfig;
  agentId: string;
  channel: string;
  accountId?: string | null;
}) {
  return {
    onModelSelected: undefined as ((model: unknown) => void) | undefined,
  };
}
