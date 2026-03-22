import {
  buildAgentSessionKey,
  buildChannelConfigSchema,
} from "openclaw/plugin-sdk/core";
import { DEFAULT_ACCOUNT_ID } from "openclaw/plugin-sdk/account-id";
import { createScopedChannelConfigBase } from "openclaw/plugin-sdk/channel-config-helpers";
import {
  listQntmAccountIds,
  normalizeQntmMessagingTarget,
  resolveDefaultQntmAccountId,
  resolveQntmAccount,
  resolveQntmBinding,
} from "./accounts.js";
import { QntmConfigSchema } from "./config-schema.js";
import { describeQntmIdentity } from "./qntm.js";
import { readQntmRuntimeStatus } from "./runtime.js";
import type {
  QntmRootConfig,
  ResolvedQntmAccount,
  ResolvedQntmBinding,
  QntmRuntimeStatus,
} from "./types.js";

export const CHANNEL_ID = "qntm";

export const QNTM_META = {
  id: CHANNEL_ID,
  label: "qntm",
  selectionLabel: "qntm (Relay WebSocket)",
  detailLabel: "qntm",
  docsPath: "/channels/qntm",
  docsLabel: "qntm",
  blurb: "encrypted qntm conversations over the relay websocket with multi-conversation routing.",
  systemImage: "lock.message",
} as const;

export const QNTM_CAPABILITIES = {
  chatTypes: ["direct", "group"],
  media: false,
  blockStreaming: true,
} as const;

const clearBaseFields = [
  "name",
  "enabled",
  "relayUrl",
  "identity",
  "identityFile",
  "defaultTo",
  "conversations",
];

const qntmConfigBase = createScopedChannelConfigBase<ResolvedQntmAccount, QntmRootConfig>({
  sectionKey: CHANNEL_ID,
  listAccountIds: listQntmAccountIds,
  resolveAccount: (cfg, accountId) => resolveQntmAccount({ cfg, accountId }),
  defaultAccountId: resolveDefaultQntmAccountId,
  clearBaseFields,
});

export function buildQntmAccountSnapshot(params: {
  account: ResolvedQntmAccount;
  runtime?: QntmRuntimeStatus;
}) {
  const runtime = params.runtime ?? readQntmRuntimeStatus(params.account.accountId);
  const identity = describeQntmIdentity(params.account.identity);
  return {
    accountId: params.account.accountId,
    name: params.account.name,
    enabled: params.account.enabled,
    configured: params.account.configured,
    running: runtime.running ?? false,
    lastStartAt: runtime.lastStartAt ?? null,
    lastStopAt: runtime.lastStopAt ?? null,
    lastError: runtime.lastError ?? params.account.configErrors[0] ?? null,
    lastInboundAt: runtime.lastInboundAt ?? null,
    lastOutboundAt: runtime.lastOutboundAt ?? null,
    baseUrl: params.account.relayUrl,
    publicKey: identity.publicKey ?? null,
    keyId: identity.keyId ?? null,
    bindingCount: params.account.bindings.filter((binding) => binding.enabled).length,
    defaultTo: params.account.defaultTo ?? null,
    identitySource: params.account.identitySource,
  };
}

export const qntmConfigAdapter = {
  ...qntmConfigBase,
  isEnabled: (account: ResolvedQntmAccount) => account.enabled,
  isConfigured: (account: ResolvedQntmAccount) => account.configured,
  unconfiguredReason: (account: ResolvedQntmAccount, _cfg?: QntmRootConfig) => {
    if (!account.identity) {
      return "qntm identity is not configured";
    }
    if (!account.bindings.some((binding) => binding.enabled)) {
      return "no enabled qntm conversations are configured";
    }
    return "qntm account is not configured";
  },
  describeAccount: (account: ResolvedQntmAccount) => buildQntmAccountSnapshot({ account }),
  resolveDefaultTo: ({ cfg, accountId }: { cfg: QntmRootConfig; accountId?: string | null }) =>
    resolveQntmAccount({ cfg, accountId }).defaultTo,
};

export function createQntmPluginBase(params: { setup: unknown }) {
  return {
    id: CHANNEL_ID,
    meta: { ...QNTM_META },
    capabilities: { ...QNTM_CAPABILITIES },
    reload: { configPrefixes: ["channels.qntm"] },
    configSchema: buildChannelConfigSchema(QntmConfigSchema),
    config: qntmConfigAdapter,
    setup: params.setup,
  };
}

export function looksLikeQntmTargetId(raw: string, normalized?: string): boolean {
  return Boolean(normalized ?? normalizeQntmMessagingTarget(raw));
}

export function parseQntmExplicitTarget(params: { raw: string }) {
  const to = normalizeQntmMessagingTarget(params.raw);
  return to ? { to } : null;
}

export function buildQntmSessionKey(params: {
  agentId: string;
  accountId?: string | null;
  binding: ResolvedQntmBinding;
}): string {
  return buildAgentSessionKey({
    agentId: params.agentId,
    channel: CHANNEL_ID,
    accountId: params.accountId ?? DEFAULT_ACCOUNT_ID,
    peer: {
      kind: params.binding.chatType,
      id: params.binding.conversationId,
    },
    ...(params.binding.chatType === "direct"
      ? { dmScope: "per-account-channel-peer" as const }
      : {}),
  }).toLowerCase();
}

export function resolveQntmOutboundSessionRoute(params: {
  cfg: QntmRootConfig;
  agentId: string;
  accountId?: string | null;
  target: string;
  resolvedTarget?: { to: string } | null;
}) {
  const account = resolveQntmAccount({
    cfg: params.cfg,
    accountId: params.accountId,
  });
  const binding = resolveQntmBinding(account, params.resolvedTarget?.to ?? params.target);
  if (!binding) {
    return null;
  }
  const sessionKey = buildQntmSessionKey({
    agentId: params.agentId,
    accountId: account.accountId,
    binding,
  });
  return {
    sessionKey,
    baseSessionKey: sessionKey,
    peer: {
      kind: binding.chatType,
      id: binding.conversationId,
    },
    chatType: binding.chatType,
    from: `qntm:${binding.conversationId}`,
    to: `qntm:${binding.conversationId}`,
  };
}

export function listQntmDirectoryEntries(params: {
  account: ResolvedQntmAccount;
  kind: "direct" | "group";
}) {
  return params.account.bindings
    .filter((binding) => binding.enabled && binding.chatType === params.kind)
    .map((binding) => ({
      id: binding.conversationId,
      name: binding.label,
      handle: binding.target,
      raw: {
        target: binding.target,
        conversationId: binding.conversationId,
      },
    }));
}
