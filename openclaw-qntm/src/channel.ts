import { DropboxClient } from "@corpollc/qntm";
import {
  DEFAULT_ACCOUNT_ID,
  type ChannelPlugin,
  type OpenClawConfig,
} from "openclaw/plugin-sdk";
import {
  listQntmDirectoryEntries,
  looksLikeQntmTargetId,
  parseQntmExplicitTarget,
  buildQntmAccountSnapshot,
  buildQntmSessionKey,
  CHANNEL_ID,
  createQntmPluginBase,
  qntmConfigAdapter,
  resolveQntmOutboundSessionRoute,
} from "./shared.js";
import { normalizeQntmMessagingTarget, resolveQntmAccount, resolveQntmBinding } from "./accounts.js";
import { monitorQntmAccount } from "./monitor.js";
import { flattenQntmReplyPayload, sendQntmText } from "./qntm.js";
import { getQntmRuntime, patchQntmRuntimeStatus } from "./runtime.js";
import { qntmSetupAdapter } from "./setup-core.js";
import type { QntmRootConfig, ResolvedQntmAccount } from "./types.js";

async function sendOutbound(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
  to: string;
  text: string;
  mediaUrl?: string | null;
}) {
  const account = resolveQntmAccount({
    cfg: params.cfg as QntmRootConfig,
    accountId: params.accountId,
  });
  if (!account.identity) {
    throw new Error(`qntm identity is not configured for account "${account.accountId}"`);
  }
  const binding = resolveQntmBinding(account, params.to);
  if (!binding) {
    throw new Error(`unknown qntm target "${params.to}" for account "${account.accountId}"`);
  }
  const text = flattenQntmReplyPayload({
    text: params.text,
    mediaUrl: params.mediaUrl ?? undefined,
  });
  if (!text.trim()) {
    return {
      messageId: "",
      conversationId: binding.conversationId,
      meta: { target: binding.target },
    };
  }
  const result = await sendQntmText({
    client: new DropboxClient(account.relayUrl),
    identity: account.identity,
    conversation: binding.conversation,
    text,
  });
  patchQntmRuntimeStatus(account.accountId, {
    lastOutboundAt: Date.now(),
    lastError: null,
  });
  return {
    messageId: result.messageId,
    conversationId: binding.conversationId,
    meta: {
      sequence: result.sequence,
      target: binding.target,
    },
  };
}

function inferChatType(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
  to: string;
}): "direct" | "group" | undefined {
  const account = resolveQntmAccount({
    cfg: params.cfg as QntmRootConfig,
    accountId: params.accountId,
  });
  return resolveQntmBinding(account, params.to)?.chatType;
}

async function waitForAbort(signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return;
  }
  await new Promise<void>((resolve) => {
    signal.addEventListener("abort", () => resolve(), { once: true });
  });
}

export const qntmPlugin: ChannelPlugin<ResolvedQntmAccount> = {
  ...createQntmPluginBase({ setup: qntmSetupAdapter }),
  agentPrompt: {
    messageToolHints: () => [
      "qntm targets are configured conversation bindings. Use a binding id or a raw qntm conv_id.",
      "Replies stay pinned to the originating qntm conversation, even when the account listens to multiple conversations.",
    ],
  },
  messaging: {
    normalizeTarget: normalizeQntmMessagingTarget,
    parseExplicitTarget: parseQntmExplicitTarget,
    inferTargetChatType: ({ to, accountId, cfg }) => inferChatType({ cfg, accountId, to }),
    targetResolver: {
      looksLikeId: looksLikeQntmTargetId,
      hint: "<binding-id|conv-id>",
      resolveTarget: async ({ cfg, accountId, normalized, preferredKind }) => {
        const account = resolveQntmAccount({
          cfg: cfg as QntmRootConfig,
          accountId,
        });
        const binding = resolveQntmBinding(account, normalized);
        if (!binding) {
          return null;
        }
        const kind = binding.chatType === "group" ? "group" : "user";
        if (preferredKind && preferredKind !== kind) {
          return null;
        }
        return {
          to: binding.conversationId,
          kind,
          display: binding.label,
          source: "directory" as const,
        };
      },
    },
    formatTargetDisplay: ({ target, display }) =>
      display ? `${display} (${target})` : target,
    resolveOutboundSessionRoute: async (params) =>
      resolveQntmOutboundSessionRoute({
        cfg: params.cfg as QntmRootConfig,
        agentId: params.agentId,
        accountId: params.accountId,
        target: params.target,
        resolvedTarget: params.resolvedTarget
          ? { to: params.resolvedTarget.to }
          : null,
      }),
  },
  resolver: {
    resolveTargets: async ({ cfg, accountId, inputs, kind }) => {
      const account = resolveQntmAccount({
        cfg: cfg as QntmRootConfig,
        accountId,
      });
      return inputs.map((input) => {
        const binding = resolveQntmBinding(account, input);
        if (!binding) {
          return {
            input,
            resolved: false,
            note: "unknown qntm conversation",
          };
        }
        if (kind === "group" && binding.chatType !== "group") {
          return {
            input,
            resolved: false,
            note: "qntm target is configured as a direct conversation",
          };
        }
        if (kind === "user" && binding.chatType !== "direct") {
          return {
            input,
            resolved: false,
            note: "qntm target is configured as a group conversation",
          };
        }
        return {
          input,
          resolved: true,
          id: binding.conversationId,
          name: binding.label,
        };
      });
    },
  },
  directory: {
    listPeers: async ({ cfg, accountId }) => {
      const account = resolveQntmAccount({
        cfg: cfg as QntmRootConfig,
        accountId,
      });
      return listQntmDirectoryEntries({ account, kind: "direct" }).map((entry) => ({
        kind: "user" as const,
        ...entry,
      }));
    },
    listGroups: async ({ cfg, accountId }) => {
      const account = resolveQntmAccount({
        cfg: cfg as QntmRootConfig,
        accountId,
      });
      return listQntmDirectoryEntries({ account, kind: "group" }).map((entry) => ({
        kind: "group" as const,
        ...entry,
      }));
    },
  },
  outbound: {
    deliveryMode: "direct",
    textChunkLimit: 4000,
    sendText: async ({ cfg, to, text, accountId }) => ({
      channel: CHANNEL_ID,
      ...(await sendOutbound({ cfg, accountId, to, text })),
    }),
    sendMedia: async ({ cfg, to, text, mediaUrl, accountId }) => ({
      channel: CHANNEL_ID,
      ...(await sendOutbound({
        cfg,
        accountId,
        to,
        text,
        mediaUrl,
      })),
    }),
  },
  status: {
    defaultRuntime: {
      accountId: DEFAULT_ACCOUNT_ID,
      running: false,
      lastStartAt: null,
      lastStopAt: null,
      lastError: null,
      lastInboundAt: null,
      lastOutboundAt: null,
    },
    buildChannelSummary: ({ account, snapshot }) => ({
      configured: snapshot.configured ?? account.configured,
      running: snapshot.running ?? false,
      relayUrl: account.relayUrl,
      bindingCount: account.bindings.filter((binding) => binding.enabled).length,
      lastInboundAt: snapshot.lastInboundAt ?? null,
      lastOutboundAt: snapshot.lastOutboundAt ?? null,
      identitySource: account.identitySource,
    }),
    buildAccountSnapshot: ({ account }) => buildQntmAccountSnapshot({ account }),
  },
  gateway: {
    startAccount: async (ctx) => {
      const account = ctx.account;
      if (!account.configured || !account.identity) {
        const reason =
          qntmConfigAdapter.unconfiguredReason?.(account, ctx.cfg as QntmRootConfig) ??
          "qntm account is not configured";
        throw new Error(`qntm is not configured for account "${account.accountId}" (${reason})`);
      }

      const patchStatus = (patch: {
        running?: boolean;
        lastStartAt?: number | null;
        lastStopAt?: number | null;
        lastError?: string | null;
        lastInboundAt?: number | null;
        lastOutboundAt?: number | null;
      }) => {
        const runtime = patchQntmRuntimeStatus(account.accountId, patch);
        ctx.setStatus(buildQntmAccountSnapshot({ account, runtime }));
      };

      ctx.log?.info?.(
        `[${account.accountId}] starting qntm relay monitor (${account.bindings.filter((binding) => binding.enabled).length} conversations)`,
      );
      patchStatus({
        running: true,
        lastStartAt: Date.now(),
        lastStopAt: null,
        lastError: null,
      });
      try {
        const channelRuntime = ctx.channelRuntime ?? getQntmRuntime()?.channel;
        if (!channelRuntime) {
          throw new Error(
            "qntm channel runtime is unavailable; use OpenClaw Plugin SDK channelRuntime or register the plugin before starting accounts",
          );
        }

        const monitor = await monitorQntmAccount({
          account,
          cfg: ctx.cfg,
          channelRuntime,
          abortSignal: ctx.abortSignal,
          statusSink: patchStatus,
          log: ctx.log,
        });
        try {
          await waitForAbort(ctx.abortSignal);
        } finally {
          monitor.stop();
        }
        return;
      } catch (error) {
        patchStatus({
          running: false,
          lastStopAt: Date.now(),
          lastError: String(error),
        });
        throw error;
      }
    },
  },
};
