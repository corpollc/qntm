import type { Conversation, Identity } from "@corpollc/qntm";
import type { OpenClawConfig } from "openclaw/plugin-sdk/core";

export type QntmConversationConfig = {
  name?: string;
  enabled?: boolean;
  invite?: string;
};

export type QntmAccountConfig = {
  name?: string;
  enabled?: boolean;
  relayUrl?: string;
  identity?: string;
  identityFile?: string;
  defaultTo?: string;
  conversations?: Record<string, QntmConversationConfig | undefined>;
};

export type QntmChannelConfig = QntmAccountConfig & {
  accounts?: Record<string, QntmAccountConfig | undefined>;
  defaultAccount?: string;
};

export type QntmRootConfig = OpenClawConfig & {
  channels?: OpenClawConfig["channels"] & {
    qntm?: QntmChannelConfig;
  };
};

export type ResolvedQntmBinding = {
  key: string;
  target: string;
  label: string;
  enabled: boolean;
  invite: string;
  conversationId: string;
  conversation: Conversation;
  chatType: "direct" | "group";
};

export type ResolvedQntmAccount = {
  accountId: string;
  name?: string;
  enabled: boolean;
  configured: boolean;
  relayUrl: string;
  identity?: Identity;
  identitySource: "config" | "identityFile" | "none";
  defaultTo?: string;
  bindings: ResolvedQntmBinding[];
  config: QntmAccountConfig;
  configErrors: string[];
};

export type QntmRuntimeStatus = {
  running?: boolean;
  lastStartAt?: number | null;
  lastStopAt?: number | null;
  lastError?: string | null;
  lastInboundAt?: number | null;
  lastOutboundAt?: number | null;
};
