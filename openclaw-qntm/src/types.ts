import type { Conversation, Identity } from "@corpollc/qntm";
import type { OpenClawConfig } from "openclaw/plugin-sdk";

export type QntmConversationConfig = {
  name?: string;
  enabled?: boolean;
  invite?: string;
  convId?: string;
  /** When to dispatch inbound messages to the agent.
   *  - "all" (default): every message is dispatched
   *  - "mention": only when body contains one of `triggerNames` (case-insensitive)
   */
  trigger?: "all" | "mention";
  /** Names that trigger the agent when `trigger` is "mention".
   *  Matched case-insensitively anywhere in the message body.
   *  If empty/missing and trigger is "mention", the conversation `name` is used as fallback.
   */
  triggerNames?: string[];
};

export type QntmAccountConfig = {
  name?: string;
  enabled?: boolean;
  relayUrl?: string;
  identity?: string;
  identityFile?: string;
  identityDir?: string;
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
  invite?: string;
  conversationId: string;
  conversation: Conversation;
  chatType: "direct" | "group";
  trigger: "all" | "mention";
  triggerNames: string[];
};

export type ResolvedQntmAccount = {
  accountId: string;
  name?: string;
  enabled: boolean;
  configured: boolean;
  relayUrl: string;
  identity?: Identity;
  identitySource: "config" | "identityFile" | "identityDir" | "none";
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
