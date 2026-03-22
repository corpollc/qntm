import { createAccountListHelpers } from "openclaw/plugin-sdk/account-helpers";
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from "openclaw/plugin-sdk/account-id";
import type {
  QntmAccountConfig,
  QntmRootConfig,
  ResolvedQntmAccount,
  ResolvedQntmBinding,
} from "./types.js";
import {
  resolveInviteConversation,
  resolveQntmIdentity,
  toHex,
} from "./qntm.js";

const DEFAULT_RELAY_URL = "https://inbox.qntm.corpo.llc";
const TARGET_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

const {
  listAccountIds: listQntmAccountIds,
  resolveDefaultAccountId: resolveDefaultQntmAccountId,
} = createAccountListHelpers("qntm", { normalizeAccountId });

export { listQntmAccountIds, resolveDefaultQntmAccountId };

function resolveAccountConfig(
  cfg: QntmRootConfig,
  accountId: string,
): QntmAccountConfig | undefined {
  const accounts = cfg.channels?.qntm?.accounts;
  if (!accounts || typeof accounts !== "object") {
    return undefined;
  }
  if (accounts[accountId]) {
    return accounts[accountId];
  }
  const normalized = normalizeAccountId(accountId);
  const matchedKey = Object.keys(accounts).find((key) => normalizeAccountId(key) === normalized);
  return matchedKey ? accounts[matchedKey] : undefined;
}

function mergeAccountConfig(cfg: QntmRootConfig, accountId: string): QntmAccountConfig {
  const {
    accounts: _accounts,
    defaultAccount: _defaultAccount,
    ...base
  } = (cfg.channels?.qntm ?? {}) as QntmAccountConfig & {
    accounts?: unknown;
    defaultAccount?: unknown;
  };
  const account = resolveAccountConfig(cfg, accountId) ?? {};
  return {
    ...base,
    ...account,
    conversations: {
      ...(base.conversations ?? {}),
      ...(account.conversations ?? {}),
    },
  };
}

function normalizeTargetToken(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) {
    return undefined;
  }
  if (/^[0-9a-f]{32}$/i.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  if (TARGET_RE.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  const normalized = trimmed
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "");
  return normalized || undefined;
}

export function normalizeQntmMessagingTarget(raw: string): string | undefined {
  let normalized = raw.trim();
  for (const prefix of ["qntm:", "conversation:", "conv:", "group:", "user:"]) {
    if (normalized.toLowerCase().startsWith(prefix)) {
      normalized = normalized.slice(prefix.length).trim();
      break;
    }
  }
  return normalizeTargetToken(normalized);
}

export function normalizeQntmBindingKey(raw: string): string | undefined {
  return normalizeTargetToken(raw);
}

function resolveBindings(config: QntmAccountConfig, errors: string[]): ResolvedQntmBinding[] {
  const bindings: ResolvedQntmBinding[] = [];
  for (const [rawKey, value] of Object.entries(config.conversations ?? {})) {
    if (!value?.invite?.trim()) {
      continue;
    }
    const key = normalizeQntmBindingKey(rawKey);
    if (!key) {
      errors.push(`invalid qntm conversation key: ${rawKey}`);
      continue;
    }
    try {
      const conversation = resolveInviteConversation(value.invite);
      bindings.push({
        key,
        target: key,
        label: value.name?.trim() || rawKey || toHex(conversation.id),
        enabled: value.enabled !== false,
        invite: value.invite.trim(),
        conversationId: toHex(conversation.id),
        conversation,
        chatType: conversation.type === "group" ? "group" : "direct",
      });
    } catch (error) {
      errors.push(`invalid qntm invite for "${rawKey}": ${String(error)}`);
    }
  }
  return bindings.toSorted((left, right) => left.key.localeCompare(right.key));
}

function resolveDefaultBindingTarget(account: {
  bindings: ResolvedQntmBinding[];
  config: QntmAccountConfig;
}): string | undefined {
  const explicit = normalizeQntmMessagingTarget(account.config.defaultTo ?? "");
  if (explicit) {
    const matched = account.bindings.find(
      (binding) => binding.enabled && (binding.target === explicit || binding.conversationId === explicit),
    );
    if (matched) {
      return explicit;
    }
  }
  return account.bindings.find((binding) => binding.enabled)?.target;
}

export function resolveQntmAccount(params: {
  cfg: QntmRootConfig;
  accountId?: string | null;
}): ResolvedQntmAccount {
  const hasExplicitAccountId = Boolean(params.accountId?.trim());
  const baseEnabled = params.cfg.channels?.qntm?.enabled !== false;

  const resolve = (accountId: string): ResolvedQntmAccount => {
    const config = mergeAccountConfig(params.cfg, accountId);
    const configErrors: string[] = [];
    const enabled = baseEnabled && config.enabled !== false;

    const relayUrl = config.relayUrl?.trim() || DEFAULT_RELAY_URL;
    let identity;
    let identitySource: ResolvedQntmAccount["identitySource"] = "none";
    try {
      const resolvedIdentity = resolveQntmIdentity({
        identity: config.identity,
        identityFile: config.identityFile,
      });
      identity = resolvedIdentity.identity;
      identitySource = resolvedIdentity.source;
    } catch (error) {
      configErrors.push(`invalid qntm identity: ${String(error)}`);
    }

    const bindings = resolveBindings(config, configErrors);
    const configured = Boolean(identity && bindings.some((binding) => binding.enabled));

    return {
      accountId,
      name: config.name?.trim() || undefined,
      enabled,
      configured,
      relayUrl,
      identity,
      identitySource,
      defaultTo: resolveDefaultBindingTarget({ bindings, config }),
      bindings,
      config,
      configErrors,
    };
  };

  const requested = normalizeAccountId(params.accountId);
  const primary = resolve(requested);
  if (hasExplicitAccountId) {
    return primary;
  }
  if (primary.configured) {
    return primary;
  }
  const fallbackId = resolveDefaultQntmAccountId(params.cfg);
  if (fallbackId === primary.accountId) {
    return primary;
  }
  const fallback = resolve(fallbackId);
  return fallback.configured ? fallback : primary;
}

export function listEnabledQntmAccounts(cfg: QntmRootConfig): ResolvedQntmAccount[] {
  return listQntmAccountIds(cfg)
    .map((accountId) => resolveQntmAccount({ cfg, accountId }))
    .filter((account) => account.enabled);
}

export function resolveQntmBinding(
  account: Pick<ResolvedQntmAccount, "bindings" | "defaultTo">,
  target?: string | null,
): ResolvedQntmBinding | null {
  const normalized = normalizeQntmMessagingTarget(target ?? account.defaultTo ?? "");
  if (!normalized) {
    return null;
  }
  return (
    account.bindings.find(
      (binding) =>
        binding.enabled && (binding.target === normalized || binding.conversationId === normalized),
    ) ?? null
  );
}

export function isDefaultQntmAccount(accountId?: string | null): boolean {
  return normalizeAccountId(accountId) === DEFAULT_ACCOUNT_ID;
}
