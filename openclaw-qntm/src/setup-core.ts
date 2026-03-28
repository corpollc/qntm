import { existsSync } from "node:fs";
import { normalizeAccountId } from "openclaw/plugin-sdk";
import { normalizeQntmBindingKey } from "./accounts.js";
import { loadQntmIdentityFromString, resolveInviteConversation, toHex } from "./qntm.js";
import type { QntmAccountConfig, QntmRootConfig } from "./types.js";

type QntmSetupInput = {
  name?: string;
  url?: string;
  privateKey?: string;
  token?: string;
};

type ResolveAccountIdParams = {
  accountId?: string | null;
};

type ApplyAccountNameParams = {
  cfg: QntmRootConfig;
  accountId: string;
  name?: string;
};

type ValidateInputParams = {
  input: QntmSetupInput;
};

type ApplyAccountConfigParams = {
  cfg: QntmRootConfig;
  accountId: string;
  input: QntmSetupInput;
};

function upsertAccountConfig(
  cfg: QntmRootConfig,
  accountId: string,
  update: (current: QntmAccountConfig) => QntmAccountConfig,
): QntmRootConfig {
  const channel = cfg.channels?.qntm ?? {};
  const accounts = { ...(channel.accounts ?? {}) };
  accounts[accountId] = update(accounts[accountId] ?? {});
  return {
    ...cfg,
    channels: {
      ...cfg.channels,
      qntm: {
        ...channel,
        accounts,
        defaultAccount: channel.defaultAccount ?? accountId,
      },
    },
  };
}

function resolveSetupBindingKey(params: {
  name?: string;
  token: string;
}): string {
  const normalizedName = normalizeQntmBindingKey(params.name ?? "");
  if (normalizedName) {
    return normalizedName;
  }
  const conversation = resolveInviteConversation(params.token);
  return `conv-${toHex(conversation.id).slice(0, 8)}`;
}

function resolveIdentityUpdate(raw: string): Pick<QntmAccountConfig, "identity" | "identityFile"> {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {};
  }
  if (existsSync(trimmed)) {
    return {
      identityFile: trimmed,
      identity: undefined,
    };
  }
  loadQntmIdentityFromString(trimmed);
  return {
    identity: trimmed,
    identityFile: undefined,
  };
}

export const qntmSetupAdapter = {
  resolveAccountId: ({ accountId }: ResolveAccountIdParams) => normalizeAccountId(accountId),
  applyAccountName: ({ cfg, accountId, name }: ApplyAccountNameParams) =>
    upsertAccountConfig(cfg, accountId, (current) => ({
      ...current,
      ...(name?.trim() ? { name: name.trim() } : {}),
    })),
  validateInput: ({ input }: ValidateInputParams) => {
    if (input.privateKey?.trim()) {
      try {
        resolveIdentityUpdate(input.privateKey);
      } catch (error) {
        return `invalid qntm identity: ${String(error)}`;
      }
    }
    if (input.token?.trim()) {
      try {
        resolveInviteConversation(input.token);
      } catch (error) {
        return `invalid qntm invite: ${String(error)}`;
      }
    }
    return null;
  },
  applyAccountConfig: ({ cfg, accountId, input }: ApplyAccountConfigParams) =>
    upsertAccountConfig(cfg, accountId, (current) => {
      const next: QntmAccountConfig = {
        ...current,
        enabled: true,
      };

      if (input.url?.trim()) {
        next.relayUrl = input.url.trim();
      }
      if (input.name?.trim()) {
        next.name = input.name.trim();
      }
      if (input.privateKey?.trim()) {
        Object.assign(next, resolveIdentityUpdate(input.privateKey));
      }
      if (input.token?.trim()) {
        const bindingKey = resolveSetupBindingKey({
          name: input.name,
          token: input.token,
        });
        next.conversations = {
          ...(current.conversations ?? {}),
          [bindingKey]: {
            ...(current.conversations?.[bindingKey] ?? {}),
            name: input.name?.trim() || current.conversations?.[bindingKey]?.name,
            invite: input.token.trim(),
            enabled: true,
          },
        };
        next.defaultTo = next.defaultTo ?? bindingKey;
      }
      return next;
    }),
};

export const __testing = {
  upsertAccountConfig,
  resolveSetupBindingKey,
  resolveIdentityUpdate,
};
