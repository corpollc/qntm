type NormalizeAccountId = (accountId?: string | null) => string;

export function createAccountListHelpers(
  channelId: string,
  params: { normalizeAccountId: NormalizeAccountId },
) {
  const listAccountIds = (cfg: Record<string, any>): string[] => {
    const channel = cfg?.channels?.[channelId] ?? {};
    const result = new Set<string>();
    const accounts = channel.accounts;
    if (accounts && typeof accounts === "object") {
      for (const key of Object.keys(accounts)) {
        result.add(params.normalizeAccountId(key));
      }
    }
    const hasTopLevelConfig = Object.keys(channel).some(
      (key) => key !== "accounts" && key !== "defaultAccount",
    );
    if (hasTopLevelConfig || result.size === 0) {
      result.add(params.normalizeAccountId(channel.defaultAccount));
    }
    return Array.from(result).sort((left, right) => left.localeCompare(right));
  };

  const resolveDefaultAccountId = (cfg: Record<string, any>): string => {
    const channel = cfg?.channels?.[channelId] ?? {};
    if (typeof channel.defaultAccount === "string" && channel.defaultAccount.trim()) {
      return params.normalizeAccountId(channel.defaultAccount);
    }
    return listAccountIds(cfg)[0] ?? params.normalizeAccountId();
  };

  return {
    listAccountIds,
    resolveDefaultAccountId,
  };
}
