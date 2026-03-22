export function createScopedChannelConfigBase<TResolvedAccount, TConfig>(params: {
  sectionKey: string;
  listAccountIds: (cfg: TConfig) => string[];
  resolveAccount: (cfg: TConfig, accountId?: string | null) => TResolvedAccount;
  defaultAccountId: (cfg: TConfig) => string;
  clearBaseFields?: string[];
}) {
  return {
    sectionKey: params.sectionKey,
    listAccountIds: params.listAccountIds,
    resolveAccount: params.resolveAccount,
    defaultAccountId: params.defaultAccountId,
    clearBaseFields: params.clearBaseFields ?? [],
  };
}
