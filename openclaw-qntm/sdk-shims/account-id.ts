export const DEFAULT_ACCOUNT_ID = "default";

export function normalizeAccountId(accountId?: string | null): string {
  const trimmed = accountId?.trim().toLowerCase();
  return trimmed || DEFAULT_ACCOUNT_ID;
}
