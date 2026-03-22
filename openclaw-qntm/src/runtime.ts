import type { PluginRuntime } from "openclaw/plugin-sdk/core";
import type { QntmRuntimeStatus } from "./types.js";

let runtime: PluginRuntime | undefined;
const accountStatus = new Map<string, QntmRuntimeStatus>();

export function setQntmRuntime(nextRuntime: PluginRuntime): void {
  runtime = nextRuntime;
}

export function getQntmRuntime(): PluginRuntime | undefined {
  return runtime;
}

export function readQntmRuntimeStatus(accountId: string): QntmRuntimeStatus {
  return { ...(accountStatus.get(accountId) ?? {}) };
}

export function patchQntmRuntimeStatus(
  accountId: string,
  patch: QntmRuntimeStatus,
): QntmRuntimeStatus {
  const next = {
    ...(accountStatus.get(accountId) ?? {}),
    ...patch,
  };
  accountStatus.set(accountId, next);
  return next;
}

export function clearQntmRuntimeStatus(accountId: string): void {
  accountStatus.delete(accountId);
}

export const __testing = {
  reset(): void {
    runtime = undefined;
    accountStatus.clear();
  },
};
