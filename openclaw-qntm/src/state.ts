import os from "node:os";
import path from "node:path";
import { readBoundedFile, writePrivateJSON } from "./storage.js";
import { normalizeAccountId } from "openclaw/plugin-sdk/account-id";

function resolveOpenClawStateDir(env: NodeJS.ProcessEnv): string {
  return env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw", "state");
}

export type ConversationCursorStore = {
  getCursor: (params: { accountId: string; conversationId: string }) => Promise<number>;
  setCursor: (params: { accountId: string; conversationId: string; sequence: number }) => Promise<void>;
};

function normalizeConversationId(conversationId: string): string {
  const id = conversationId.trim().toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(id)) throw new Error("invalid qntm conversation id");
  return id;
}

export function resolveQntmStateRoot(options?: { stateDir?: string }): string {
  return path.join(options?.stateDir ?? resolveOpenClawStateDir(process.env), "plugins", "qntm");
}

export function resolveConversationCursorPath(params: {
  accountId: string;
  conversationId: string;
  stateDir?: string;
}): string {
  return path.join(
    resolveQntmStateRoot({ stateDir: params.stateDir }),
    "accounts",
    normalizeAccountId(params.accountId),
    "cursors",
    `${normalizeConversationId(params.conversationId)}.json`,
  );
}

export function readConversationCursor(params: {
  accountId: string;
  conversationId: string;
  stateDir?: string;
}): number {
  const cursorPath = resolveConversationCursorPath(params);
  let raw: Buffer;
  try { raw = readBoundedFile(cursorPath, 4096); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw error;
  }
  try {
    const parsed: unknown = JSON.parse(raw.toString("utf8"));
    const sequence = typeof parsed === "number" ? parsed : (parsed as { seq?: unknown } | null)?.seq;
    if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) throw new Error();
    return sequence;
  } catch { throw new Error("invalid qntm legacy cursor file"); }
}

export function writeConversationCursor(params: {
  accountId: string;
  conversationId: string;
  sequence: number;
  stateDir?: string;
  updatedAt?: number;
}): void {
  const cursorPath = resolveConversationCursorPath(params);
  if (!Number.isSafeInteger(params.sequence) || params.sequence < 0) throw new Error("invalid qntm cursor sequence");
  writePrivateJSON(cursorPath, { seq: params.sequence, updatedAt: params.updatedAt ?? Date.now() }, 4096);
}

export function createFileCursorStore(options?: {
  stateDir?: string;
  now?: () => number;
}): ConversationCursorStore {
  return {
    getCursor: async ({ accountId, conversationId }) =>
      readConversationCursor({
        accountId,
        conversationId,
        stateDir: options?.stateDir,
      }),
    setCursor: async ({ accountId, conversationId, sequence }) => {
      writeConversationCursor({
        accountId,
        conversationId,
        sequence,
        stateDir: options?.stateDir,
        updatedAt: options?.now?.(),
      });
    },
  };
}
