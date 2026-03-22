import path from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { normalizeAccountId } from "openclaw/plugin-sdk";

function resolveOpenClawStateDir(env: NodeJS.ProcessEnv): string {
  return env.OPENCLAW_STATE_DIR || path.join(process.cwd(), ".openclaw", "state");
}

export type ConversationCursorStore = {
  getCursor: (params: { accountId: string; conversationId: string }) => Promise<number>;
  setCursor: (params: { accountId: string; conversationId: string; sequence: number }) => Promise<void>;
};

function normalizeConversationId(conversationId: string): string {
  return conversationId.trim().toLowerCase();
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
  if (!existsSync(cursorPath)) {
    return 0;
  }
  try {
    const parsed = JSON.parse(readFileSync(cursorPath, "utf-8")) as {
      seq?: unknown;
    } | number;
    if (typeof parsed === "number" && Number.isFinite(parsed)) {
      return parsed;
    }
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof parsed.seq === "number" &&
      Number.isFinite(parsed.seq)
    ) {
      return parsed.seq;
    }
  } catch {
    return 0;
  }
  return 0;
}

export function writeConversationCursor(params: {
  accountId: string;
  conversationId: string;
  sequence: number;
  stateDir?: string;
  updatedAt?: number;
}): void {
  const cursorPath = resolveConversationCursorPath(params);
  mkdirSync(path.dirname(cursorPath), { recursive: true });
  writeFileSync(
    cursorPath,
    `${JSON.stringify(
      {
        seq: params.sequence,
        updatedAt: params.updatedAt ?? Date.now(),
      },
      null,
      2,
    )}\n`,
  );
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
