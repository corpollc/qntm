import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

export type ConversationCursorStore = {
  getCursor: (params: { conversationId: string }) => Promise<number>;
  setCursor: (params: { conversationId: string; sequence: number }) => Promise<void>;
};

function normalizeConversationId(conversationId: string): string {
  return conversationId.trim().toLowerCase();
}

export function resolveStateRoot(options?: { stateDir?: string }): string {
  return path.join(options?.stateDir ?? path.join(process.cwd(), "store", "qntm"));
}

export function resolveConversationCursorPath(params: {
  conversationId: string;
  stateDir?: string;
}): string {
  return path.join(
    resolveStateRoot({ stateDir: params.stateDir }),
    "cursors",
    `${normalizeConversationId(params.conversationId)}.json`,
  );
}

export function readConversationCursor(params: {
  conversationId: string;
  stateDir?: string;
}): number {
  const cursorPath = resolveConversationCursorPath(params);
  if (!existsSync(cursorPath)) {
    return 0;
  }
  try {
    const parsed = JSON.parse(readFileSync(cursorPath, "utf-8")) as { seq?: unknown } | number;
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
    getCursor: async ({ conversationId }) =>
      readConversationCursor({
        conversationId,
        stateDir: options?.stateDir,
      }),
    setCursor: async ({ conversationId, sequence }) => {
      writeConversationCursor({
        conversationId,
        sequence,
        stateDir: options?.stateDir,
        updatedAt: options?.now?.(),
      });
    },
  };
}
