import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import {
  createFileCursorStore,
  readConversationCursor,
  resolveConversationCursorPath,
} from "../src/state.js";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("cursor state", () => {
  test("persists cursors per account and conversation", async () => {
    const stateDir = mkdtempSync(path.join(os.tmpdir(), "openclaw-qntm-state-"));
    tempDirs.push(stateDir);
    const store = createFileCursorStore({ stateDir, now: () => 1234 });

    await store.setCursor({
      accountId: "default",
      conversationId: "abcd1234",
      sequence: 9,
    });

    expect(
      readConversationCursor({
        accountId: "default",
        conversationId: "abcd1234",
        stateDir,
      }),
    ).toBe(9);
    expect(
      resolveConversationCursorPath({
        accountId: "default",
        conversationId: "abcd1234",
        stateDir,
      }),
    ).toContain(path.join("accounts", "default", "cursors", "abcd1234.json"));
  });
});
