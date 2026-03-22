import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { qntmSetupAdapter } from "../src/setup-core.js";
import type { QntmRootConfig } from "../src/types.js";
import { createConversationFixture, createIdentityFixture } from "./helpers.js";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("qntmSetupAdapter", () => {
  test("writes account config with relay url, identity, and first conversation", () => {
    const identity = createIdentityFixture();
    const group = createConversationFixture("group");
    const cfg = qntmSetupAdapter.applyAccountConfig({
      cfg: {} as QntmRootConfig,
      accountId: "default",
      input: {
        name: "Operations",
        url: "https://relay.example.test",
        privateKey: identity.serialized,
        token: group.token,
      },
    }) as QntmRootConfig;

    const account = cfg.channels?.qntm?.accounts?.default;

    expect(account?.relayUrl).toBe("https://relay.example.test");
    expect(account?.identity).toBe(identity.serialized);
    expect(account?.conversations?.operations?.invite).toBe(group.token);
    expect(account?.defaultTo).toBe("operations");
  });

  test("stores existing file paths as identityFile entries", () => {
    const identity = createIdentityFixture();
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "openclaw-qntm-setup-"));
    tempDirs.push(tmpDir);
    const identityPath = path.join(tmpDir, "identity.txt");
    writeFileSync(identityPath, identity.serialized);

    const cfg = qntmSetupAdapter.applyAccountConfig({
      cfg: {} as QntmRootConfig,
      accountId: "default",
      input: {
        privateKey: identityPath,
      },
    }) as QntmRootConfig;

    expect(cfg.channels?.qntm?.accounts?.default?.identityFile).toBe(identityPath);
    expect(cfg.channels?.qntm?.accounts?.default?.identity).toBeUndefined();
  });

  test("rejects invalid invites and identity payloads during setup validation", () => {
    expect(
      qntmSetupAdapter.validateInput({
        input: {
          token: "not-a-real-invite",
        },
      }),
    ).toContain("invalid qntm invite");

    expect(
      qntmSetupAdapter.validateInput({
        input: {
          privateKey: "not-a-real-identity",
        },
      }),
    ).toContain("invalid qntm identity");
  });
});
