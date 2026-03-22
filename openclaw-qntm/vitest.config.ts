import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@corpollc/qntm",
        replacement: path.resolve(__dirname, "../client/src/index.ts"),
      },
      {
        find: "openclaw/plugin-sdk/core",
        replacement: path.resolve(__dirname, "./sdk-shims/core.ts"),
      },
      {
        find: "openclaw/plugin-sdk/account-helpers",
        replacement: path.resolve(__dirname, "./sdk-shims/account-helpers.ts"),
      },
      {
        find: "openclaw/plugin-sdk/account-id",
        replacement: path.resolve(__dirname, "./sdk-shims/account-id.ts"),
      },
      {
        find: "openclaw/plugin-sdk/channel-config-helpers",
        replacement: path.resolve(__dirname, "./sdk-shims/channel-config-helpers.ts"),
      },
      {
        find: "openclaw/plugin-sdk/channel-send-result",
        replacement: path.resolve(__dirname, "./sdk-shims/channel-send-result.ts"),
      },
      {
        find: "openclaw/plugin-sdk/channel-reply-pipeline",
        replacement: path.resolve(__dirname, "./sdk-shims/channel-reply-pipeline.ts"),
      },
      {
        find: "openclaw/plugin-sdk/reply-payload",
        replacement: path.resolve(__dirname, "./sdk-shims/reply-payload.ts"),
      },
      {
        find: "openclaw/plugin-sdk/extension-shared",
        replacement: path.resolve(__dirname, "./sdk-shims/extension-shared.ts"),
      },
      {
        find: "openclaw/plugin-sdk/state-paths",
        replacement: path.resolve(__dirname, "./sdk-shims/state-paths.ts"),
      },
    ],
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
