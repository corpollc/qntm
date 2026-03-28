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
        find: "openclaw/plugin-sdk",
        replacement: path.resolve(__dirname, "./sdk-shims/index.ts"),
      },
    ],
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
