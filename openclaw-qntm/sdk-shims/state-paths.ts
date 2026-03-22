import path from "node:path";

export function resolveStateDir(env: NodeJS.ProcessEnv): string {
  return env.OPENCLAW_STATE_DIR || path.join(process.cwd(), ".openclaw", "state");
}
