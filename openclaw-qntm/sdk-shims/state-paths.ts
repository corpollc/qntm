import os from "node:os";
import path from "node:path";

export function resolveStateDir(env: NodeJS.ProcessEnv): string {
  return env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw", "state");
}
