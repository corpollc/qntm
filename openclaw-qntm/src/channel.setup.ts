import type { ChannelPlugin } from "openclaw/plugin-sdk/core";
import { createQntmPluginBase } from "./shared.js";
import { qntmSetupAdapter } from "./setup-core.js";
import type { ResolvedQntmAccount } from "./types.js";

export const qntmSetupPlugin: ChannelPlugin<ResolvedQntmAccount> = {
  ...createQntmPluginBase({ setup: qntmSetupAdapter }),
};
