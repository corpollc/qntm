import type { ChannelPlugin } from "openclaw/plugin-sdk/core";
import { defineChannelPluginEntry } from "openclaw/plugin-sdk/core";
import { qntmPlugin } from "./src/channel.js";
import { setQntmRuntime } from "./src/runtime.js";

export { qntmPlugin } from "./src/channel.js";
export { setQntmRuntime } from "./src/runtime.js";

export default defineChannelPluginEntry({
  id: "qntm",
  name: "qntm",
  description: "qntm channel plugin",
  plugin: qntmPlugin as ChannelPlugin,
  setRuntime: setQntmRuntime,
});
