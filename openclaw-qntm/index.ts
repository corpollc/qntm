import type { ChannelPlugin, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { qntmPlugin } from "./src/channel.js";
import { setQntmRuntime } from "./src/runtime.js";

export { qntmPlugin } from "./src/channel.js";
export { setQntmRuntime } from "./src/runtime.js";

const plugin = {
  id: "qntm",
  name: "qntm",
  description: "qntm channel plugin",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setQntmRuntime(api.runtime);
    console.info("qntm: registered (relay websocket monitor)");
    api.registerChannel({ plugin: qntmPlugin as ChannelPlugin });
  },
};

export default plugin;
