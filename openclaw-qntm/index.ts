import { QntmGroupActions, createQntmGroupTool } from "./src/group-tool.js";
import type { ChannelPlugin, OpenClawPluginApi } from "openclaw/plugin-sdk/channel-core";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk/plugin-entry";
import { qntmPlugin } from "./src/channel.js";
import { setQntmRuntime } from "./src/runtime.js";
import { QntmGatewayActions } from "./src/gateway-actions.js";
import { createQntmGatewayTool } from "./src/gateway-tool.js";

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
    const groupActions = new QntmGroupActions();
    api.registerTool(ctx => createQntmGroupTool(ctx, api.config, groupActions), { name: 'qntm_group', optional: true });
    const gatewayActions = new QntmGatewayActions();
    api.registerTool(ctx => createQntmGatewayTool(ctx, api.config, gatewayActions), { name: 'qntm_gateway', optional: true });
  },
};

export default plugin;
