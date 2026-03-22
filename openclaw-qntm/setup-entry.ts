import { defineSetupPluginEntry } from "openclaw/plugin-sdk/core";
import { qntmSetupPlugin } from "./src/channel.setup.js";

export { qntmSetupPlugin } from "./src/channel.setup.js";

export default defineSetupPluginEntry(qntmSetupPlugin);
