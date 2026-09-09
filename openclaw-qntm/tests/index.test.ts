import { describe, expect, test, vi } from "vitest";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/channel-core";
import plugin from "../index.ts";

describe("qntm plugin registration", () => {
  test("logs registration and registers the qntm channel", () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const registerChannel = vi.fn();
    const registerTool = vi.fn();

    plugin.register({
      runtime: {
        channel: {} as never,
      },
      registerChannel,
      registerTool,
      config: {},
    } as unknown as OpenClawPluginApi);

    expect(info).toHaveBeenCalledWith("qntm: registered (relay websocket monitor)");
    expect(registerChannel).toHaveBeenCalledWith({
      plugin: expect.objectContaining({ id: "qntm" }),
    });
    expect(registerTool).toHaveBeenCalledWith(expect.any(Function), { name: 'qntm_gateway', optional: true });
    expect(registerTool.mock.calls[0][0]({})).toBeNull();
  });
});
