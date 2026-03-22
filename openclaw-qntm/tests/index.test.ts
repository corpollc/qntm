import { describe, expect, test, vi } from "vitest";
import plugin from "../index.ts";

describe("qntm plugin registration", () => {
  test("logs registration and registers the qntm channel", () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const registerChannel = vi.fn();

    plugin.register({
      runtime: {
        channel: {} as never,
      },
      registerChannel,
    });

    expect(info).toHaveBeenCalledWith("qntm: registered (relay websocket monitor)");
    expect(registerChannel).toHaveBeenCalledWith({
      plugin: expect.objectContaining({ id: "qntm" }),
    });
  });
});
