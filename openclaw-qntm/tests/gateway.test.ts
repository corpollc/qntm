import { afterEach, describe, expect, test, vi } from "vitest";
import { resolveQntmAccount } from "../src/accounts.js";
import { qntmPlugin } from "../src/channel.js";
import { monitorQntmAccount } from "../src/monitor.js";
import { __testing, setQntmRuntime } from "../src/runtime.js";
import { createConfig, createConversationFixture, createIdentityFixture } from "./helpers.js";

vi.mock("../src/monitor.js", () => ({
  monitorQntmAccount: vi.fn(),
}));

afterEach(() => {
  vi.clearAllMocks();
  __testing.reset();
});

describe("qntm gateway lifecycle", () => {
  test("uses the registered plugin runtime when startAccount omits channelRuntime and stays alive until abort", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        alice: {
          invite: direct.token,
        },
      },
    });
    const account = resolveQntmAccount({ cfg });
    const channelRuntime = {
      routing: {},
      session: {},
      reply: {},
    } as never;
    const stop = vi.fn();
    const setStatus = vi.fn();
    const abortController = new AbortController();

    vi.mocked(monitorQntmAccount).mockImplementation(async ({ statusSink }) => ({
      stop: () => {
        stop();
        statusSink?.({
          running: false,
          lastStopAt: Date.now(),
        });
      },
    }));
    setQntmRuntime({
      channel: channelRuntime,
    } as never);

    const task = qntmPlugin.gateway?.startAccount?.({
      cfg,
      accountId: account.accountId,
      account,
      runtime: {} as never,
      abortSignal: abortController.signal,
      getStatus: () => ({ accountId: account.accountId }),
      setStatus,
      log: {
        info: vi.fn(),
        error: vi.fn(),
      },
    } as never);

    expect(task).toBeTruthy();

    const settled = vi.fn();
    void task?.then(settled);
    await Promise.resolve();
    await Promise.resolve();

    expect(monitorQntmAccount).toHaveBeenCalledWith(
      expect.objectContaining({
        account,
        cfg,
        channelRuntime,
        abortSignal: abortController.signal,
      }),
    );
    expect(settled).not.toHaveBeenCalled();

    abortController.abort();
    await task;

    expect(stop).toHaveBeenCalledTimes(1);
    expect(settled).toHaveBeenCalledTimes(1);
    expect(setStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: account.accountId,
        running: false,
      }),
    );
  });

  test("fails clearly when neither the start context nor the registered runtime exposes channelRuntime", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        alice: {
          invite: direct.token,
        },
      },
    });
    const account = resolveQntmAccount({ cfg });

    await expect(
      qntmPlugin.gateway?.startAccount?.({
        cfg,
        accountId: account.accountId,
        account,
        runtime: {} as never,
        abortSignal: new AbortController().signal,
        getStatus: () => ({ accountId: account.accountId }),
        setStatus: vi.fn(),
        log: {
          info: vi.fn(),
          error: vi.fn(),
        },
      } as never),
    ).rejects.toThrow(/channel runtime is unavailable/i);

    expect(monitorQntmAccount).not.toHaveBeenCalled();
  });
});
