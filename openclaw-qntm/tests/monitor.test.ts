import {
  createMessage,
  defaultTTL,
  generateIdentity,
  serializeEnvelope,
} from "@corpollc/qntm";
import { buildAgentSessionKey } from "openclaw/plugin-sdk/core";
import { afterEach, describe, expect, test, vi } from "vitest";
import { resolveQntmAccount } from "../src/accounts.js";
import { monitorQntmAccount } from "../src/monitor.js";
import { toHex } from "../src/qntm.js";
import type { QntmRootConfig } from "../src/types.js";
import { createConfig, createConversationFixture, createIdentityFixture } from "./helpers.js";

function createChannelRuntimeMock() {
  const recordInboundSession = vi.fn(async (_params: { sessionKey: string }) => undefined);
  const dispatchReplyWithBufferedBlockDispatcher = vi.fn(async ({ dispatcherOptions }) => {
    await dispatcherOptions.deliver({ text: "auto reply" });
    return {};
  });
  return {
    runtime: {
      routing: {
        resolveAgentRoute: vi.fn(({ accountId }) => ({
          agentId: "main",
          channel: "qntm",
          accountId: accountId ?? "default",
          sessionKey: "agent:main:main",
          mainSessionKey: "agent:main:main",
          lastRoutePolicy: "main",
          matchedBy: "default",
        })),
        buildAgentSessionKey,
      },
      session: {
        resolveStorePath: vi.fn(() => "/tmp/openclaw-qntm-session-store.json"),
        readSessionUpdatedAt: vi.fn(() => undefined),
        recordInboundSession,
      },
      reply: {
        resolveEnvelopeFormatOptions: vi.fn(() => ({})),
        formatAgentEnvelope: vi.fn(({ body }) => body),
        finalizeInboundContext: vi.fn((ctx) => ctx),
        dispatchReplyWithBufferedBlockDispatcher,
      },
    },
    recordInboundSession,
    dispatchReplyWithBufferedBlockDispatcher,
  };
}

function createClientMock() {
  const subscriptions = new Map<
    string,
    {
      close: ReturnType<typeof vi.fn>;
      handlers: {
        getCursor?: () => Promise<number> | number;
        onMessage: (message: { seq: number; envelope: Uint8Array }) => Promise<void> | void;
      };
    }
  >();
  const sent: Array<{ conversationId: string; envelope: Uint8Array }> = [];

  const client = {
    subscribeMessages: vi.fn((conversationId, _fromSequence, handlers) => {
      const key = toHex(conversationId);
      const close = vi.fn();
      subscriptions.set(key, { close, handlers });
      return {
        close,
        closed: Promise.resolve(),
      };
    }),
    postMessage: vi.fn(async (conversationId, envelope) => {
      sent.push({
        conversationId: toHex(conversationId),
        envelope,
      });
      return sent.length;
    }),
  };

  return {
    client,
    subscriptions,
    sent,
    async emit(conversationId: string, seq: number, envelope: Uint8Array) {
      const entry = subscriptions.get(conversationId);
      if (!entry) {
        throw new Error(`missing subscription for ${conversationId}`);
      }
      await entry.handlers.onMessage({ seq, envelope });
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("monitorQntmAccount", () => {
  test("tracks multiple subscriptions and replies on the correct bound conversation", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const group = createConversationFixture("group");
    const cfg: QntmRootConfig = createConfig({
      identity: identity.serialized,
      conversations: {
        alice: {
          invite: direct.token,
        },
        ops: {
          invite: group.token,
        },
      },
    });
    const account = resolveQntmAccount({ cfg });
    const runtime = createChannelRuntimeMock();
    const clientMock = createClientMock();
    const cursors = new Map<string, number>();
    const statusPatches: Array<Record<string, unknown>> = [];

    const monitor = await monitorQntmAccount({
      account,
      cfg,
      channelRuntime: runtime.runtime as never,
      abortSignal: new AbortController().signal,
      statusSink: (patch) => {
        statusPatches.push(patch as Record<string, unknown>);
      },
      deps: {
        createClient: () => clientMock.client,
        cursorStore: {
          getCursor: vi.fn(async ({ conversationId }) => cursors.get(conversationId) ?? 0),
          setCursor: vi.fn(async ({ conversationId, sequence }) => {
            cursors.set(conversationId, sequence);
          }),
        },
        now: () => 1_700_000_000_000,
      },
    });

    expect(clientMock.subscriptions.size).toBe(2);

    const directSender = generateIdentity();
    const groupSender = generateIdentity();
    const directEnvelope = serializeEnvelope(
      createMessage(
        directSender,
        direct.conversation,
        "text",
        new TextEncoder().encode("hello from direct"),
        undefined,
        defaultTTL(),
      ),
    );
    const groupEnvelope = serializeEnvelope(
      createMessage(
        groupSender,
        group.conversation,
        "text",
        new TextEncoder().encode("hello from group"),
        undefined,
        defaultTTL(),
      ),
    );

    await clientMock.emit(direct.conversationId, 7, directEnvelope);
    await clientMock.emit(group.conversationId, 11, groupEnvelope);

    expect(runtime.recordInboundSession).toHaveBeenCalledTimes(2);
    const firstSessionKey = runtime.recordInboundSession.mock.calls[0]?.[0]?.sessionKey;
    const secondSessionKey = runtime.recordInboundSession.mock.calls[1]?.[0]?.sessionKey;
    expect(firstSessionKey).toContain(direct.conversationId);
    expect(secondSessionKey).toContain(group.conversationId);

    expect(runtime.dispatchReplyWithBufferedBlockDispatcher).toHaveBeenCalledTimes(2);
    expect(clientMock.sent).toHaveLength(2);
    expect(clientMock.sent[0]?.conversationId).toBe(direct.conversationId);
    expect(clientMock.sent[1]?.conversationId).toBe(group.conversationId);
    expect(cursors.get(direct.conversationId)).toBe(7);
    expect(cursors.get(group.conversationId)).toBe(11);

    monitor.stop();

    expect(Array.from(clientMock.subscriptions.values()).every((entry) => entry.close.mock.calls.length === 1)).toBe(
      true,
    );
    expect(statusPatches.at(-1)?.running).toBe(false);
  });

  test("skips self-authored messages while still advancing the cursor", async () => {
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
    const runtime = createChannelRuntimeMock();
    const clientMock = createClientMock();
    const cursors = new Map<string, number>();

    const monitor = await monitorQntmAccount({
      account,
      cfg,
      channelRuntime: runtime.runtime as never,
      abortSignal: new AbortController().signal,
      deps: {
        createClient: () => clientMock.client,
        cursorStore: {
          getCursor: vi.fn(async ({ conversationId }) => cursors.get(conversationId) ?? 0),
          setCursor: vi.fn(async ({ conversationId, sequence }) => {
            cursors.set(conversationId, sequence);
          }),
        },
      },
    });

    const envelope = serializeEnvelope(
      createMessage(
        identity.identity,
        direct.conversation,
        "text",
        new TextEncoder().encode("self message"),
        undefined,
        defaultTTL(),
      ),
    );

    await clientMock.emit(direct.conversationId, 5, envelope);

    expect(runtime.recordInboundSession).not.toHaveBeenCalled();
    expect(runtime.dispatchReplyWithBufferedBlockDispatcher).not.toHaveBeenCalled();
    expect(cursors.get(direct.conversationId)).toBe(5);

    monitor.stop();
  });
});
