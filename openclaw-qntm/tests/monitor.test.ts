import {
  createMessage,
  defaultTTL,
  generateIdentity,
  keyIDFromPublicKey,
  serializeEnvelope,
} from "@corpollc/qntm";
import { afterEach, describe, expect, test, vi } from "vitest";
import { resolveQntmAccount } from "../src/accounts.js";
import { monitorQntmAccount } from "../src/monitor.js";
import { toHex } from "../src/qntm.js";
import type { QntmRootConfig } from "../src/types.js";
import {
  createConfig,
  createConversationFixture,
  createIdentityDirFixture,
  createIdentityFixture,
} from "./helpers.js";

function resolveMockRoute(params: {
  cfg: QntmRootConfig;
  accountId?: string | null;
  peer?: { kind?: string; id?: string };
}) {
  const agentId = "main";
  const accountId = params.accountId ?? "default";
  const mainSessionKey = "agent:main:main";
  const peerKind = params.peer?.kind ?? "direct";
  const peerId = params.peer?.id ?? "peer";
  let sessionKey = mainSessionKey;

  if (peerKind !== "direct") {
    sessionKey = `agent:${agentId}:qntm:${peerKind}:${peerId}`;
  } else {
    switch (params.cfg.session?.dmScope ?? "main") {
      case "main":
        sessionKey = mainSessionKey;
        break;
      case "per-peer":
        sessionKey = `agent:${agentId}:direct:${peerId}`;
        break;
      case "per-channel-peer":
        sessionKey = `agent:${agentId}:qntm:direct:${peerId}`;
        break;
      case "per-account-channel-peer":
        sessionKey = `agent:${agentId}:qntm:${accountId}:direct:${peerId}`;
        break;
    }
  }

  return {
    agentId,
    channel: "qntm",
    accountId,
    sessionKey,
    mainSessionKey,
    lastRoutePolicy: sessionKey === mainSessionKey ? "main" : "session",
    matchedBy: "default",
  };
}

function createChannelRuntimeMock() {
  const recordInboundSession = vi.fn(
    async (_params: {
      sessionKey: string;
      ctx?: Record<string, unknown>;
      updateLastRoute?: Record<string, unknown>;
    }) => undefined,
  );
  const dispatchReplyWithBufferedBlockDispatcher = vi.fn(async ({ dispatcherOptions }) => {
    await dispatcherOptions.deliver({ text: "auto reply" });
    return {};
  });
  return {
    runtime: {
      routing: {
        resolveAgentRoute: vi.fn((params) => resolveMockRoute(params as Parameters<typeof resolveMockRoute>[0])),
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
    expect(firstSessionKey).toBe("agent:main:main");
    expect(secondSessionKey).toBe(`agent:main:qntm:group:${group.conversationId}`);

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

  test("skips self-authored messages when stored identity key_id is stale but the public key matches", async () => {
    const identity = generateIdentity();
    const direct = createConversationFixture("direct");
    const staleStoredKeyId = keyIDFromPublicKey(generateIdentity().publicKey);
    const identityDir = createIdentityDirFixture({
      identity,
      storedKeyId: staleStoredKeyId,
      conversations: [direct],
    });
    const cfg = createConfig({
      identityDir: identityDir.dir,
      conversations: {
        alice: {
          convId: direct.conversationId,
        },
      },
    });
    const account = resolveQntmAccount({ cfg });
    const runtime = createChannelRuntimeMock();
    const clientMock = createClientMock();
    const cursors = new Map<string, number>();

    try {
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
          {
            ...identity,
            keyID: keyIDFromPublicKey(identity.publicKey),
          },
          direct.conversation,
          "text",
          new TextEncoder().encode("self message"),
          undefined,
          defaultTTL(),
        ),
      );

      await clientMock.emit(direct.conversationId, 6, envelope);

      expect(runtime.recordInboundSession).not.toHaveBeenCalled();
      expect(runtime.dispatchReplyWithBufferedBlockDispatcher).not.toHaveBeenCalled();
      expect(cursors.get(direct.conversationId)).toBe(6);

      monitor.stop();
    } finally {
      identityDir.cleanup();
    }
  });

  test("uses dmScope-shaped direct session keys from resolveAgentRoute", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const cfg = createConfig({
      identity: identity.serialized,
      sessionDmScope: "per-account-channel-peer",
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

    await monitorQntmAccount({
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

    const sender = generateIdentity();
    const envelope = serializeEnvelope(
      createMessage(
        sender,
        direct.conversation,
        "text",
        new TextEncoder().encode("hello scoped direct"),
        undefined,
        defaultTTL(),
      ),
    );

    await clientMock.emit(direct.conversationId, 9, envelope);

    const call = runtime.recordInboundSession.mock.calls[0]?.[0];
    expect(call?.sessionKey).toBe(`agent:main:qntm:default:direct:${direct.conversationId}`);
    expect(call?.ctx?.SessionKey).toBe(`agent:main:qntm:default:direct:${direct.conversationId}`);
    expect(call?.updateLastRoute).toEqual({
      sessionKey: `agent:main:qntm:default:direct:${direct.conversationId}`,
      channel: "qntm",
      to: `qntm:${direct.conversationId}`,
      accountId: "default",
    });
  });
});
