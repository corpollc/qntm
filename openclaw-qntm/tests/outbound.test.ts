import { Buffer } from "node:buffer";
import { decryptMessage, deserializeEnvelope } from "@corpollc/qntm";
import { afterEach, describe, expect, test, vi } from "vitest";
import { qntmPlugin } from "../src/channel.js";
import { resolveQntmOutboundSessionRoute } from "../src/shared.js";
import { createConfig, createConversationFixture, createIdentityFixture } from "./helpers.js";

const originalFetch = global.fetch;

afterEach(() => {
  vi.restoreAllMocks();
  global.fetch = originalFetch;
});

describe("qntm outbound", () => {
  test("sends encrypted text to the resolved conversation binding", async () => {
    const identity = createIdentityFixture();
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        team: {
          invite: group.token,
          name: "Team",
        },
      },
    });

    let requestBody = "";
    global.fetch = vi.fn(async (_url, init) => {
      requestBody = String(init?.body ?? "");
      return new Response(JSON.stringify({ seq: 42 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const result = await qntmPlugin.outbound?.sendText?.({
      cfg,
      to: "team",
      text: "hello team",
    });

    const payload = JSON.parse(requestBody) as {
      conv_id: string;
      envelope_b64: string;
    };
    const envelope = deserializeEnvelope(
      new Uint8Array(Buffer.from(payload.envelope_b64, "base64")),
    );
    const message = decryptMessage(envelope, group.conversation);

    expect(payload.conv_id).toBe(group.conversationId);
    expect(new TextDecoder().decode(message.inner.body)).toBe("hello team");
    expect(result?.conversationId).toBe(group.conversationId);
  });

  test.each([
    { sessionDmScope: undefined, expected: "agent:main:main" },
    { sessionDmScope: "main" as const, expected: "agent:main:main" },
    { sessionDmScope: "per-peer" as const, expectedPrefix: "agent:main:direct:" },
    { sessionDmScope: "per-channel-peer" as const, expectedPrefix: "agent:main:qntm:direct:" },
    {
      sessionDmScope: "per-account-channel-peer" as const,
      expectedPrefix: "agent:main:qntm:default:direct:",
    },
  ])("routes direct conversations using OpenClaw dmScope semantics", ({ sessionDmScope, expected, expectedPrefix }) => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const cfg = createConfig({
      identity: identity.serialized,
      sessionDmScope,
      conversations: {
        alice: {
          invite: direct.token,
        },
      },
    });

    const route = resolveQntmOutboundSessionRoute({
      cfg,
      agentId: "main",
      accountId: "default",
      target: "alice",
    });

    expect(route?.chatType).toBe("direct");
    if (expected) {
      expect(route?.sessionKey).toBe(expected);
    } else {
      expect(route?.sessionKey).toBe(`${expectedPrefix}${direct.conversationId}`);
    }
    expect(route?.to).toBe(`qntm:${direct.conversationId}`);
  });

  test("routes group conversations to channel-scoped session keys regardless of dmScope", () => {
    const identity = createIdentityFixture();
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      sessionDmScope: "per-account-channel-peer",
      conversations: {
        team: {
          invite: group.token,
        },
      },
    });

    const route = resolveQntmOutboundSessionRoute({
      cfg,
      agentId: "main",
      accountId: "default",
      target: "team",
    });

    expect(route?.chatType).toBe("group");
    expect(route?.sessionKey).toBe(`agent:main:qntm:group:${group.conversationId}`);
    expect(route?.to).toBe(`qntm:${group.conversationId}`);
  });

  test("flattens media sends into attachment text for qntm conversations", async () => {
    const identity = createIdentityFixture();
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        ops: {
          invite: group.token,
          name: "Ops",
        },
      },
    });

    let requestBody = "";
    global.fetch = vi.fn(async (_url, init) => {
      requestBody = String(init?.body ?? "");
      return new Response(JSON.stringify({ seq: 43 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    await qntmPlugin.outbound?.sendMedia?.({
      cfg,
      to: "ops",
      text: "see attachment",
      mediaUrl: "https://files.example.test/runbook.pdf",
    });

    const payload = JSON.parse(requestBody) as {
      envelope_b64: string;
    };
    const envelope = deserializeEnvelope(
      new Uint8Array(Buffer.from(payload.envelope_b64, "base64")),
    );
    const message = decryptMessage(envelope, group.conversation);

    expect(new TextDecoder().decode(message.inner.body)).toBe(
      "see attachment\n\nAttachment: https://files.example.test/runbook.pdf",
    );
  });
});
