import { describe, expect, test } from "vitest";
import { qntmPlugin } from "../src/channel.js";
import { createConfig, createConversationFixture, createIdentityFixture } from "./helpers.js";

describe("qntmPlugin directory and resolver", () => {
  test("lists peers and groups separately for configured bindings", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        alice: {
          invite: direct.token,
          name: "Alice",
        },
        ops: {
          invite: group.token,
          name: "Ops Room",
        },
      },
    });

    const peers = await qntmPlugin.directory?.listPeers?.({ cfg });
    const groups = await qntmPlugin.directory?.listGroups?.({ cfg });

    expect(peers).toEqual([
      expect.objectContaining({
        kind: "user",
        id: direct.conversationId,
        name: "Alice",
        handle: "alice",
      }),
    ]);
    expect(groups).toEqual([
      expect.objectContaining({
        kind: "group",
        id: group.conversationId,
        name: "Ops Room",
        handle: "ops",
      }),
    ]);
  });

  test("resolves configured targets and respects preferred target kinds", async () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        alice: {
          invite: direct.token,
          name: "Alice",
        },
        ops: {
          invite: group.token,
          name: "Ops Room",
        },
      },
    });

    const resolved = await qntmPlugin.resolver?.resolveTargets?.({
      cfg,
      inputs: ["alice", "ops", "missing"],
      kind: "user",
    });
    const directTarget = await qntmPlugin.messaging?.targetResolver?.resolveTarget?.({
      cfg,
      normalized: "alice",
      preferredKind: "user",
    });
    const wrongKind = await qntmPlugin.messaging?.targetResolver?.resolveTarget?.({
      cfg,
      normalized: "ops",
      preferredKind: "user",
    });

    expect(resolved).toEqual([
      expect.objectContaining({
        input: "alice",
        resolved: true,
        id: direct.conversationId,
        name: "Alice",
      }),
      expect.objectContaining({
        input: "ops",
        resolved: false,
        note: "qntm target is configured as a group conversation",
      }),
      expect.objectContaining({
        input: "missing",
        resolved: false,
        note: "unknown qntm conversation",
      }),
    ]);
    expect(directTarget).toEqual({
      to: direct.conversationId,
      kind: "user",
      display: "Alice",
      source: "directory",
    });
    expect(wrongKind).toBeNull();
  });
});
