import { describe, expect, test } from "vitest";
import { resolveQntmAccount, resolveQntmBinding } from "../src/accounts.js";
import { createConfig, createConversationFixture, createIdentityFixture } from "./helpers.js";

describe("resolveQntmAccount", () => {
  test("parses identity and multiple conversation bindings", () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const group = createConversationFixture("group");
    const cfg = createConfig({
      identity: identity.serialized,
      defaultTo: "team-room",
      conversations: {
        alice: {
          invite: direct.token,
          name: "Alice",
        },
        "team-room": {
          invite: group.token,
          name: "Team Room",
        },
      },
    });

    const account = resolveQntmAccount({ cfg });

    expect(account.configured).toBe(true);
    expect(account.identitySource).toBe("config");
    expect(account.defaultTo).toBe("team-room");
    expect(account.bindings.map((binding) => binding.key)).toEqual(["alice", "team-room"]);
    expect(resolveQntmBinding(account, "qntm:alice")?.conversationId).toBe(direct.conversationId);
    expect(resolveQntmBinding(account, group.conversationId)?.target).toBe("team-room");
  });

  test("reports invalid invite configuration errors", () => {
    const identity = createIdentityFixture();
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        broken: {
          invite: "not-a-real-invite",
        },
      },
    });

    const account = resolveQntmAccount({ cfg });

    expect(account.configured).toBe(false);
    expect(account.configErrors[0]).toContain("invalid qntm invite");
    expect(account.bindings).toHaveLength(0);
  });
});
