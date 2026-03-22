import { describe, expect, test } from "vitest";
import { resolveQntmAccount, resolveQntmBinding } from "../src/accounts.js";
import {
  createConfig,
  createConversationFixture,
  createIdentityDirFixture,
  createIdentityFixture,
} from "./helpers.js";

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

  test("loads identity and conversations from qntm identityDir config", () => {
    const storedIdentity = createIdentityFixture();
    const direct = { ...createConversationFixture("direct"), name: "Peter" };
    const group = { ...createConversationFixture("group"), name: "Ops Room" };
    const fixture = createIdentityDirFixture({
      identity: storedIdentity.identity,
      conversations: [direct, group],
    });

    try {
      const cfg = createConfig({
        identityDir: fixture.dir,
        defaultTo: "ops",
        conversations: {
          peter: {
            convId: direct.conversationId,
          },
          ops: {
            convId: group.conversationId,
          },
        },
      });

      const account = resolveQntmAccount({ cfg });

      expect(account.configured).toBe(true);
      expect(account.identitySource).toBe("identityDir");
      expect(account.defaultTo).toBe("ops");
      expect(account.bindings.map((binding) => binding.key)).toEqual(["ops", "peter"]);
      expect(resolveQntmBinding(account, "peter")?.conversationId).toBe(direct.conversationId);
      expect(resolveQntmBinding(account, group.conversationId)?.label).toBe("Ops Room");
      expect(account.configErrors).toEqual([]);
    } finally {
      fixture.cleanup();
    }
  });

  test("requires identityDir for convId conversation bindings", () => {
    const identity = createIdentityFixture();
    const direct = createConversationFixture("direct");
    const cfg = createConfig({
      identity: identity.serialized,
      conversations: {
        peter: {
          convId: direct.conversationId,
        },
      },
    });

    const account = resolveQntmAccount({ cfg });

    expect(account.configured).toBe(false);
    expect(account.bindings).toEqual([]);
    expect(account.configErrors).toContain(
      'qntm conversation "peter" uses convId but no identityDir is configured',
    );
  });
});
