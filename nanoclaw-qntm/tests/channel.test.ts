import { describe, expect, test } from "vitest";
import { decryptMessage, deserializeEnvelope, generateIdentity } from "@corpollc/qntm";
import { createQntmChannelFactory } from "../src/channels/qntm.js";
import { readConversationCursor, writeConversationCursor } from "../src/state.js";
import type { NewMessage, RegisteredGroup } from "../src/types.js";
import {
  createConversationFixture,
  createEnvelopeFixture,
  createIdentityDirFixture,
  createMockClient,
  createStateDirFixture,
} from "./helpers.js";

function createOpts(registeredGroups: Record<string, RegisteredGroup>) {
  const messages: Array<{ jid: string; message: NewMessage }> = [];
  const metadata: Array<{
    jid: string;
    timestamp: string;
    name?: string;
    channel?: string;
    isGroup?: boolean;
  }> = [];
  const opts = {
    onMessage: (jid: string, message: NewMessage) => {
      messages.push({ jid, message });
    },
    onChatMetadata: (
      jid: string,
      timestamp: string,
      name?: string,
      channel?: string,
      isGroup?: boolean,
    ) => {
      metadata.push({ jid, timestamp, name, channel, isGroup });
    },
    registeredGroups: () => registeredGroups,
  };
  return {
    opts,
    messages,
    metadata,
  };
}

describe("QntmChannel", () => {
  test("factory returns null when QNTM_IDENTITY_DIR is missing", () => {
    const factory = createQntmChannelFactory({
      env: {},
    });
    const { opts } = createOpts({});
    expect(factory(opts)).toBeNull();
  });

  test("connect subscribes to registered qntm groups and delivers inbound text", async () => {
    const conversation = createConversationFixture("group");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Ops Room" }],
    });
    const stateDir = createStateDirFixture();
    const mock = createMockClient();
    const { opts, messages, metadata } = createOpts({
      [`qntm:${conversation.conversationId}`]: {
        name: "Ops Room",
        folder: "qntm_ops",
        trigger: "@Andy",
        added_at: new Date().toISOString(),
      },
    });

    const factory = createQntmChannelFactory({
      env: {
        QNTM_IDENTITY_DIR: identityDir.dir,
        QNTM_RELAY_URL: "https://relay.example.test",
      },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
    });
    const channel = factory(opts);
    expect(channel).not.toBeNull();

    await channel!.connect();
    expect(mock.subscriptionCount()).toBe(1);

    const sender = generateIdentity();
    const inbound = createEnvelopeFixture({
      sender,
      conversation: conversation.conversation,
      text: "hello from qntm",
    });
    await mock.emit(conversation.conversationId, {
      seq: 7,
      envelope: inbound.serialized,
    });

    expect(messages).toEqual([
      expect.objectContaining({
        jid: `qntm:${conversation.conversationId}`,
        message: expect.objectContaining({
          id: inbound.messageId,
          chat_jid: `qntm:${conversation.conversationId}`,
          content: "hello from qntm",
        }),
      }),
    ]);
    expect(metadata).toEqual([
      expect.objectContaining({
        jid: `qntm:${conversation.conversationId}`,
        name: "Ops Room",
        channel: "qntm",
        isGroup: true,
      }),
    ]);
    expect(
      readConversationCursor({
        conversationId: conversation.conversationId,
        stateDir: stateDir.dir,
      }),
    ).toBe(7);

    identityDir.cleanup();
    stateDir.cleanup();
  });

  test("sendMessage encrypts text to the requested conversation", async () => {
    const conversation = createConversationFixture("direct");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Alice" }],
    });
    const stateDir = createStateDirFixture();
    const mock = createMockClient();
    const { opts } = createOpts({});

    const factory = createQntmChannelFactory({
      env: {
        QNTM_IDENTITY_DIR: identityDir.dir,
        QNTM_RELAY_URL: "https://relay.example.test",
      },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
    });
    const channel = factory(opts);
    expect(channel).not.toBeNull();

    await channel!.sendMessage(`qntm:${conversation.conversationId}`, "ship it");

    expect(mock.postMessageCalls).toHaveLength(1);
    expect(mock.postMessageCalls[0]?.conversationId).toEqual(conversation.conversation.id);
    const envelope = deserializeEnvelope(mock.postMessageCalls[0]!.envelope);
    const decrypted = decryptMessage(envelope, conversation.conversation);
    expect(new TextDecoder().decode(decrypted.inner.body)).toBe("ship it");

    identityDir.cleanup();
    stateDir.cleanup();
  });

  test("connect resumes from the persisted cursor for each conversation", async () => {
    const conversation = createConversationFixture("group");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Ops Room" }],
    });
    const stateDir = createStateDirFixture();
    writeConversationCursor({
      conversationId: conversation.conversationId,
      sequence: 6,
      stateDir: stateDir.dir,
      updatedAt: 1,
    });
    const mock = createMockClient();
    const { opts } = createOpts({
      [`qntm:${conversation.conversationId}`]: {
        name: "Ops Room",
        folder: "qntm_ops",
        trigger: "@Andy",
        added_at: new Date().toISOString(),
      },
    });

    const factory = createQntmChannelFactory({
      env: {
        QNTM_IDENTITY_DIR: identityDir.dir,
      },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
    });
    const channel = factory(opts);
    expect(channel).not.toBeNull();

    await channel!.connect();

    expect(mock.subscribeCalls).toEqual([
      {
        conversationId: conversation.conversationId,
        fromSequence: 6,
      },
    ]);

    identityDir.cleanup();
    stateDir.cleanup();
  });

  test("self-authored qntm messages are ignored", async () => {
    const conversation = createConversationFixture("direct");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Alice" }],
    });
    const stateDir = createStateDirFixture();
    const mock = createMockClient();
    const { opts, messages } = createOpts({
      [`qntm:${conversation.conversationId}`]: {
        name: "Alice",
        folder: "qntm_alice",
        trigger: "@Andy",
        added_at: new Date().toISOString(),
      },
    });

    const factory = createQntmChannelFactory({
      env: {
        QNTM_IDENTITY_DIR: identityDir.dir,
      },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
    });
    const channel = factory(opts);
    expect(channel).not.toBeNull();
    await channel!.connect();

    const selfAuthored = createEnvelopeFixture({
      sender: identityDir.identity,
      conversation: conversation.conversation,
      text: "ignore me",
    });
    await mock.emit(conversation.conversationId, {
      seq: 3,
      envelope: selfAuthored.serialized,
    });

    expect(messages).toEqual([]);
    expect(
      readConversationCursor({
        conversationId: conversation.conversationId,
        stateDir: stateDir.dir,
      }),
    ).toBe(3);

    identityDir.cleanup();
    stateDir.cleanup();
  });

  test("non-text bodies are surfaced with a readable type prefix", async () => {
    const conversation = createConversationFixture("group");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Ops Room" }],
    });
    const stateDir = createStateDirFixture();
    const mock = createMockClient();
    const { opts, messages } = createOpts({
      [`qntm:${conversation.conversationId}`]: {
        name: "Ops Room",
        folder: "qntm_ops",
        trigger: "@Andy",
        added_at: new Date().toISOString(),
      },
    });

    const factory = createQntmChannelFactory({
      env: {
        QNTM_IDENTITY_DIR: identityDir.dir,
      },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
    });
    const channel = factory(opts);
    expect(channel).not.toBeNull();
    await channel!.connect();

    const sender = generateIdentity();
    const inbound = createEnvelopeFixture({
      sender,
      conversation: conversation.conversation,
      text: "{\"request\":\"approve\"}",
      bodyType: "gate.request",
    });
    await mock.emit(conversation.conversationId, {
      seq: 9,
      envelope: inbound.serialized,
    });

    expect(messages[0]?.message.content).toBe('[gate.request] {"request":"approve"}');

    identityDir.cleanup();
    stateDir.cleanup();
  });
});
