import { writeFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";
import {
  QSP1Suite,
  applyRekey,
  createGroupRekeyBody,
  createMessage,
  decryptMessage,
  defaultTTL,
  deserializeEnvelope,
  generateIdentity,
  serializeEnvelope,
} from "@corpollc/qntm";
import { createQntmChannelFactory } from "../src/channels/qntm.js";
import { loadQntmIdentityFromFile, toHex } from "../src/qntm.js";
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

  test("does not advance persisted cursor when onMessage handler throws", async () => {
    const conversation = createConversationFixture("group");
    const identityDir = createIdentityDirFixture({
      conversations: [{ ...conversation, name: "Ops Room" }],
    });
    const stateDir = createStateDirFixture();
    const mock = createMockClient();

    let failNext = true;
    const delivered: NewMessage[] = [];
    const opts = {
      onMessage: (_jid: string, message: NewMessage) => {
        if (failNext) {
          throw new Error("transient sqlite busy");
        }
        delivered.push(message);
      },
      onChatMetadata: () => undefined,
      registeredGroups: () => ({
        [`qntm:${conversation.conversationId}`]: {
          name: "Ops Room",
          folder: "qntm_ops",
          trigger: "@Andy",
          added_at: new Date().toISOString(),
        },
      }),
    };

    const channel = createQntmChannelFactory({
      env: { QNTM_IDENTITY_DIR: identityDir.dir },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
      log: { info: () => undefined, warn: () => undefined, error: () => undefined },
    })(opts)!;

    await channel.connect();

    const sender = generateIdentity();
    const inbound = createEnvelopeFixture({
      sender,
      conversation: conversation.conversation,
      text: "must not be lost",
    });

    await mock.emit(conversation.conversationId, {
      seq: 11,
      envelope: inbound.serialized,
    });

    expect(delivered).toHaveLength(0);
    expect(
      readConversationCursor({
        conversationId: conversation.conversationId,
        stateDir: stateDir.dir,
      }),
    ).toBe(0);

    failNext = false;
    await mock.emit(conversation.conversationId, {
      seq: 11,
      envelope: inbound.serialized,
    });

    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.content).toBe("must not be lost");
    expect(
      readConversationCursor({
        conversationId: conversation.conversationId,
        stateDir: stateDir.dir,
      }),
    ).toBe(11);

    identityDir.cleanup();
    stateDir.cleanup();
  });

  test("validates loaded identities and rejects tampered key_id or keypair", () => {
    const valid = generateIdentity();
    const other = generateIdentity();
    const identityDir = createIdentityDirFixture({ identity: valid });
    try {
      const idPath = path.join(identityDir.dir, "identity.json");
      writeFileSync(
        idPath,
        JSON.stringify({
          private_key: toHex(valid.privateKey),
          public_key: toHex(valid.publicKey),
          key_id: toHex(other.keyID),
        }),
        "utf-8",
      );
      expect(() => loadQntmIdentityFromFile(idPath)).toThrow();
    } finally {
      identityDir.cleanup();
    }
  });

  test("rejects stale conv_epoch envelopes and applies inbound group_rekey rotations", async () => {
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

    const channel = createQntmChannelFactory({
      env: { QNTM_IDENTITY_DIR: identityDir.dir },
      stateDir: stateDir.dir,
      createClient: () => mock.client,
      log: { info: () => undefined, warn: () => undefined, error: () => undefined },
    })(opts)!;
    await channel.connect();

    // Wrong epoch (epoch 2 while conversation is at epoch 0) is rejected
    const wrongEpochConv = { ...conversation.conversation, currentEpoch: 2 };
    const staleOrFuture = createEnvelopeFixture({
      sender: conversation.inviter,
      conversation: wrongEpochConv,
      text: "wrong epoch",
    });
    await mock.emit(conversation.conversationId, {
      seq: 1,
      envelope: staleOrFuture.serialized,
    });
    expect(messages).toHaveLength(0);

    // Valid group_rekey from group inviter rotates epoch 0 -> 1
    const newRoot = new QSP1Suite().generateGroupKey();
    const rekeyBody = createGroupRekeyBody(
      newRoot,
      1,
      [
        { kid: conversation.inviter.keyID, publicKey: conversation.inviter.publicKey },
        { kid: identityDir.identity.keyID, publicKey: identityDir.identity.publicKey },
      ],
      conversation.conversation.id,
    );
    const rekeyEnvelope = serializeEnvelope(
      createMessage(
        conversation.inviter,
        conversation.conversation,
        "group_rekey",
        rekeyBody,
        undefined,
        defaultTTL(),
      ),
    );
    await mock.emit(conversation.conversationId, {
      seq: 2,
      envelope: rekeyEnvelope,
    });

    // Old epoch-0 message replayed after rotation is rejected
    const staleReplay = createEnvelopeFixture({
      sender: conversation.inviter,
      conversation: conversation.conversation,
      text: "stale epoch 0 replay",
    });
    await mock.emit(conversation.conversationId, {
      seq: 3,
      envelope: staleReplay.serialized,
    });
    expect(messages.some((m) => m.message.content === "stale epoch 0 replay")).toBe(false);

    // Epoch-1 message under rotated keys is decrypted and delivered
    const epoch1Conv = {
      ...conversation.conversation,
      keys: { ...conversation.conversation.keys },
    };
    applyRekey(epoch1Conv, newRoot, 1);
    const epoch1Inbound = createEnvelopeFixture({
      sender: conversation.inviter,
      conversation: epoch1Conv,
      text: "hello on epoch 1",
    });
    await mock.emit(conversation.conversationId, {
      seq: 4,
      envelope: epoch1Inbound.serialized,
    });
    expect(messages.at(-1)?.message.content).toBe("hello on epoch 1");

    // Outbound sendMessage encrypts under epoch 1
    await channel.sendMessage(`qntm:${conversation.conversationId}`, "ack epoch 1");
    expect(mock.postMessageCalls).toHaveLength(1);
    const sentEnv = deserializeEnvelope(mock.postMessageCalls[0]!.envelope);
    expect(sentEnv.conv_epoch).toBe(1);
    expect(new TextDecoder().decode(decryptMessage(sentEnv, epoch1Conv).inner.body)).toBe(
      "ack epoch 1",
    );

    identityDir.cleanup();
    stateDir.cleanup();
  });
});
