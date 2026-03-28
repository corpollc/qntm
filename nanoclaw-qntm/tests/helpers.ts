import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  createConversation,
  createInvite,
  deriveConversationKeys,
  generateIdentity,
  serializeEnvelope,
  createMessage,
  defaultTTL,
} from "@corpollc/qntm";
import type {
  Conversation,
  DropboxSubscription,
  DropboxSubscriptionHandlers,
  Identity,
  SubscriptionMessage,
} from "@corpollc/qntm";
import { toHex } from "../src/qntm.js";

export function createConversationFixture(type: "direct" | "group" = "direct") {
  const inviter = generateIdentity();
  const invite = createInvite(inviter, type);
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  return {
    inviter,
    invite,
    conversation,
    conversationId: toHex(conversation.id),
  };
}

export function createIdentityDirFixture(params?: {
  identity?: Identity;
  conversations?: Array<
    ReturnType<typeof createConversationFixture> & {
      name?: string;
    }
  >;
}) {
  const identity = params?.identity ?? generateIdentity();
  const dir = mkdtempSync(path.join(tmpdir(), "nanoclaw-qntm-"));
  writeFileSync(
    path.join(dir, "identity.json"),
    JSON.stringify(
      {
        private_key: toHex(identity.privateKey),
        public_key: toHex(identity.publicKey),
        key_id: toHex(identity.keyID),
      },
      null,
      2,
    ) + "\n",
    "utf-8",
  );
  writeFileSync(
    path.join(dir, "conversations.json"),
    JSON.stringify(
      (params?.conversations ?? []).map((conversation) => ({
        id: conversation.conversationId,
        name: conversation.name,
        type: conversation.conversation.type,
        keys: {
          root: toHex(conversation.conversation.keys.root),
          aead_key: toHex(conversation.conversation.keys.aeadKey),
          nonce_key: toHex(conversation.conversation.keys.nonceKey),
        },
        participants: conversation.conversation.participants.map((participant) => toHex(participant)),
        created_at: conversation.conversation.createdAt.toISOString(),
        current_epoch: conversation.conversation.currentEpoch,
      })),
      null,
      2,
    ) + "\n",
    "utf-8",
  );
  return {
    dir,
    identity,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export function createStateDirFixture() {
  const dir = mkdtempSync(path.join(tmpdir(), "nanoclaw-qntm-state-"));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export function createEnvelopeFixture(params: {
  sender: Identity;
  conversation: Conversation;
  text: string;
  bodyType?: string;
}) {
  const envelope = createMessage(
    params.sender,
    params.conversation,
    params.bodyType ?? "text",
    new TextEncoder().encode(params.text),
    undefined,
    defaultTTL(),
  );
  return {
    envelope,
    serialized: serializeEnvelope(envelope),
    messageId: toHex(envelope.msg_id),
  };
}

export function createMockClient() {
  const subscriptions = new Map<string, DropboxSubscriptionHandlers>();
  const postMessageCalls: Array<{ conversationId: Uint8Array; envelope: Uint8Array }> = [];
  const subscribeCalls: Array<{ conversationId: string; fromSequence: number }> = [];

  const client = {
    postMessage: async (conversationId: Uint8Array, envelope: Uint8Array) => {
      postMessageCalls.push({ conversationId, envelope });
      return 1;
    },
    subscribeMessages: (
      conversationId: Uint8Array,
      fromSequence: number,
      handlers: DropboxSubscriptionHandlers,
    ): DropboxSubscription => {
      const conversationKey = toHex(conversationId);
      subscriptions.set(conversationKey, handlers);
      subscribeCalls.push({
        conversationId: conversationKey,
        fromSequence,
      });
      return {
        close: () => undefined,
        closed: Promise.resolve(),
      };
    },
  };

  return {
    client,
    postMessageCalls,
    subscribeCalls,
    async emit(conversationId: string, message: SubscriptionMessage) {
      const handlers = subscriptions.get(conversationId);
      if (!handlers) {
        throw new Error(`no subscription for ${conversationId}`);
      }
      await handlers.onMessage(message);
    },
    subscriptionCount() {
      return subscriptions.size;
    },
  };
}
