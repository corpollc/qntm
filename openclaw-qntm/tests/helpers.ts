import {
  createConversation,
  createInvite,
  deriveConversationKeys,
  generateIdentity,
  inviteToToken,
  serializeIdentity,
  base64UrlEncode,
} from "@corpollc/qntm";
import type { Identity } from "@corpollc/qntm";
import type { QntmRootConfig } from "../src/types.js";
import { toHex } from "../src/qntm.js";

export function createIdentityFixture(identity: Identity = generateIdentity()) {
  return {
    identity,
    serialized: base64UrlEncode(serializeIdentity(identity)),
  };
}

export function createConversationFixture(type: "direct" | "group" = "direct") {
  const inviter = generateIdentity();
  const invite = createInvite(inviter, type);
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  return {
    inviter,
    invite,
    token: inviteToToken(invite),
    conversation,
    conversationId: toHex(conversation.id),
  };
}

export function createConfig(params: {
  identity?: string;
  relayUrl?: string;
  defaultTo?: string;
  conversations?: Record<string, { invite: string; name?: string; enabled?: boolean }>;
}): QntmRootConfig {
  return {
    channels: {
      qntm: {
        relayUrl: params.relayUrl ?? "https://relay.example.test",
        identity: params.identity,
        defaultTo: params.defaultTo,
        conversations: params.conversations,
      },
    },
  };
}
