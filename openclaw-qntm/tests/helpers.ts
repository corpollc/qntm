import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  identityDir?: string;
  relayUrl?: string;
  defaultTo?: string;
  sessionDmScope?: "main" | "per-peer" | "per-channel-peer" | "per-account-channel-peer";
  conversations?: Record<
    string,
    { invite?: string; convId?: string; name?: string; enabled?: boolean }
  >;
}): QntmRootConfig {
  const cfg: QntmRootConfig = {
    channels: {
      qntm: {
        relayUrl: params.relayUrl ?? "https://relay.example.test",
        identity: params.identity,
        identityDir: params.identityDir,
        defaultTo: params.defaultTo,
        conversations: params.conversations,
      },
    },
  };
  if (params.sessionDmScope) {
    cfg.session = {
      dmScope: params.sessionDmScope,
    };
  }
  return cfg;
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
  const dir = mkdtempSync(join(tmpdir(), "openclaw-qntm-"));
  writeFileSync(
    join(dir, "identity.json"),
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
    join(dir, "conversations.json"),
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
        invite_token: conversation.token,
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
