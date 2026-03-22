import {
  base64UrlDecode,
  base64UrlEncode,
  createMessage,
  createConversation,
  defaultTTL,
  deriveConversationKeys,
  deserializeIdentity,
  inviteFromURL,
  serializeEnvelope,
} from "@corpollc/qntm";
import { readFileSync } from "node:fs";
import type { Conversation, DropboxClient, Identity } from "@corpollc/qntm";

export type QntmClientLike = Pick<DropboxClient, "postMessage" | "subscribeMessages">;

type IdentityResolution =
  | { identity: Identity; source: "config" | "identityFile" }
  | { identity: undefined; source: "none" };

function fromHex(hex: string): Uint8Array {
  const normalized = hex.trim();
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeIdentityBytes(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === "number")) {
    return Uint8Array.from(value);
  }
  if (typeof value !== "string") {
    throw new Error(`invalid qntm identity ${field}`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`missing qntm identity ${field}`);
  }
  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
    return fromHex(trimmed);
  }
  return base64UrlDecode(trimmed);
}

function parseIdentityJsonText(raw: string): Identity {
  const value = JSON.parse(raw) as Record<string, unknown>;
  return {
    privateKey: decodeIdentityBytes(value.private_key ?? value.privateKey, "private_key"),
    publicKey: decodeIdentityBytes(value.public_key ?? value.publicKey, "public_key"),
    keyID: decodeIdentityBytes(value.key_id ?? value.keyID ?? value.kid, "key_id"),
  };
}

export function loadQntmIdentityFromString(raw: string): Identity {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("empty qntm identity");
  }
  if (trimmed.startsWith("{")) {
    return parseIdentityJsonText(trimmed);
  }
  try {
    return deserializeIdentity(base64UrlDecode(trimmed));
  } catch {
    if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
      return deserializeIdentity(fromHex(trimmed));
    }
  }
  throw new Error("invalid qntm identity payload");
}

export function loadQntmIdentityFromFile(identityFile: string): Identity {
  const raw = readFileSync(identityFile);
  try {
    return deserializeIdentity(new Uint8Array(raw));
  } catch {
    const text = raw.toString("utf-8").trim();
    if (!text) {
      throw new Error(`empty qntm identity file: ${identityFile}`);
    }
    if (text.startsWith("{")) {
      return parseIdentityJsonText(text);
    }
    return loadQntmIdentityFromString(text);
  }
}

export function resolveQntmIdentity(params: {
  identity?: string;
  identityFile?: string;
}): IdentityResolution {
  if (params.identity?.trim()) {
    return {
      identity: loadQntmIdentityFromString(params.identity),
      source: "config",
    };
  }
  if (params.identityFile?.trim()) {
    return {
      identity: loadQntmIdentityFromFile(params.identityFile),
      source: "identityFile",
    };
  }
  return { identity: undefined, source: "none" };
}

export function resolveInviteConversation(invite: string): Conversation {
  const invitePayload = inviteFromURL(invite);
  const keys = deriveConversationKeys(invitePayload);
  return createConversation(invitePayload, keys);
}

export function decodeQntmBody(bodyType: string, body: Uint8Array): {
  rawBody: string;
  bodyForAgent: string;
} {
  const decoded = new TextDecoder().decode(body).trim();
  const rawBody = decoded || `[${body.length} bytes]`;
  if (bodyType === "text") {
    return { rawBody, bodyForAgent: rawBody };
  }
  return {
    rawBody,
    bodyForAgent: `[${bodyType}] ${rawBody}`,
  };
}

export function flattenQntmReplyPayload(payload: {
  text?: string;
  mediaUrls?: string[];
  mediaUrl?: string;
}): string {
  const text = payload.text?.trim() ?? "";
  const urls = payload.mediaUrls?.length
    ? payload.mediaUrls
    : payload.mediaUrl
      ? [payload.mediaUrl]
      : [];
  if (urls.length === 0) {
    return text;
  }
  const attachmentBlock = urls.map((url) => `Attachment: ${url}`).join("\n");
  return text ? `${text}\n\n${attachmentBlock}` : attachmentBlock;
}

export async function sendQntmText(params: {
  client: Pick<DropboxClient, "postMessage">;
  identity: Identity;
  conversation: Conversation;
  text: string;
}): Promise<{
  messageId: string;
  sequence: number;
}> {
  const envelope = createMessage(
    params.identity,
    params.conversation,
    "text",
    new TextEncoder().encode(params.text),
    undefined,
    defaultTTL(),
  );
  const sequence = await params.client.postMessage(
    params.conversation.id,
    serializeEnvelope(envelope),
  );
  return {
    messageId: toHex(envelope.msg_id),
    sequence,
  };
}

export function describeQntmIdentity(identity?: Identity): {
  publicKey?: string | null;
  keyId?: string | null;
} {
  if (!identity) {
    return {
      publicKey: null,
      keyId: null,
    };
  }
  return {
    publicKey: base64UrlEncode(identity.publicKey),
    keyId: toHex(identity.keyID),
  };
}
