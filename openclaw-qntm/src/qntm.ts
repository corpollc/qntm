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
  validateIdentity,
} from "@corpollc/qntm";
import { readBoundedFile } from "./storage.js";
import { join } from "node:path";
import type { Conversation, DropboxClient, Identity } from "@corpollc/qntm";

export type QntmClientLike = Pick<DropboxClient, "postMessage" | "subscribeMessages">;

type IdentityResolution =
  | { identity: Identity; source: "config" | "identityFile" | "identityDir" }
  | { identity: undefined; source: "none" };

type StoredConversationRecord = {
  id: unknown;
  name?: unknown;
  type?: unknown;
  keys?: Record<string, unknown>;
  participants?: unknown;
  created_at?: unknown;
  createdAt?: unknown;
  current_epoch?: unknown;
  currentEpoch?: unknown;
  invite_token?: unknown;
  inviteToken?: unknown;
};

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
  if (Array.isArray(value) && value.every((entry) => typeof entry === "number" && Number.isInteger(entry) && entry >= 0 && entry <= 255)) {
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
  let value: Record<string, unknown>;
  try { value = JSON.parse(raw); } catch { throw new Error("invalid qntm identity JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid qntm identity object");
  return checkedIdentity({
    privateKey: decodeIdentityBytes(value.private_key ?? value.privateKey, "private_key"),
    publicKey: decodeIdentityBytes(value.public_key ?? value.publicKey, "public_key"),
    keyID: decodeIdentityBytes(value.key_id ?? value.keyID ?? value.kid, "key_id"),
  });
}

function checkedIdentity(identity: Identity): Identity {
  validateIdentity(identity);
  return identity;
}

export function loadQntmIdentityFromString(raw: string): Identity {
  const trimmed = raw.trim();
  if (Buffer.byteLength(trimmed) > 65536) throw new Error("qntm identity exceeds its size limit");
  if (!trimmed) {
    throw new Error("empty qntm identity");
  }
  if (trimmed.startsWith("{")) {
    return parseIdentityJsonText(trimmed);
  }
  try {
    return checkedIdentity(deserializeIdentity(base64UrlDecode(trimmed)));
  } catch {
    if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
      return checkedIdentity(deserializeIdentity(fromHex(trimmed)));
    }
  }
  throw new Error("invalid qntm identity payload");
}

export function loadQntmIdentityFromFile(identityFile: string): Identity {
  const raw = readBoundedFile(identityFile, 65536);
  try {
    return checkedIdentity(deserializeIdentity(new Uint8Array(raw)));
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
  identityDir?: string;
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
  if (params.identityDir?.trim()) {
    return {
      identity: loadQntmIdentityFromFile(join(params.identityDir, "identity.json")),
      source: "identityDir",
    };
  }
  return { identity: undefined, source: "none" };
}

export function resolveInviteConversation(invite: string): Conversation {
  const invitePayload = inviteFromURL(invite);
  const keys = deriveConversationKeys(invitePayload);
  return createConversation(invitePayload, keys);
}

function parseStoredConversationType(value: unknown): Conversation["type"] {
  if (value === "direct" || value === "group" || value === "announce") {
    return value;
  }
  throw new Error("invalid qntm conversation type");
}

function parseStoredConversationEpoch(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error("invalid qntm conversation epoch");
  }
  return value;
}

function parseStoredConversationDate(value: unknown): Date {
  if (value instanceof Date && !Number.isNaN(value.valueOf())) {
    return value;
  }
  if (typeof value === "string" || typeof value === "number") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.valueOf())) {
      return parsed;
    }
  }
  return new Date(0);
}

function loadStoredConversationRecords(identityDir: string): StoredConversationRecord[] {
  let raw: unknown;
  try { raw = JSON.parse(readBoundedFile(join(identityDir, "conversations.json"), 16 * 1024 * 1024).toString("utf8")); }
  catch { throw new Error("invalid qntm conversations file"); }
  if (!Array.isArray(raw)) {
    throw new Error(`invalid qntm conversations file: ${join(identityDir, "conversations.json")}`);
  }
  return raw as StoredConversationRecord[];
}

export function parseStoredConversationRecord(record: StoredConversationRecord): Conversation {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("invalid qntm conversation record");
  if (!record.keys || typeof record.keys !== "object") {
    throw new Error("missing qntm conversation keys");
  }
  if (record.participants !== undefined && !Array.isArray(record.participants)) throw new Error("invalid qntm conversation participants");
  const participants = Array.isArray(record.participants)
    ? record.participants.map((entry, index) => decodeIdentityBytes(entry, `participant ${index}`))
    : [];
  const name = typeof record.name === "string" ? record.name.trim() : "";
  const inviteToken =
    typeof record.invite_token === "string"
      ? record.invite_token.trim()
      : typeof record.inviteToken === "string"
        ? record.inviteToken.trim()
        : "";
  const conversation: Conversation = {
    id: decodeIdentityBytes(record.id, "conversation id"),
    name: name || undefined,
    type: parseStoredConversationType(record.type ?? "direct"),
    keys: {
      root: decodeIdentityBytes(record.keys.root, "conversation key root"),
      aeadKey: decodeIdentityBytes(
        record.keys.aeadKey ?? record.keys.aead_key,
        "conversation key aead_key",
      ),
      nonceKey: decodeIdentityBytes(
        record.keys.nonceKey ?? record.keys.nonce_key,
        "conversation key nonce_key",
      ),
    },
    participants,
    createdAt: parseStoredConversationDate(record.createdAt ?? record.created_at),
    currentEpoch: parseStoredConversationEpoch(record.currentEpoch ?? record.current_epoch),
    inviteToken: inviteToken || undefined,
  };
  if (conversation.id.length !== 16 || Object.values(conversation.keys).some(key => key.length !== 32)
    || conversation.participants.length > 1000 || conversation.participants.some(key => key.length !== 16)
    || new Set(conversation.participants.map(toHex)).size !== conversation.participants.length) {
    throw new Error("invalid qntm conversation keys or participants");
  }
  return conversation;
}

export function loadQntmConversationFromDir(identityDir: string, convId: string): Conversation {
  const normalizedConvId = toHex(decodeIdentityBytes(convId, "conversation id"));
  const record = loadStoredConversationRecords(identityDir).find((entry) => {
    try {
      return toHex(decodeIdentityBytes(entry.id, "conversation id")) === normalizedConvId;
    } catch {
      return false;
    }
  });
  if (!record) {
    throw new Error(
      `qntm conversation ${normalizedConvId} not found in ${join(identityDir, "conversations.json")}`,
    );
  }
  return parseStoredConversationRecord(record);
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
