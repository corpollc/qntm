import {
  base64UrlDecode,
  createMessage,
  defaultTTL,
  decryptMessage,
  deserializeEnvelope,
  deserializeIdentity,
  serializeEnvelope,
} from "@corpollc/qntm";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Conversation, DropboxClient, Identity } from "@corpollc/qntm";

export type QntmClientLike = Pick<DropboxClient, "postMessage" | "subscribeMessages">;

type IdentityResolution =
  | { identity: Identity; source: "identityDir" }
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
};

function parseIdentityJsonText(raw: string): Identity {
  const value = JSON.parse(raw) as Record<string, unknown>;
  return {
    privateKey: decodeIdentityBytes(value.private_key ?? value.privateKey, "private_key"),
    publicKey: decodeIdentityBytes(value.public_key ?? value.publicKey, "public_key"),
    keyID: decodeIdentityBytes(value.key_id ?? value.keyID ?? value.kid, "key_id"),
  };
}

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
    return deserializeIdentity(base64UrlDecode(text));
  }
}

export function resolveQntmIdentity(params: { identityDir?: string }): IdentityResolution {
  if (params.identityDir?.trim()) {
    return {
      identity: loadQntmIdentityFromFile(join(params.identityDir, "identity.json")),
      source: "identityDir",
    };
  }
  return { identity: undefined, source: "none" };
}

function parseStoredConversationType(value: unknown): Conversation["type"] {
  if (value === "direct" || value === "group" || value === "announce") {
    return value;
  }
  throw new Error(`invalid qntm conversation type: ${String(value)}`);
}

function parseStoredConversationEpoch(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value));
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) {
      return Math.max(0, parsed);
    }
  }
  return 0;
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
  const raw = JSON.parse(readFileSync(join(identityDir, "conversations.json"), "utf-8")) as unknown;
  if (!Array.isArray(raw)) {
    throw new Error(`invalid qntm conversations file: ${join(identityDir, "conversations.json")}`);
  }
  return raw as StoredConversationRecord[];
}

function parseStoredConversationRecord(record: StoredConversationRecord): Conversation {
  if (!record.keys || typeof record.keys !== "object") {
    throw new Error("missing qntm conversation keys");
  }
  const participants = Array.isArray(record.participants)
    ? record.participants.map((entry, index) => decodeIdentityBytes(entry, `participant ${index}`))
    : [];
  const name = typeof record.name === "string" ? record.name.trim() : "";
  return {
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
  };
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

export function decodeInboundEnvelope(params: {
  identity: Identity;
  conversation: Conversation;
  envelopeBytes: Uint8Array;
}) {
  return decryptMessage(deserializeEnvelope(params.envelopeBytes), params.conversation);
}
