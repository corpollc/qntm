import {
  QSP1Suite,
  applyAuthenticatedGroupControl,
  applyRekey,
  base64UrlDecode,
  base64UrlEncode,
  createMessage,
  defaultTTL,
  decryptMessage,
  deserializeEnvelope,
  deserializeIdentity,
  keyIDFromPublicKey,
  parseGroupAddBody,
  parseGroupGenesisBody,
  parseGroupRekeyBody,
  parseGroupRemoveBody,
  serializeEnvelope,
  validateIdentity,
} from "@corpollc/qntm";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Conversation, DropboxClient, GroupControlState, Identity, Message, OuterEnvelope } from "@corpollc/qntm";

export type QntmClientLike = Pick<DropboxClient, "postMessage" | "subscribeMessages">;

export class QntmInboundRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QntmInboundRejectedError";
  }
}

type IdentityResolution =
  | { identity: Identity; source: "identityDir" }
  | { identity: undefined; source: "none" };

type StoredGatewayRecord = {
  status?: unknown;
  keyId?: unknown;
  key_id?: unknown;
  kid?: unknown;
  publicKey?: unknown;
  public_key?: unknown;
  membershipAuthority?: unknown;
  membership_authority?: unknown;
};

type StoredConversationRecord = {
  id: unknown;
  name?: unknown;
  type?: unknown;
  keys?: Record<string, unknown>;
  participants?: unknown;
  participantPublicKeys?: unknown;
  participant_public_keys?: unknown;
  created_at?: unknown;
  createdAt?: unknown;
  current_epoch?: unknown;
  currentEpoch?: unknown;
  excluded?: unknown;
  removed?: unknown;
  needs_rekey?: unknown;
  needsRekey?: unknown;
  pending_control?: unknown;
  recovery_required?: unknown;
  recoveryRequired?: unknown;
  groupControl?: GroupControlState;
  group_control?: {
    creator?: string;
    roster?: string;
    needs_rekey?: boolean;
    needsRekey?: boolean;
    removed?: boolean;
  };
  gateway?: StoredGatewayRecord | null;
};

export type LoadedConversationState = {
  conversation: Conversation;
  excluded: boolean;
  needsRekey: boolean;
  recoveryRequired: boolean;
  groupControl?: GroupControlState;
  knownPublicKeys: Record<string, string>;
  delegatedGatewayPublicKey?: Uint8Array;
};

const suite = new QSP1Suite();
const GROUP_CONTROL_TYPES = new Set(["group_genesis", "group_add", "group_remove", "group_rekey"]);

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

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
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
  if (/^[0-9a-f]+$/i.test(trimmed) && (trimmed.length === 32 || trimmed.length === 64)) {
    return fromHex(trimmed);
  }
  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length !== 22 && trimmed.length !== 44) {
    return fromHex(trimmed);
  }
  return base64UrlDecode(trimmed);
}

export function loadQntmIdentityFromFile(identityFile: string): Identity {
  const raw = readFileSync(identityFile);
  let identity: Identity | undefined;
  try {
    identity = deserializeIdentity(new Uint8Array(raw));
  } catch {
    const text = raw.toString("utf-8").trim();
    if (!text) {
      throw new Error(`empty qntm identity file: ${identityFile}`);
    }
    identity = text.startsWith("{")
      ? parseIdentityJsonText(text)
      : deserializeIdentity(base64UrlDecode(text));
  }
  validateIdentity(identity);
  return identity;
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

function parseStoredConversationState(record: StoredConversationRecord): LoadedConversationState {
  if (!record.keys || typeof record.keys !== "object") {
    throw new Error("missing qntm conversation keys");
  }
  const rawParticipants = Array.isArray(record.participants)
    ? record.participants.map((entry, index) => decodeIdentityBytes(entry, `participant ${index}`))
    : [];
  const knownPublicKeys: Record<string, string> = {};
  const normalizedParticipants = rawParticipants.map((bytes) => {
    if (bytes.length === 32) {
      const kid = keyIDFromPublicKey(bytes);
      knownPublicKeys[base64UrlEncode(kid)] = base64UrlEncode(bytes);
      return kid;
    }
    return bytes;
  });
  const extraPks = record.participantPublicKeys ?? record.participant_public_keys;
  if (Array.isArray(extraPks)) {
    for (const entry of extraPks) {
      const pkBytes = decodeIdentityBytes(entry, "participant public key");
      if (pkBytes.length === 32) {
        knownPublicKeys[base64UrlEncode(keyIDFromPublicKey(pkBytes))] = base64UrlEncode(pkBytes);
      }
    }
  }

  const name = typeof record.name === "string" ? record.name.trim() : "";
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
    participants: normalizedParticipants,
    createdAt: parseStoredConversationDate(record.createdAt ?? record.created_at),
    currentEpoch: parseStoredConversationEpoch(record.currentEpoch ?? record.current_epoch),
  };

  const rawGc = record.groupControl ?? record.group_control;
  const defaultCreator =
    conversation.type === "group" && normalizedParticipants[0]
      ? base64UrlEncode(normalizedParticipants[0])
      : undefined;
  const groupControl: GroupControlState | undefined = rawGc?.creator
    ? {
        creator: rawGc.creator,
        ...(rawGc.roster ? { roster: rawGc.roster } : {}),
        needsRekey: Boolean(rawGc.needsRekey ?? (rawGc as { needs_rekey?: boolean }).needs_rekey),
        removed: Boolean(rawGc.removed),
      }
    : defaultCreator
      ? { creator: defaultCreator, needsRekey: false, removed: false }
      : undefined;

  const excluded = Boolean(record.excluded || record.removed || groupControl?.removed);
  const needsRekey = Boolean(
    record.needs_rekey || record.needsRekey || record.pending_control || groupControl?.needsRekey,
  );
  const recoveryRequired = Boolean(record.recovery_required || record.recoveryRequired);

  let delegatedGatewayPublicKey: Uint8Array | undefined;
  const gw = record.gateway;
  if (gw && gw.status === "active") {
    const rawPk = gw.publicKey ?? gw.public_key;
    const authority = gw.membershipAuthority ?? gw.membership_authority ?? true;
    if (rawPk && authority) {
      delegatedGatewayPublicKey = decodeIdentityBytes(rawPk, "gateway public key");
    }
  }

  return {
    conversation,
    excluded,
    needsRekey,
    recoveryRequired,
    groupControl,
    knownPublicKeys,
    delegatedGatewayPublicKey,
  };
}

export function loadQntmConversationStateFromDir(
  identityDir: string,
  convId: string,
): LoadedConversationState {
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
  return parseStoredConversationState(record);
}

export function loadQntmConversationFromDir(identityDir: string, convId: string): Conversation {
  return loadQntmConversationStateFromDir(identityDir, convId).conversation;
}

export function persistConversationStateToDir(
  identityDir: string,
  convId: string,
  nextState: LoadedConversationState,
): void {
  const filePath = join(identityDir, "conversations.json");
  const normalizedConvId = toHex(decodeIdentityBytes(convId, "conversation id"));
  const records = loadStoredConversationRecords(identityDir);
  const updated = records.map((entry) => {
    let matches = false;
    try {
      matches = toHex(decodeIdentityBytes(entry.id, "conversation id")) === normalizedConvId;
    } catch {
      matches = false;
    }
    if (!matches) {
      return entry;
    }
    const useCamelKeys = Boolean(entry.keys && "aeadKey" in entry.keys);
    const nextKeys = useCamelKeys
      ? {
          root: toHex(nextState.conversation.keys.root),
          aeadKey: toHex(nextState.conversation.keys.aeadKey),
          nonceKey: toHex(nextState.conversation.keys.nonceKey),
        }
      : {
          root: toHex(nextState.conversation.keys.root),
          aead_key: toHex(nextState.conversation.keys.aeadKey),
          nonce_key: toHex(nextState.conversation.keys.nonceKey),
        };
    return {
      ...entry,
      keys: nextKeys,
      participants: nextState.conversation.participants.map((p) => toHex(p)),
      current_epoch: nextState.conversation.currentEpoch,
      ...("currentEpoch" in entry ? { currentEpoch: nextState.conversation.currentEpoch } : {}),
      excluded: nextState.excluded,
      needs_rekey: nextState.needsRekey,
      recovery_required: nextState.recoveryRequired,
      ...(nextState.groupControl ? { groupControl: nextState.groupControl } : {}),
    };
  });
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmpPath, `${JSON.stringify(updated, null, 2)}\n`, "utf-8");
  renameSync(tmpPath, filePath);
}

export function applyInboundGroupControl(params: {
  envelope: OuterEnvelope;
  message: Message;
  identity: Identity;
  state: LoadedConversationState;
}): LoadedConversationState {
  const { envelope, message, identity, state } = params;
  const bodyType = message.inner.body_type;
  if (!GROUP_CONTROL_TYPES.has(bodyType)) {
    return state;
  }

  const senderKidB64 = base64UrlEncode(message.inner.sender_kid);
  const senderPkB64 = base64UrlEncode(message.inner.sender_ik_pk);
  const knownPublicKeys = { ...state.knownPublicKeys, [senderKidB64]: senderPkB64 };

  // Full roster-tracked control path when genesis is present or arriving
  if (bodyType === "group_genesis" || state.groupControl?.roster || state.delegatedGatewayPublicKey) {
    try {
      const control = state.groupControl ?? {
        creator: senderKidB64,
        needsRekey: false,
        removed: false,
      };
      const applied = applyAuthenticatedGroupControl(
        envelope,
        message,
        state.conversation,
        identity,
        control,
        knownPublicKeys,
        state.delegatedGatewayPublicKey,
      );
      return {
        ...state,
        conversation: applied.conversation,
        groupControl: applied.state,
        knownPublicKeys: applied.participants,
        excluded: applied.state.removed,
        needsRekey: applied.state.needsRekey,
      };
    } catch (error) {
      throw new QntmInboundRejectedError(
        `invalid group control ${bodyType}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // Pre-genesis group_rekey fallback for pre-existing group fixtures in conversations.json
  if (bodyType === "group_rekey" && state.conversation.type === "group") {
    const senderAdmitted =
      state.conversation.participants.length === 0 ||
      state.conversation.participants.some(
        (member) =>
          uint8ArrayEquals(member, message.inner.sender_kid) ||
          uint8ArrayEquals(member, message.inner.sender_ik_pk),
      );
    if (!senderAdmitted) {
      throw new QntmInboundRejectedError("unauthorized group_rekey sender");
    }
    let parsed: ReturnType<typeof parseGroupRekeyBody> & { group_epoch?: number };
    try {
      parsed = parseGroupRekeyBody(new Uint8Array(message.inner.body)) as ReturnType<
        typeof parseGroupRekeyBody
      > & { group_epoch?: number };
    } catch (error) {
      throw new QntmInboundRejectedError(
        `malformed group_rekey: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (
      parsed.new_conv_epoch !== state.conversation.currentEpoch + 1 ||
      (parsed.group_epoch !== undefined && parsed.group_epoch !== state.conversation.currentEpoch) ||
      !parsed.wrapped_keys
    ) {
      throw new QntmInboundRejectedError("group_rekey epoch or wrapped_keys invalid");
    }
    const myKidB64 = base64UrlEncode(identity.keyID);
    const wrapped = parsed.wrapped_keys[myKidB64];
    if (!wrapped) {
      return {
        ...state,
        excluded: true,
        needsRekey: false,
      };
    }
    let root: Uint8Array;
    try {
      root = suite.unwrapKeyForRecipient(
        wrapped,
        identity.privateKey,
        identity.keyID,
        state.conversation.id,
      );
    } catch {
      return {
        ...state,
        recoveryRequired: true,
      };
    }
    if (root.length !== 32) {
      return {
        ...state,
        recoveryRequired: true,
      };
    }
    const nextConversation: Conversation = {
      ...state.conversation,
      keys: { ...state.conversation.keys },
      participants: Object.keys(parsed.wrapped_keys).map((kid) => base64UrlDecode(kid)),
    };
    applyRekey(nextConversation, root, state.conversation.currentEpoch + 1);
    return {
      ...state,
      conversation: nextConversation,
      knownPublicKeys,
      excluded: false,
      needsRekey: false,
    };
  }

  throw new QntmInboundRejectedError(`unexpected group control ${bodyType} before group_genesis`);
}

export function decodeQntmBody(bodyType: string, body: Uint8Array): {
  rawBody: string;
  bodyForAgent: string;
} {
  if (GROUP_CONTROL_TYPES.has(bodyType)) {
    try {
      const parsed =
        bodyType === "group_genesis"
          ? parseGroupGenesisBody(body)
          : bodyType === "group_add"
            ? parseGroupAddBody(body)
            : bodyType === "group_remove"
              ? parseGroupRemoveBody(body)
              : parseGroupRekeyBody(body);
      const serialized = JSON.stringify(parsed, (_key, value) =>
        value instanceof Uint8Array ? base64UrlEncode(value) : value,
      );
      return { rawBody: serialized, bodyForAgent: `[${bodyType}] ${serialized}` };
    } catch {
      // Fall through to generic text/byte formatting
    }
  }
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
  let envelope: OuterEnvelope;
  try {
    envelope = deserializeEnvelope(params.envelopeBytes);
  } catch (error) {
    throw new QntmInboundRejectedError(
      `malformed envelope: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (envelope.conv_epoch !== params.conversation.currentEpoch) {
    throw new QntmInboundRejectedError(
      `stale or mismatched conv_epoch: expected ${params.conversation.currentEpoch}, got ${envelope.conv_epoch}`,
    );
  }
  let decrypted: Message;
  try {
    decrypted = decryptMessage(envelope, params.conversation);
  } catch (error) {
    throw new QntmInboundRejectedError(
      `decryption failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (
    !decrypted.verified ||
    toHex(keyIDFromPublicKey(decrypted.inner.sender_ik_pk)) !== toHex(decrypted.inner.sender_kid)
  ) {
    throw new QntmInboundRejectedError("unverified message signature or sender_kid mismatch");
  }
  return decrypted;
}
