/**
 * Group conversation management for QSP.
 *
 * Implements group genesis, member add/remove, rekey, and group state tracking.
 * Follows the Go reference implementation and the Python client (group.py).
 */

import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { keyIDFromPublicKey, base64UrlEncode, uint8ArrayEquals } from '../identity/index.js';
import type { Identity, Conversation, KeyID } from '../types.js';

const suite = new QSP1Suite();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GroupMember {
  key_id: Uint8Array;
  public_key: Uint8Array;
  role: 'admin' | 'member';
  added_at: number;
  added_by: Uint8Array;
}

export interface GroupGenesisBody {
  group_name: string;
  description: string;
  created_at: number;
  founding_members: GroupMember[];
}

export interface GroupAddBody {
  added_at: number;
  new_members: GroupMember[];
}

export interface GroupRemoveBody {
  removed_at: number;
  removed_members: Uint8Array[];
  reason: string;
}

export interface GroupRekeyBody {
  new_conv_epoch: number;
  wrapped_keys: Record<string, Uint8Array>;
}

// ---------------------------------------------------------------------------
// Body construction helpers
// ---------------------------------------------------------------------------

/**
 * Create a CBOR-encoded group_genesis body.
 *
 * The creator is always included as the first member with role "admin".
 * Additional foundingMemberKeys are added with role "member".
 */
export function createGroupGenesisBody(
  groupName: string,
  description: string,
  creatorIdentity: Identity,
  foundingMemberKeys: Uint8Array[],
): Uint8Array {
  const now = Math.floor(Date.now() / 1000);
  const creatorKid = keyIDFromPublicKey(creatorIdentity.publicKey);

  const members: Record<string, unknown>[] = [
    {
      key_id: creatorKid,
      public_key: creatorIdentity.publicKey,
      role: 'admin',
      added_at: now,
      added_by: creatorKid,
    },
  ];

  for (const pk of foundingMemberKeys) {
    const kid = keyIDFromPublicKey(pk);
    // Skip duplicates (creator passed again, or duplicate keys)
    if (uint8ArrayEquals(kid, creatorKid)) continue;
    if (members.some((m) => uint8ArrayEquals(m.key_id as Uint8Array, kid))) continue;

    members.push({
      key_id: kid,
      public_key: pk,
      role: 'member',
      added_at: now,
      added_by: creatorKid,
    });
  }

  const body = {
    created_at: now,
    description,
    founding_members: members,
    group_name: groupName,
  };
  return marshalCanonical(body);
}

/** Parse a CBOR-encoded group_genesis body. */
export function parseGroupGenesisBody(data: Uint8Array): GroupGenesisBody {
  return unmarshalCanonical<GroupGenesisBody>(data);
}

/**
 * Create a CBOR-encoded group_add body.
 */
export function createGroupAddBody(
  adderIdentity: Identity,
  newMemberKeys: Uint8Array[],
): Uint8Array {
  const now = Math.floor(Date.now() / 1000);
  const adderKid = keyIDFromPublicKey(adderIdentity.publicKey);

  const newMembers: Record<string, unknown>[] = [];
  for (const pk of newMemberKeys) {
    const kid = keyIDFromPublicKey(pk);
    newMembers.push({
      key_id: kid,
      public_key: pk,
      role: 'member',
      added_at: now,
      added_by: adderKid,
    });
  }

  const body = {
    added_at: now,
    new_members: newMembers,
  };
  return marshalCanonical(body);
}

/** Parse a CBOR-encoded group_add body. */
export function parseGroupAddBody(data: Uint8Array): GroupAddBody {
  return unmarshalCanonical<GroupAddBody>(data);
}

/**
 * Create a CBOR-encoded group_remove body.
 */
export function createGroupRemoveBody(
  removedMemberKids: Uint8Array[],
  reason = '',
): Uint8Array {
  const now = Math.floor(Date.now() / 1000);
  const body = {
    reason,
    removed_at: now,
    removed_members: removedMemberKids,
  };
  return marshalCanonical(body);
}

/** Parse a CBOR-encoded group_remove body. */
export function parseGroupRemoveBody(data: Uint8Array): GroupRemoveBody {
  return unmarshalCanonical<GroupRemoveBody>(data);
}

/**
 * Create a CBOR-encoded group_rekey body.
 *
 * Each member gets the newGroupKey wrapped for their public key via ECDH.
 */
export function createGroupRekeyBody(
  newGroupKey: Uint8Array,
  newEpoch: number,
  members: Array<{ kid: Uint8Array; publicKey: Uint8Array }>,
  convID: Uint8Array,
): Uint8Array {
  const wrappedKeys: Record<string, Uint8Array> = {};

  for (const m of members) {
    const kidStr = base64UrlEncode(m.kid);
    const wrapped = suite.wrapKeyForRecipient(newGroupKey, m.publicKey, m.kid, convID);
    wrappedKeys[kidStr] = wrapped;
  }

  const body = {
    new_conv_epoch: newEpoch,
    wrapped_keys: wrappedKeys,
  };
  return marshalCanonical(body);
}

/** Parse a CBOR-encoded group_rekey body. */
export function parseGroupRekeyBody(data: Uint8Array): GroupRekeyBody {
  return unmarshalCanonical<GroupRekeyBody>(data);
}

// ---------------------------------------------------------------------------
// GroupState
// ---------------------------------------------------------------------------

interface MemberInfo {
  keyId: Uint8Array;
  publicKey: Uint8Array;
  role: 'admin' | 'member';
  addedAt: number;
  addedBy: Uint8Array;
}

/**
 * Tracks the current state of a group conversation.
 * Mirrors the Go GroupState struct and the Python GroupState class.
 */
export class GroupState {
  groupName = '';
  description = '';
  createdAt = 0;
  /** members keyed by kid string (base64url) for reliable Map lookup */
  private _members = new Map<string, MemberInfo>();
  private _admins = new Set<string>();
  /** kid of the creator (base64url-encoded) */
  private _creator: string | null = null;

  // --- Internal helpers ---

  private _kidKey(kid: Uint8Array): string {
    return base64UrlEncode(kid);
  }

  // --- Apply operations ---

  applyGenesis(parsed: GroupGenesisBody): void {
    this.groupName = parsed.group_name ?? '';
    this.description = parsed.description ?? '';
    this.createdAt = parsed.created_at ?? 0;

    for (const member of parsed.founding_members ?? []) {
      const kid = new Uint8Array(member.key_id);
      const key = this._kidKey(kid);
      this._members.set(key, {
        keyId: kid,
        publicKey: new Uint8Array(member.public_key),
        role: member.role ?? 'member',
        addedAt: member.added_at ?? 0,
        addedBy: new Uint8Array(member.added_by),
      });
      if (member.role === 'admin') {
        this._admins.add(key);
        if (this._creator === null) {
          this._creator = key;
        }
      }
    }
  }

  applyAdd(parsed: GroupAddBody): void {
    for (const member of parsed.new_members ?? []) {
      const kid = new Uint8Array(member.key_id);
      const key = this._kidKey(kid);
      this._members.set(key, {
        keyId: kid,
        publicKey: new Uint8Array(member.public_key),
        role: member.role ?? 'member',
        addedAt: member.added_at ?? 0,
        addedBy: new Uint8Array(member.added_by),
      });
      if (member.role === 'admin') {
        this._admins.add(key);
      }
    }
  }

  applyRemove(parsed: GroupRemoveBody): void {
    for (const kidRaw of parsed.removed_members ?? []) {
      const kid = new Uint8Array(kidRaw);
      const key = this._kidKey(kid);
      // Don't allow removing the creator
      if (key === this._creator) continue;
      this._members.delete(key);
      this._admins.delete(key);
    }
  }

  // --- Queries ---

  isMember(kid: Uint8Array): boolean {
    return this._members.has(this._kidKey(kid));
  }

  isAdmin(kid: Uint8Array): boolean {
    return this._admins.has(this._kidKey(kid));
  }

  memberCount(): number {
    return this._members.size;
  }

  listMembers(): Uint8Array[] {
    return [...this._members.values()].map((m) => m.keyId);
  }

  listAdmins(): Uint8Array[] {
    return [...this._admins].map((key) => this._members.get(key)!.keyId);
  }

  /** Return member info list suitable for createGroupRekeyBody. */
  membersForRekey(): Array<{ kid: Uint8Array; publicKey: Uint8Array }> {
    return [...this._members.values()].map((m) => ({
      kid: m.keyId,
      publicKey: m.publicKey,
    }));
  }
}

// ---------------------------------------------------------------------------
// High-level operations
// ---------------------------------------------------------------------------

/**
 * Process a group management message and update state.
 * Handles body_types: group_genesis, group_add, group_remove.
 * group_rekey is processed separately. Non-group messages are ignored.
 */
export function processGroupMessage(
  bodyType: string,
  bodyBytes: Uint8Array,
  state: GroupState,
): void {
  switch (bodyType) {
    case 'group_genesis':
      state.applyGenesis(parseGroupGenesisBody(bodyBytes));
      break;
    case 'group_add':
      state.applyAdd(parseGroupAddBody(bodyBytes));
      break;
    case 'group_remove':
      state.applyRemove(parseGroupRemoveBody(bodyBytes));
      break;
    // Other body types (text, group_rekey, etc.) are ignored
  }
}

/**
 * Create a rekey body and return { bodyBytes, newGroupKey }.
 * Wraps a fresh group key for all current members.
 */
export function createRekey(
  _senderIdentity: Identity,
  conversation: Conversation,
  state: GroupState,
): { bodyBytes: Uint8Array; newGroupKey: Uint8Array } {
  const newGroupKey = suite.generateGroupKey();
  const newEpoch = conversation.currentEpoch + 1;
  const members = state.membersForRekey();

  const bodyBytes = createGroupRekeyBody(newGroupKey, newEpoch, members, conversation.id);
  return { bodyBytes, newGroupKey };
}

/**
 * Apply a rekey to a conversation, updating keys and epoch.
 */
export function applyRekey(
  conversation: Conversation,
  newGroupKey: Uint8Array,
  newEpoch: number,
): void {
  const { aeadKey, nonceKey } = suite.deriveEpochKeys(newGroupKey, conversation.id, newEpoch);
  conversation.currentEpoch = newEpoch;
  conversation.keys.root = newGroupKey;
  conversation.keys.aeadKey = aeadKey;
  conversation.keys.nonceKey = nonceKey;
}
