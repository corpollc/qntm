/** Authenticated ordinary-group receive state. Hosts persist this private
 * checkpoint atomically with their relay cursor and dispatch queue. It is local
 * state, never network evidence or a replacement for gateway governance.
 */
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlDecode, base64UrlEncode, uint8ArrayEquals, validateIdentity } from '../identity/index.js';
import { createMessage, decryptMessage, serializeEnvelope } from '../message/index.js';
import { GroupState, applyRekey, createRekey, type GroupGenesisBody } from './index.js';
import { validateGroupSnapshot, prepareGroupAddition, sealGroupWelcome, GROUP_WELCOME_TTL,
  type GroupAddition, type GroupWelcomeEnvelope } from './welcome.js';
import type { Conversation, Identity, Message, OuterEnvelope } from '../types.js';

const suite = new QSP1Suite();
const MAX_EPOCH = 0xffffffff;
const MAX_SEEN = 8192;
export const GROUP_REKEY_GRACE_SECONDS = 86400;
export const MAX_GROUP_REKEY_CHECKPOINTS = 64;
const controls = new Set(['group_genesis', 'group_add', 'group_remove', 'group_rekey']);
const hex = (v: Uint8Array) => Array.from(v, b => b.toString(16).padStart(2, '0')).join('');
const bytes = (v: string) => new Uint8Array(v.match(/../g)!.map(b => parseInt(b, 16)));
const uint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const fixedHex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n * 2 && /^[0-9a-f]+$/.test(v);
function requireValue(v: unknown, reason: string): asserts v { if (!v) throw new Error(reason); }
function fields(v: unknown, names: string): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    && Object.keys(v).sort().join(',') === names.split(',').sort().join(',');
}
function snapshot(encoded: string): GroupGenesisBody {
  requireValue(typeof encoded === 'string' && encoded.length <= 65536, 'Invalid saved group snapshot');
  const wire = base64UrlDecode(encoded), value = unmarshalCanonical<unknown>(wire);
  requireValue(base64UrlEncode(wire) === encoded && uint8ArrayEquals(wire, marshalCanonical(value)), 'Noncanonical saved group snapshot');
  validateGroupSnapshot(value);
  return value;
}
function roster(encoded: string): GroupState {
  const state = new GroupState(); state.applyGenesis(snapshot(encoded)); return state;
}
function encodeRoster(state: GroupState): string {
  const value = state.snapshot(); validateGroupSnapshot(value); return base64UrlEncode(marshalCanonical(value));
}
function validWrapped(value: unknown): boolean {
  if (!(value instanceof Uint8Array) || value.length > 256) return false;
  try {
    const wrapped = unmarshalCanonical<unknown>(value);
    return fields(wrapped, 'ek_pk,nonce,ct') && wrapped.ek_pk instanceof Uint8Array && wrapped.ek_pk.length === 32
      && wrapped.nonce instanceof Uint8Array && wrapped.nonce.length === 24
      && wrapped.ct instanceof Uint8Array && wrapped.ct.length === 48;
  } catch { return false; }
}
interface RekeyCheckpoint {
  epoch: number;
  root: string;
  snapshot: string;
  messageId: string;
  expiresAt: number;
}
export interface GroupSessionState {
  version: 1;
  conversationId: string;
  identityKid: string;
  epoch: number;
  root: string;
  snapshot: string;
  /** Sticky across ordinary replay. Readmission requires a new welcome. */
  removed: boolean;
  needsRekey: boolean;
  /** Set false only when migrating an existing QSP v1.1 local checkpoint. */
  signedEpoch: boolean;
  rekeys: RekeyCheckpoint[];
  seen: Record<string, { digest: string; epoch: number }>;
}
export type GroupEvent = {
  state: GroupSessionState;
  conversation: Conversation;
  group: GroupState;
  /** Hosts replay retained, undecryptable envelopes after a canonical rewind. */
  rewound: boolean;
} & ({ duplicate: true } | { duplicate: false; message: Message });

export interface GroupWelcomeRefresh {
  conversation: Conversation;
  state: GroupState;
  welcomes: GroupWelcomeEnvelope[];
}
export interface GroupSessionRekey {
  conversation: Conversation;
  state: GroupState;
  rekey: OuterEnvelope;
}

/** Use only a trusted local roster or the result of openGroupWelcome. */
export function createGroupSession(identity: Identity, conversation: Conversation, group: GroupState,
  options: { signedEpoch?: boolean } = {}): GroupSessionState {
  validateIdentity(identity);
  requireValue(conversation.type === 'group' && conversation.id.length === 16
    && uint(conversation.currentEpoch) && conversation.currentEpoch <= MAX_EPOCH, 'Invalid group session context');
  const encoded = encodeRoster(group);
  requireValue(group.isMember(identity.keyID), 'Local identity is not a current group member');
  const kids = (values: Uint8Array[]) => values.map(hex).sort().join(',');
  requireValue(kids(conversation.participants) === kids(group.listMembers()), 'Group roster differs from conversation');
  requireValue(conversation.keys.root.length === 32, 'Invalid group root');
  const derived = suite.deriveEpochKeys(conversation.keys.root, conversation.id, conversation.currentEpoch);
  requireValue(uint8ArrayEquals(derived.aeadKey, conversation.keys.aeadKey)
    && uint8ArrayEquals(derived.nonceKey, conversation.keys.nonceKey), 'Group keys differ from epoch');
  return { version: 1, conversationId: hex(conversation.id), identityKid: hex(identity.keyID),
    epoch: conversation.currentEpoch, root: hex(conversation.keys.root), snapshot: encoded,
    removed: false, needsRekey: false, signedEpoch: options.signedEpoch !== false, rekeys: [], seen: {} };
}

/** Validate a private JSON checkpoint after restart, binding it to this identity.
 * Validation does not authenticate a checkpoint obtained from another party.
 */
export function restoreGroupSession(identity: Identity, value: unknown): GroupSessionState {
  validateIdentity(identity);
  requireValue(fields(value, 'version,conversationId,identityKid,epoch,root,snapshot,removed,needsRekey,signedEpoch,rekeys,seen')
    && value.version === 1 && fixedHex(value.conversationId, 16) && value.identityKid === hex(identity.keyID)
    && uint(value.epoch) && value.epoch <= MAX_EPOCH && fixedHex(value.root, 32)
    && typeof value.removed === 'boolean' && typeof value.needsRekey === 'boolean' && typeof value.signedEpoch === 'boolean',
  'Invalid saved group session');
  const group = roster(value.snapshot as string);
  requireValue(value.removed || group.isMember(identity.keyID), 'Saved group omits local identity');
  requireValue(Array.isArray(value.rekeys) && value.rekeys.length <= MAX_GROUP_REKEY_CHECKPOINTS, 'Invalid rekey archive');
  let last = -1;
  for (const frame of value.rekeys) {
    requireValue(fields(frame, 'epoch,root,snapshot,messageId,expiresAt') && uint(frame.epoch)
      && frame.epoch > last && frame.epoch < value.epoch && fixedHex(frame.root, 32)
      && fixedHex(frame.messageId, 16) && uint(frame.expiresAt), 'Invalid rekey checkpoint');
    const prior = snapshot(frame.snapshot as string);
    requireValue(uint8ArrayEquals(prior.founding_members[0].key_id, group.snapshot().founding_members[0].key_id), 'Saved creator changed');
    last = frame.epoch;
  }
  requireValue(value.seen !== null && typeof value.seen === 'object' && !Array.isArray(value.seen)
    && Object.keys(value.seen).length <= MAX_SEEN, 'Invalid group replay checkpoint');
  for (const [id, event] of Object.entries(value.seen)) {
    requireValue(fixedHex(id, 16) && fields(event, 'digest,epoch') && fixedHex(event.digest, 32)
      && uint(event.epoch) && event.epoch <= value.epoch, 'Invalid saved group event');
  }
  return structuredClone(value) as unknown as GroupSessionState;
}

/** Reconstruct keys from a trusted, validated checkpoint. No archived key is
 * exposed through the resulting conversation; old keys are for rekeys only. */
export function groupSessionConversation(state: GroupSessionState): Conversation {
  const group = roster(state.snapshot), id = bytes(state.conversationId), root = bytes(state.root);
  return { id, type: 'group', name: group.groupName, participants: group.listMembers(),
    createdAt: new Date(group.createdAt * 1000), currentEpoch: state.epoch,
    keys: { root, ...suite.deriveEpochKeys(root, id, state.epoch) } };
}

/** Membership changes must finish their rekey before sending application data. */
export function assertGroupCanSend(identity: Identity, state: GroupSessionState): void {
  requireValue(state.identityKid === hex(identity.keyID), 'Group checkpoint belongs to another identity');
  requireValue(!state.removed, 'You have been removed from this group');
  requireValue(!state.needsRekey, 'Group membership update awaits key rotation');
  requireValue(roster(state.snapshot).isMember(identity.keyID), 'Local identity is not a current group member');
}

/** Prepare using the authenticated local checkpoint, including its exclusion
 * and unfinished-rotation guards. Save the exact operation before publishing. */
export function prepareGroupSessionAddition(identity: Identity, state: GroupSessionState,
  recipients: Uint8Array[], ttl?: number): GroupAddition {
  assertGroupCanSend(identity, state);
  return prepareGroupAddition(identity, groupSessionConversation(state), roster(state.snapshot), recipients, ttl);
}

/** Refresh current keys for existing members without admission or rotation.
 * Hosts finish relay replay first, persist the exact operation and recheck it
 * immediately before release. Gateway-governed groups use their own reducer.
 */
export function prepareGroupWelcomeRefresh(identity: Identity, previous: GroupSessionState,
  recipients: Uint8Array[], ttl = GROUP_WELCOME_TTL): GroupWelcomeRefresh {
  const state = restoreGroupSession(identity, previous);
  assertGroupCanSend(identity, state);
  const conversation = groupSessionConversation(state), group = roster(state.snapshot);
  requireValue(uint(ttl) && ttl > 0 && ttl <= GROUP_WELCOME_TTL, 'Invalid welcome lifetime');
  requireValue(Array.isArray(recipients) && recipients.length > 0 && recipients.length <= 128,
    'Invalid refresh recipient count');
  const members = group.snapshot().founding_members;
  const seen = new Set<string>();
  for (const recipient of recipients) {
    requireValue(recipient instanceof Uint8Array && recipient.length === 32
      && members.some(member => uint8ArrayEquals(member.public_key, recipient)), 'Refresh recipient is not a current member');
    requireValue(!seen.has(hex(recipient)), 'Duplicate refresh recipient');
    seen.add(hex(recipient));
  }
  const at = Math.floor(Date.now() / 1000);
  return { conversation, state: group,
    welcomes: recipients.map(recipient => sealGroupWelcome(identity, conversation, group, recipient, at, ttl)) };
}

/** Any remaining ordinary-group member can finish an interrupted rotation.
 * Application traffic stays blocked until this exact control is accepted.
 */
export function prepareGroupSessionRekey(identity: Identity, previous: GroupSessionState, ttl?: number): GroupSessionRekey {
  const state = restoreGroupSession(identity, previous);
  // Rotation itself is allowed while membership awaits its new keys.
  assertGroupCanSend(identity, { ...state, needsRekey: false });
  const conversation = groupSessionConversation(state), group = roster(state.snapshot);
  const rekey = createGroupControlMessage(identity, conversation, 'group_rekey', createRekey(identity, conversation, group).bodyBytes, ttl);
  const received = receiveGroupEvent(identity, rekey, state);
  return { conversation: received.conversation, state: received.group, rekey };
}

/** A refresh must still describe the accepted keys and roster when released. */
export function assertGroupWelcomeRefreshCurrent(identity: Identity, state: GroupSessionState,
  operation: GroupWelcomeRefresh): void {
  assertGroupCanSend(identity, state);
  requireValue(state.conversationId === hex(operation.conversation.id) && state.epoch === operation.conversation.currentEpoch
    && state.root === hex(operation.conversation.keys.root) && state.snapshot === encodeRoster(operation.state),
  'Prepared welcome refresh differs from accepted group state');
  const at = Math.floor(Date.now() / 1000);
  requireValue(operation.welcomes.length > 0 && operation.welcomes.every(welcome => welcome.created_ts <= at + 600
    && welcome.expiry_ts >= at), 'Prepared welcome refresh expired');
}

/** Before publishing welcomes, require the exact prepared add/rekey to have
 * passed receive verification and still describe the current accepted state.
 * A relay POST acknowledgement alone does not establish that fact. */
export function assertGroupAdditionAccepted(identity: Identity, state: GroupSessionState, operation: GroupAddition): void {
  assertGroupCanSend(identity, state);
  requireValue(state.conversationId === hex(operation.conversation.id) && state.epoch === operation.conversation.currentEpoch
    && state.root === hex(operation.conversation.keys.root) && state.snapshot === encodeRoster(operation.state),
  'Prepared addition differs from accepted group state');
  for (const envelope of [operation.addition, operation.rekey]) {
    requireValue(state.seen[hex(envelope.msg_id)]?.digest === hex(suite.hash(serializeEnvelope(envelope))),
      'Prepared addition and rekey have not both been accepted');
  }
}

/** Bind a control to its source epoch inside the signed body. QSP v1.1's
 * signature does not itself cover the outer conv_epoch field. */
export function createGroupControlMessage(identity: Identity, conversation: Conversation, type: string,
  body: Uint8Array, ttl?: number): OuterEnvelope {
  requireValue(controls.has(type), 'Not a group control');
  const value = unmarshalCanonical<Record<string, unknown>>(body);
  requireValue(value && typeof value === 'object' && !Array.isArray(value), 'Invalid group control body');
  return createMessage(identity, conversation, type, marshalCanonical({ ...value, group_epoch: conversation.currentEpoch }), undefined, ttl);
}

/** Receive in relay order. Invalid events never mutate the input. Retained old
 * roots can authenticate only lower-ID competing rekeys, never application
 * traffic. A rewind invalidates descendants; hosts retry pending ciphertext.
 * This reducer is for ordinary groups; accepted gateways use their governance.
 */
export function receiveGroupEvent(identity: Identity, envelope: OuterEnvelope, previous: GroupSessionState): GroupEvent {
  validateIdentity(identity);
  requireValue(previous.identityKid === hex(identity.keyID), 'Group checkpoint belongs to another identity');
  requireValue(envelope.conv_id instanceof Uint8Array && hex(envelope.conv_id) === previous.conversationId
    && envelope.msg_id instanceof Uint8Array && envelope.msg_id.length === 16
    && uint(envelope.conv_epoch) && envelope.conv_epoch <= MAX_EPOCH, 'Invalid group envelope context');
  const id = hex(envelope.msg_id), digest = hex(suite.hash(serializeEnvelope(envelope)));
  const result = (state: GroupSessionState, rewound: boolean) => ({ state, rewound, conversation: groupSessionConversation(state), group: roster(state.snapshot) });
  if (previous.seen[id]) {
    requireValue(previous.seen[id].digest === digest, 'Conflicting group message ID');
    return { ...result(previous, false), duplicate: true };
  }
  const at = Math.floor(Date.now() / 1000);
  const state = structuredClone(previous);
  state.rekeys = state.rekeys.filter(frame => frame.expiresAt >= at);
  const rewound = envelope.conv_epoch < state.epoch;
  const source = rewound ? state.rekeys.find(frame => frame.epoch === envelope.conv_epoch) : undefined;
  requireValue(envelope.conv_epoch === state.epoch || source && id < source.messageId, 'Stale, future or superseded group epoch');
  const sourceState = source ? { ...state, epoch: source.epoch, root: source.root, snapshot: source.snapshot } : state;
  const conversation = groupSessionConversation(sourceState);
  const message = decryptMessage(envelope, conversation);
  const { body_type: type, sender_kid: sender } = message.inner;
  requireValue(!rewound || type === 'group_rekey', 'Old group epochs cannot deliver application or membership events');
  const group = roster(sourceState.snapshot);
  requireValue(group.isMember(sender), 'Group sender is not a current member');
  if (controls.has(type)) {
    const body = unmarshalCanonical<Record<string, unknown>>(message.inner.body);
    requireValue(body && typeof body === 'object' && !Array.isArray(body), 'Invalid group control');
    requireValue((body.group_epoch === undefined && !state.signedEpoch)
      || uint(body.group_epoch) && body.group_epoch === envelope.conv_epoch, 'Group control is not signed for this epoch');
    requireValue(type !== 'group_genesis', 'Group genesis is already established');
    if (type === 'group_add') {
      const members = body.new_members;
      requireValue(uint(body.added_at) && Array.isArray(members) && members.length > 0
        && group.memberCount() + members.length <= 128, 'Invalid group addition');
      const merged = group.snapshot();
      for (const member of members) {
        requireValue(member && member.added_by instanceof Uint8Array && uint8ArrayEquals(member.added_by, sender)
          && member.added_at === body.added_at && member.key_id instanceof Uint8Array
          && !group.isMember(member.key_id), 'Invalid added member binding');
      }
      merged.founding_members.push(...members);
      validateGroupSnapshot(merged);
      group.applyAdd({ added_at: body.added_at, new_members: members });
      state.needsRekey = true;
    } else if (type === 'group_remove') {
      const members = body.removed_members;
      requireValue(uint(body.removed_at) && typeof body.reason === 'string' && new TextEncoder().encode(body.reason).length <= 4096
        && Array.isArray(members) && members.length > 0 && members.length <= 128, 'Invalid group removal');
      const creator = group.snapshot().founding_members[0].key_id;
      const seen = new Set<string>();
      for (const kid of members) {
        requireValue(kid instanceof Uint8Array && kid.length === 16 && group.isMember(kid)
          && !uint8ArrayEquals(kid, creator) && !seen.has(hex(kid)), 'Invalid removed member');
        seen.add(hex(kid));
      }
      group.applyRemove({ removed_at: body.removed_at, removed_members: members, reason: body.reason });
      state.needsRekey = true;
      state.removed ||= !group.isMember(identity.keyID);
    } else {
      requireValue(uint(body.new_conv_epoch) && body.new_conv_epoch === envelope.conv_epoch + 1
        && body.new_conv_epoch <= MAX_EPOCH, 'Rekey must advance exactly one epoch');
      const wrapped = body.wrapped_keys;
      requireValue(wrapped && typeof wrapped === 'object' && !Array.isArray(wrapped)
        && Object.keys(wrapped).sort().join(',') === group.listMembers().map(base64UrlEncode).sort().join(',')
        && Object.values(wrapped).every(validWrapped),
      'Rekey recipients differ from current membership');
      // Removal is sticky. Even a later old-key add cannot restore access without
      // a separately admitted welcome and its new key generation.
      if (!state.removed && group.isMember(identity.keyID)) {
        const root = suite.unwrapKeyForRecipient((wrapped as Record<string, Uint8Array>)[base64UrlEncode(identity.keyID)], identity.privateKey, identity.keyID, conversation.id);
        requireValue(root.length === 32, 'Invalid rekey group root');
        if (source) {
          state.rekeys = state.rekeys.filter(frame => frame.epoch < source.epoch);
          for (const [seenId, event] of Object.entries(state.seen)) if (event.epoch > source.epoch) delete state.seen[seenId];
        }
        state.rekeys.push({ epoch: conversation.currentEpoch, root: hex(conversation.keys.root),
          snapshot: sourceState.snapshot, messageId: id, expiresAt: Math.min(envelope.expiry_ts, at + GROUP_REKEY_GRACE_SECONDS) });
        state.rekeys = state.rekeys.slice(-MAX_GROUP_REKEY_CHECKPOINTS);
        applyRekey(conversation, root, body.new_conv_epoch);
        state.root = hex(root); state.epoch = body.new_conv_epoch;
      } else state.removed = true;
      state.needsRekey = false;
    }
    state.snapshot = encodeRoster(group);
  } else {
    requireValue(!type.startsWith('gate.') && !type.startsWith('gov.'), 'Gateway events require the gateway session reducer');
    assertGroupCanSend(identity, state);
  }
  state.seen[id] = { digest, epoch: envelope.conv_epoch };
  if (Object.keys(state.seen).length > MAX_SEEN) delete state.seen[Object.keys(state.seen)[0]];
  return { ...result(state, rewound), duplicate: false, message };
}
