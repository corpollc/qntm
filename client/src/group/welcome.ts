/** Recipient-encrypted welcomes for an authorized contact addition.
 *
 * These helpers do not post messages or commit local state. Hosts publish the
 * addition and rekey successfully before releasing a welcome, and persist the
 * exact prepared envelopes for uncertain-send recovery.
 */
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { isValidEd25519PublicKey } from '../crypto/ed25519.js';
import { sealSecret, openSecret } from '../crypto/naclbox.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { generateMessageID, keyIDFromPublicKey, uint8ArrayEquals, validateIdentity } from '../identity/index.js';
import { createMessage } from '../message/index.js';
import { GroupState, createGroupAddBody, parseGroupAddBody, createRekey, applyRekey } from './index.js';
import type { GroupGenesisBody } from './index.js';
import type { Conversation, Identity, OuterEnvelope } from '../types.js';

const suite = new QSP1Suite();
const DOMAIN = 'qntm/group-welcome/v1';
const REFRESH_DOMAIN = 'qntm/group-refresh/v1';
const RENEWAL_DOMAIN = 'qntm/group-renewal/v1';
export const MAX_GROUP_WELCOME_BYTES = 65536;
export const GROUP_WELCOME_TTL = 604800;
const MAX_EPOCH = 0xffffffff;
const equal = uint8ArrayEquals;
const now = () => Math.floor(Date.now() / 1000);
const uint = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const bytes = (value: unknown, size: number): value is Uint8Array => value instanceof Uint8Array && value.length === size;
const hex = (value: Uint8Array) => Array.from(value, b => b.toString(16).padStart(2, '0')).join('');
const unhex = (value: string) => new Uint8Array(value.match(/../g)!.map(b => parseInt(b, 16)));
const fixedHex = (value: unknown, size: number): value is string => typeof value === 'string'
  && value.length === size * 2 && /^[0-9a-f]+$/.test(value);
function requireValue(value: unknown, reason: string): asserts value {
  if (!value) throw new Error(reason);
}
function fields(value: unknown, names: string): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === names.split(',').sort().join(',');
}

export interface GroupWelcomeEnvelope extends OuterEnvelope {
  kind: 'group_welcome';
}
/** Private accepted-admission evidence. Missing entries mean unknown provenance. */
export interface GroupAdmission {
  addId: string;
  addDigest: string;
  sourceEpoch: number;
  completion: null | { rekeyId: string; rekeyDigest: string };
}
export type GroupAdmissions = Record<string, GroupAdmission>;

/** Validate locally authenticated evidence; this does not authenticate network JSON. */
export function validateGroupAdmissions(value: unknown, state: GroupState, epoch: number, allowPending = false): asserts value is GroupAdmissions {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length <= 128, 'Invalid group admission provenance');
  const members = new Set(state.listMembers().map(hex));
  for (const [kid, record] of Object.entries(value)) {
    requireValue(fixedHex(kid, 16) && members.has(kid)
      && fields(record, 'addId,addDigest,sourceEpoch,completion') && fixedHex(record.addId, 16)
      && fixedHex(record.addDigest, 32) && uint(record.sourceEpoch) && record.sourceEpoch <= MAX_EPOCH,
    'Invalid group admission provenance');
    requireValue(record.completion === null
      ? allowPending && record.sourceEpoch === epoch
      : fields(record.completion, 'rekeyId,rekeyDigest') && fixedHex(record.completion.rekeyId, 16)
        && fixedHex(record.completion.rekeyDigest, 32) && record.sourceEpoch < epoch,
    'Invalid group admission completion');
  }
}
function wireAdmissions(value: GroupAdmissions): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).map(([kid, record]) => {
    requireValue(record.completion, 'Admission has not completed its key rotation');
    return [kid, { add_id: unhex(record.addId), add_hash: unhex(record.addDigest), source_epoch: record.sourceEpoch,
      rekey_id: unhex(record.completion.rekeyId), rekey_hash: unhex(record.completion.rekeyDigest) }];
  }));
}
function readAdmissions(value: unknown, state: GroupState, epoch: number): GroupAdmissions {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length <= 128, 'Invalid welcome admission provenance');
  const result: GroupAdmissions = {};
  for (const [kid, record] of Object.entries(value)) {
    requireValue(fixedHex(kid, 16) && fields(record, 'add_id,add_hash,source_epoch,rekey_id,rekey_hash')
      && bytes(record.add_id, 16) && bytes(record.add_hash, 32) && uint(record.source_epoch)
      && bytes(record.rekey_id, 16) && bytes(record.rekey_hash, 32), 'Invalid welcome admission provenance');
    result[kid] = { addId: hex(record.add_id), addDigest: hex(record.add_hash), sourceEpoch: record.source_epoch,
      completion: { rekeyId: hex(record.rekey_id), rekeyDigest: hex(record.rekey_hash) } };
  }
  validateGroupAdmissions(result, state, epoch);
  return result;
}
export interface GroupAddition {
  /** New local state; install only when the corresponding rekey is accepted. */
  conversation: Conversation;
  state: GroupState;
  addition: OuterEnvelope;
  rekey: OuterEnvelope;
  /** Post after the addition and rekey, never before them. */
  welcomes: GroupWelcomeEnvelope[];
}
export type GroupWelcome = {
  conversation: Conversation;
  state: GroupState;
  inviterPublicKey: Uint8Array;
  messageId: Uint8Array;
  /** Sender's fully processed relay cursor before preparing this welcome. */
  replayFromSequence: number;
  recoveryChallenge?: Uint8Array;
  admissions: GroupAdmissions;
} & ({ purpose: 'addition'; additionId: Uint8Array; rekeyId: Uint8Array; additionHash?: Uint8Array; rekeyHash?: Uint8Array }
  | { purpose: 'refresh' | 'renewal'; additionId?: never; rekeyId?: never });
interface WelcomeContext {
  envelope: ReturnType<typeof header>;
  inviter_ik_pk: Uint8Array;
  recipient_ik_pk: Uint8Array;
  group_key: Uint8Array;
  group_state: GroupGenesisBody;
  replay_from_seq: number;
  recovery_challenge?: Uint8Array;
  admissions?: Record<string, unknown>;
}
type WelcomePayload = WelcomeContext & ({ proto: typeof DOMAIN; addition_id: Uint8Array; rekey_id: Uint8Array; addition_hash: Uint8Array; rekey_hash: Uint8Array }
  | { proto: typeof REFRESH_DOMAIN | typeof RENEWAL_DOMAIN });
function header(envelope: GroupWelcomeEnvelope) {
  return { v: envelope.v, suite: envelope.suite, kind: envelope.kind,
    conv_id: envelope.conv_id, msg_id: envelope.msg_id, conv_epoch: envelope.conv_epoch,
    created_ts: envelope.created_ts, expiry_ts: envelope.expiry_ts };
}

/** Internal sealing primitive. Call the checkpoint-aware refresh helper for recovery. */
export function sealGroupWelcome(identity: Identity, conversation: Conversation, state: GroupState,
  recipient: Uint8Array, createdAt: number, ttl: number,
  admission?: { additionId: Uint8Array; rekeyId: Uint8Array; additionHash: Uint8Array; rekeyHash: Uint8Array }, recoveryChallenge?: Uint8Array,
  replayFromSequence = 0, admissions?: GroupAdmissions, renewal = false): GroupWelcomeEnvelope {
  requireValue(uint(replayFromSequence), 'Invalid welcome replay anchor');
  if (admissions !== undefined) validateGroupAdmissions(admissions, state, conversation.currentEpoch);
  requireValue(!renewal || !admission && admissions?.[hex(keyIDFromPublicKey(recipient))]?.completion,
    'Admission renewal requires current provenance');
  const envelope: GroupWelcomeEnvelope = { v: 1, suite: 'QSP-1', kind: 'group_welcome',
    conv_id: new Uint8Array(conversation.id), msg_id: generateMessageID(), conv_epoch: conversation.currentEpoch,
    created_ts: createdAt, expiry_ts: createdAt + ttl, ciphertext: new Uint8Array() };
  const context: WelcomeContext = { envelope: header(envelope), inviter_ik_pk: identity.publicKey,
    recipient_ik_pk: recipient, group_key: conversation.keys.root, group_state: state.snapshot(), replay_from_seq: replayFromSequence,
    ...(recoveryChallenge ? { recovery_challenge: recoveryChallenge } : {}),
    ...(admissions !== undefined ? { admissions: wireAdmissions(admissions) } : {}) };
  const payload: WelcomePayload = admission
    ? { ...context, proto: DOMAIN, addition_id: admission.additionId, rekey_id: admission.rekeyId,
      addition_hash: admission.additionHash, rekey_hash: admission.rekeyHash }
    : { ...context, proto: renewal ? RENEWAL_DOMAIN : REFRESH_DOMAIN };
  const signature = suite.sign(identity.privateKey, marshalCanonical(payload));
  envelope.ciphertext = sealSecret(identity.privateKey, recipient, marshalCanonical({ payload, signature }));
  requireValue(marshalCanonical(envelope).length <= MAX_GROUP_WELCOME_BYTES, 'Group welcome exceeds size limit');
  return envelope;
}

/** Validate a roster before applying any of it. Creator identity stays first. */
export function validateGroupSnapshot(value: unknown): asserts value is GroupGenesisBody {
  requireValue(fields(value, 'group_name,description,created_at,founding_members'), 'Invalid group snapshot');
  const encoder = new TextEncoder();
  requireValue(typeof value.group_name === 'string' && encoder.encode(value.group_name).length <= 256
    && typeof value.description === 'string' && encoder.encode(value.description).length <= 4096
    && uint(value.created_at), 'Invalid group snapshot metadata');
  requireValue(Array.isArray(value.founding_members) && value.founding_members.length > 0
    && value.founding_members.length <= 128, 'Invalid group snapshot size');
  const seen = new Set<string>();
  for (const member of value.founding_members) {
    requireValue(fields(member, 'key_id,public_key,role,added_at,added_by')
      && bytes(member.key_id, 16) && bytes(member.public_key, 32) && isValidEd25519PublicKey(member.public_key)
      && equal(member.key_id, keyIDFromPublicKey(member.public_key as Uint8Array))
      && (member.role === 'admin' || member.role === 'member') && uint(member.added_at)
      && bytes(member.added_by, 16), 'Invalid group snapshot member');
    const kid = Array.from(member.key_id).join(',');
    requireValue(!seen.has(kid), 'Duplicate group snapshot member');
    seen.add(kid);
  }
  requireValue(value.founding_members[0].role === 'admin', 'Invalid group creator');
}

/** Prepare one authorized add operation, always with a fresh key generation.
 * The state is a trusted local checkpoint, not an unverified network snapshot.
 * Gateway-governed membership must use its governance operation instead.
 */
export function prepareGroupAddition(identity: Identity, conversation: Conversation, state: GroupState,
  recipients: Uint8Array[], ttl = GROUP_WELCOME_TTL, recoveryChallenge?: Uint8Array, replayFromSequence = 0,
  admissions: GroupAdmissions = {}): GroupAddition {
  validateIdentity(identity);
  requireValue(conversation.type === 'group' && bytes(conversation.id, 16)
    && uint(conversation.currentEpoch) && conversation.currentEpoch < MAX_EPOCH,
  'Invalid group addition context');
  const snapshot = state.snapshot();
  validateGroupSnapshot(snapshot);
  requireValue(state.isMember(identity.keyID), 'Only a current group member may add contacts');
  validateGroupAdmissions(admissions, state, conversation.currentEpoch);
  requireValue(Array.isArray(recipients) && recipients.length > 0
    && state.memberCount() + recipients.length <= 128, 'Invalid added contact count');
  requireValue(uint(ttl) && ttl > 0 && ttl <= GROUP_WELCOME_TTL, 'Invalid welcome lifetime');
  requireValue(uint(replayFromSequence), 'Invalid welcome replay anchor');
  requireValue(recoveryChallenge === undefined || bytes(recoveryChallenge, 32) && recipients.length === 1, 'Invalid recovery challenge');
  const seen = new Set<string>();
  for (const recipient of recipients) {
    requireValue(isValidEd25519PublicKey(recipient), 'Invalid contact public key');
    const kid = keyIDFromPublicKey(recipient);
    const key = Array.from(kid).join(',');
    requireValue(!state.isMember(kid) && !seen.has(key), 'Contact is already a group member');
    seen.add(key);
  }
  // Compare the complete roster before creating any new key or message.
  const kids = (values: Uint8Array[]) => values.map(v => Array.from(v).join(',')).sort().join(';');
  requireValue(kids(conversation.participants) === kids(state.listMembers()), 'Group roster differs from conversation');
  requireValue(bytes(conversation.keys.root, 32), 'Invalid source group key');
  const keys = suite.deriveEpochKeys(conversation.keys.root, conversation.id, conversation.currentEpoch);
  requireValue(equal(keys.aeadKey, conversation.keys.aeadKey) && equal(keys.nonceKey, conversation.keys.nonceKey),
    'Source group keys do not match the epoch');
  const nextState = new GroupState();
  nextState.applyGenesis(snapshot);
  const add = parseGroupAddBody(createGroupAddBody(identity, recipients));
  const addition = createMessage(identity, conversation, 'group_add',
    marshalCanonical({ ...add, group_epoch: conversation.currentEpoch }), undefined, ttl);
  nextState.applyAdd(add);
  const { bodyBytes, newGroupKey } = createRekey(identity, conversation, nextState);
  const body = unmarshalCanonical<Record<string, unknown>>(bodyBytes);
  const rekey = createMessage(identity, conversation, 'group_rekey',
    marshalCanonical({ ...body, group_epoch: conversation.currentEpoch }), undefined, ttl);
  const next: Conversation = { ...conversation, keys: { ...conversation.keys }, participants: nextState.listMembers() };
  applyRekey(next, newGroupKey, conversation.currentEpoch + 1);
  // A welcome never carries an old invite token or saved epoch-key archive.
  delete next.inviteToken;
  const nextAdmissions = structuredClone(admissions);
  for (const recipient of recipients) nextAdmissions[hex(keyIDFromPublicKey(recipient))] = {
    addId: hex(addition.msg_id), addDigest: hex(suite.hash(marshalCanonical(addition))), sourceEpoch: conversation.currentEpoch,
    completion: { rekeyId: hex(rekey.msg_id), rekeyDigest: hex(suite.hash(marshalCanonical(rekey))) },
  };
  const welcomes = recipients.map(recipient => sealGroupWelcome(identity, next, nextState, recipient,
    addition.created_ts, ttl, { additionId: addition.msg_id, rekeyId: rekey.msg_id,
      additionHash: suite.hash(marshalCanonical(addition)), rekeyHash: suite.hash(marshalCanonical(rekey)) }, recoveryChallenge, replayFromSequence, nextAdmissions));
  return { conversation: next, state: nextState, addition, rekey, welcomes };
}

/** Recognize the transport kind only; this is not authentication. */
export function isGroupWelcomeEnvelope(value: unknown): value is GroupWelcomeEnvelope {
  return value !== null && typeof value === 'object' && (value as GroupWelcomeEnvelope).kind === 'group_welcome';
}

/** Open using a contact/link's pinned inviter and group, never a self-asserted key.
 * The result is bootstrap data. The host must reject rollback/replayed state and
 * replay subsequent membership changes before enabling sends or agent actions.
 */
export function openGroupWelcome(identity: Identity, wire: Uint8Array,
  expected: { conversationId: Uint8Array; inviterPublicKey: Uint8Array }, at = now()): GroupWelcome {
  validateIdentity(identity);
  requireValue(isValidEd25519PublicKey(expected.inviterPublicKey) && bytes(expected.conversationId, 16),
    'Invalid pinned group contact');
  requireValue(wire instanceof Uint8Array && wire.length > 0 && wire.length <= MAX_GROUP_WELCOME_BYTES,
    'Invalid group welcome size');
  const value = unmarshalCanonical<unknown>(wire);
  requireValue(fields(value, 'v,suite,kind,conv_id,msg_id,conv_epoch,created_ts,expiry_ts,ciphertext')
    && value.v === 1 && value.suite === 'QSP-1' && value.kind === 'group_welcome'
    && bytes(value.conv_id, 16) && bytes(value.msg_id, 16)
    && uint(value.conv_epoch) && value.conv_epoch <= MAX_EPOCH
    && uint(value.created_ts) && value.created_ts > 0 && uint(value.expiry_ts)
    && value.expiry_ts > value.created_ts && value.expiry_ts - value.created_ts <= GROUP_WELCOME_TTL
    && value.ciphertext instanceof Uint8Array && value.ciphertext.length >= 40, 'Invalid group welcome envelope');
  requireValue(equal(wire, marshalCanonical(value)), 'Group welcome must use canonical CBOR');
  requireValue(uint(at) && value.created_ts <= at + 600 && at <= value.expiry_ts, 'Group welcome is expired or not yet valid');
  requireValue(equal(value.conv_id, expected.conversationId), 'Welcome belongs to a different group');
  const plaintext = openSecret(identity.privateKey, expected.inviterPublicKey, value.ciphertext);
  const opened = unmarshalCanonical<unknown>(plaintext);
  requireValue(fields(opened, 'payload,signature') && bytes(opened.signature, 64), 'Invalid signed group welcome');
  requireValue(equal(plaintext, marshalCanonical(opened)), 'Signed group welcome must use canonical CBOR');
  const payload = opened.payload;
  const anchorFields = payload && typeof payload === 'object' && Object.hasOwn(payload, 'replay_from_seq') ? ',replay_from_seq' : '';
  const provenanceFields = payload && typeof payload === 'object' && Object.hasOwn(payload, 'admissions') ? ',admissions' : '';
  const common = 'proto,envelope,inviter_ik_pk,recipient_ik_pk,group_key,group_state' + anchorFields + provenanceFields;
  const challengeFields = payload && typeof payload === 'object' && Object.hasOwn(payload, 'recovery_challenge') ? ',recovery_challenge' : '';
  const hashFields = payload && typeof payload === 'object' && (Object.hasOwn(payload, 'addition_hash') || Object.hasOwn(payload, 'rekey_hash')) ? ',addition_hash,rekey_hash' : '';
  const addition = fields(payload, common + ',addition_id,rekey_id' + challengeFields + hashFields)
    && payload.proto === DOMAIN && bytes(payload.addition_id, 16) && bytes(payload.rekey_id, 16) && value.conv_epoch > 0
    && (!hashFields || bytes(payload.addition_hash, 32) && bytes(payload.rekey_hash, 32));
  const refresh = fields(payload, common + challengeFields)
    && payload.proto === REFRESH_DOMAIN;
  const renewal = fields(payload, common + challengeFields) && payload.proto === RENEWAL_DOMAIN && !!provenanceFields;
  requireValue((addition || refresh || renewal) && bytes(payload.inviter_ik_pk, 32) && bytes(payload.recipient_ik_pk, 32)
    && bytes(payload.group_key, 32) && (!anchorFields || uint(payload.replay_from_seq))
    && (!challengeFields || bytes(payload.recovery_challenge, 32)),
  'Invalid group welcome payload');
  requireValue(equal(payload.inviter_ik_pk, expected.inviterPublicKey)
    && equal(payload.recipient_ik_pk, identity.publicKey), 'Welcome contact binding differs');
  requireValue(equal(marshalCanonical(payload.envelope), marshalCanonical(header(value as unknown as GroupWelcomeEnvelope))),
    'Welcome envelope differs from signed context');
  requireValue(suite.verify(expected.inviterPublicKey, marshalCanonical(payload), opened.signature), 'Invalid group welcome signature');
  validateGroupSnapshot(payload.group_state);
  const state = new GroupState();
  state.applyGenesis(payload.group_state);
  requireValue(state.isMember(keyIDFromPublicKey(expected.inviterPublicKey)) && state.isMember(identity.keyID),
    'Welcome does not establish an admitted contact and current inviter');
  const admissions = provenanceFields ? readAdmissions(payload.admissions, state, value.conv_epoch) : {};
  const recipientAdmission = admissions[hex(identity.keyID)];
  requireValue(!renewal || recipientAdmission?.completion, 'Admission renewal omits recipient provenance');
  if (addition && provenanceFields) requireValue(recipientAdmission?.addId === hex(payload.addition_id as Uint8Array)
    && recipientAdmission.sourceEpoch + 1 === value.conv_epoch && hashFields
    && recipientAdmission.addDigest === hex(payload.addition_hash as Uint8Array)
    && recipientAdmission.completion?.rekeyId === hex(payload.rekey_id as Uint8Array)
    && recipientAdmission.completion.rekeyDigest === hex(payload.rekey_hash as Uint8Array), 'Welcome admission proof differs');
  const conversation: Conversation = { id: new Uint8Array(value.conv_id), type: 'group', name: state.groupName,
    keys: { root: payload.group_key, ...suite.deriveEpochKeys(payload.group_key, value.conv_id, value.conv_epoch) },
    participants: state.listMembers(), createdAt: new Date(state.createdAt * 1000), currentEpoch: value.conv_epoch };
  const result = { conversation, state, inviterPublicKey: new Uint8Array(expected.inviterPublicKey), messageId: value.msg_id,
    replayFromSequence: anchorFields ? payload.replay_from_seq as number : 0, admissions,
    ...(challengeFields ? { recoveryChallenge: payload.recovery_challenge as Uint8Array } : {}) };
  return addition
    ? { ...result, purpose: 'addition', additionId: payload.addition_id as Uint8Array, rekeyId: payload.rekey_id as Uint8Array,
      ...(hashFields ? { additionHash: payload.addition_hash as Uint8Array, rekeyHash: payload.rekey_hash as Uint8Array } : {}) }
    : { ...result, purpose: renewal ? 'renewal' : 'refresh' };
}
