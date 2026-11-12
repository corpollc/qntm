/** Authority checks for already authenticated group controls. No network I/O.
 * Persist this checkpoint with the returned keys; never accept it from a peer. */
import { marshalCanonical } from '../crypto/cbor.js';
import { base64UrlDecode, base64UrlEncode, uint8ArrayEquals } from '../identity/index.js';
import { GroupState, parseGroupGenesisBody, parseGroupAddBody, parseGroupRemoveBody, parseGroupRekeyBody } from './index.js';
import type { GroupMember } from './index.js';
import { resolveRekeyCandidates } from '../group-bootstrap/rekey.js';
import { serializeEnvelope } from '../message/index.js';
import type { Conversation, Identity, Message, OuterEnvelope } from '../types.js';

export interface GroupControlState {
  creator: string;
  roster?: string; // base64url canonical CBOR snapshot
  needsRekey: boolean;
  removed: boolean;
  recoveryRequired?: boolean;
}
const requireControl = (ok: unknown, error: string): void => { if (!ok) throw new Error(error); };

export function applyAuthenticatedGroupControl(
  envelope: OuterEnvelope, message: Message, conversation: Conversation, identity: Identity,
  previous: GroupControlState, knownKeys: Record<string, string>, gatewayPublicKey?: Uint8Array,
): { conversation: Conversation; state: GroupControlState; participants: Record<string, string> } {
  requireControl(!previous.recoveryRequired, 'Conversation rekey failed authentication; recovery required');
  const delegated = gatewayPublicKey && uint8ArrayEquals(message.inner.sender_ik_pk, gatewayPublicKey);
  requireControl(message.verified && (conversation.type === 'group' || delegated), 'Not an authorized group control');
  requireControl(envelope.conv_epoch === conversation.currentEpoch, 'Group control epoch differs from current conversation');
  requireControl(message.inner.body instanceof Uint8Array, 'Invalid group control body');
  const sender = message.inner.sender_kid, senderId = base64UrlEncode(sender), type = message.inner.body_type;
  const state = { ...previous }, roster = new GroupState();
  if (state.roster) roster.applyGenesis(parseGroupGenesisBody(base64UrlDecode(state.roster)));
  else if (delegated && type !== 'group_genesis') {
    const kids = conversation.participants.map(base64UrlEncode);
    requireControl(kids.every(kid => knownKeys[kid]), 'Missing authenticated group public keys');
    kids.sort((a, b) => a === state.creator ? -1 : b === state.creator ? 1 : a.localeCompare(b));
    roster.applyGenesis({ group_name: '', description: '', created_at: 0, founding_members: kids.map(kid => ({
      key_id: base64UrlDecode(kid), public_key: base64UrlDecode(knownKeys[kid]), role: conversation.type === 'group' && kid === state.creator ? 'admin' : 'member',
      added_at: 0, added_by: base64UrlDecode(state.creator),
    })) });
  }
  const bodyBytes = new Uint8Array(message.inner.body);
  const checkMembers = (members: GroupMember[]) => {
    requireControl(Array.isArray(members) && members.length > 0 && members.length <= 128, 'Invalid group members');
    requireControl(new Set(members.map(m => base64UrlEncode(m.key_id))).size === members.length, 'Duplicate group member');
    for (const m of members) requireControl(
      (m.role === 'admin' || m.role === 'member') && m.added_by instanceof Uint8Array && uint8ArrayEquals(m.added_by, sender)
      && Number.isSafeInteger(m.added_at) && m.added_at >= 0, 'Invalid member binding');
  };
  let next = { ...conversation, keys: { ...conversation.keys } };
  let body: object;
  if (type === 'group_genesis') {
    const genesis = parseGroupGenesisBody(bodyBytes); body = genesis;
    requireControl(!gatewayPublicKey && !state.roster && conversation.currentEpoch === 0 && senderId === state.creator,
      'Untrusted or repeated group genesis');
    checkMembers(genesis.founding_members);
    requireControl(base64UrlEncode(genesis.founding_members[0].key_id) === state.creator && genesis.founding_members[0].role === 'admin',
      'Genesis does not match creator');
    roster.applyGenesis(genesis);
  } else if (type === 'group_add') {
    requireControl(delegated || (!gatewayPublicKey && roster.isAdmin(sender)), 'Only a group administrator or accepted gateway may add members');
    const add = parseGroupAddBody(bodyBytes); body = add; checkMembers(add.new_members);
    requireControl(roster.memberCount() + add.new_members.length <= 128 && add.new_members.every(m => !roster.isMember(m.key_id)), 'Duplicate or excessive membership');
    requireControl(!delegated || add.new_members.every(m => m.role === 'member' && !uint8ArrayEquals(m.public_key, gatewayPublicKey!)), 'Gateway cannot appoint administrators or itself');
    roster.applyAdd(add); state.needsRekey = true;
  } else if (type === 'group_remove') {
    requireControl(delegated || (!gatewayPublicKey && roster.isAdmin(sender)), 'Only a group administrator or accepted gateway may remove members');
    const remove = parseGroupRemoveBody(bodyBytes); body = remove;
    requireControl(Array.isArray(remove.removed_members) && remove.removed_members.length > 0 && remove.removed_members.length <= 128
      && new Set(remove.removed_members.map(base64UrlEncode)).size === remove.removed_members.length
      && remove.removed_members.every(k => k instanceof Uint8Array && roster.isMember(k) && (conversation.type !== 'group' || base64UrlEncode(k) !== state.creator)), 'Invalid member removal');
    roster.applyRemove(remove); state.needsRekey = true;
    if (remove.removed_members.some(k => uint8ArrayEquals(k, identity.keyID))) state.removed = true;
  } else {
    requireControl(type === 'group_rekey', 'Unknown group control');
    requireControl(delegated || (!gatewayPublicKey && roster.isMember(sender)), 'Group rekey sender is not authorized');
    body = parseGroupRekeyBody(bodyBytes);
    const result = resolveRekeyCandidates(identity, { ...conversation, type: 'group' }, roster, [serializeEnvelope(envelope)],
      gatewayPublicKey ? { authorizedControlSigner: gatewayPublicKey } : {});
    requireControl(result, 'Unauthorized rekey or recipients do not match current membership');
    if (result!.excluded) state.removed = true;
    else next = { ...result!.conversation!, type: conversation.type };
    state.needsRekey = false;
  }
  const sourceEpoch = (body as { group_epoch?: number }).group_epoch;
  requireControl(sourceEpoch === undefined || sourceEpoch === envelope.conv_epoch, 'Group control source epoch mismatch');
  state.roster = base64UrlEncode(marshalCanonical(roster.snapshot()));
  next.participants = roster.listMembers();
  const participants = Object.fromEntries(roster.membersForRekey().map(m => [base64UrlEncode(m.kid), base64UrlEncode(m.publicKey)]));
  return { conversation: next, state, participants };
}
