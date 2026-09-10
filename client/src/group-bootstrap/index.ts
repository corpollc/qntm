/** QSP v1.2 creator-endorsed, recipient-sealed current-epoch group bootstrap. */
import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { sealSecret, openSecret } from '../crypto/naclbox.js';
import { base64UrlEncode, base64UrlDecode, keyIDFromPublicKey, uint8ArrayEquals } from '../identity/index.js';
import { GroupState, type GroupGenesisBody } from '../group/index.js';
import type { Identity, Conversation } from '../types.js';

const suite = new QSP1Suite();
const TYPE = 'qntm.group.join';
const MAX_BYTES = 65536;
const MAX_AGE = 30*24*60*60;
const now = () => Math.floor(Date.now()/1000);
const equal = uint8ArrayEquals;
function bytes(value:unknown,size:number):value is Uint8Array {return value instanceof Uint8Array && value.length===size;}
function fields(value:unknown,expected:string):value is Record<string,unknown> {
  return Boolean(value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).sort().join(',')===expected.split(',').sort().join(','));
}
function uint(value:unknown):value is number {return Number.isSafeInteger(value) && Number(value)>=0;}
function fail():never {throw new Error('Invalid current-epoch group invitation');}
function snapshot(value:unknown,creator:Uint8Array,recipient:Uint8Array):GroupGenesisBody {
  if (!fields(value,'group_name,description,created_at,founding_members') || typeof value.group_name!=='string' || typeof value.description!=='string'
    || new TextEncoder().encode(value.group_name).length>256 || new TextEncoder().encode(value.description).length>4096 || !uint(value.created_at)
    || !Array.isArray(value.founding_members) || !value.founding_members.length || value.founding_members.length>128) fail();
  const seen=new Set<string>();let included=false;let previous:Uint8Array|undefined;
  for (let i=0;i<value.founding_members.length;i++) {
    const member=value.founding_members[i];
    if (!fields(member,'key_id,public_key,role,added_at,added_by') || !bytes(member.key_id,16) || !bytes(member.public_key,32)
      || !equal(member.key_id,keyIDFromPublicKey(member.public_key)) || !bytes(member.added_by,16) || !uint(member.added_at)
      || !['admin','member'].includes(String(member.role))) fail();
    const key=base64UrlEncode(member.key_id);if(seen.has(key))fail();seen.add(key);
    if (i===0 && (!equal(member.public_key,creator) || member.role!=='admin')) fail();
    if (i>1 && previous) {let order=0;for(let j=0;j<16;j++){order=member.key_id[j]-previous[j];if(order)break;}if(order<=0)fail();}
    if(i>0)previous=member.key_id;
    included ||= equal(member.public_key,recipient);
  }
  if(!included)throw new Error('Invitation recipient has not been admitted to this group');
  return value as unknown as GroupGenesisBody;
}
type Unsigned = {v:1;type:typeof TYPE;creator_ik_pk:Uint8Array;recipient_ik_pk:Uint8Array;sealed:Uint8Array};
type Token = Unsigned & {signature:Uint8Array};
export type CurrentEpochBootstrap = {
  conversation:Conversation;state:GroupState;creatorPublicKey:Uint8Array;rekeyId:Uint8Array;issuedAt:number;expiresAt:number;
};
function unsigned(token:Token):Unsigned {return {v:1,type:TYPE,creator_ik_pk:token.creator_ik_pk,recipient_ik_pk:token.recipient_ik_pk,sealed:token.sealed};}
function parse(token:string):Token {
  const fragment=(()=>{try{return new URL(token).hash.slice(1);}catch{return token;}})();
  if(!fragment || fragment.length>Math.ceil(MAX_BYTES*4/3))fail();
  const raw=base64UrlDecode(fragment);if(!raw.length||raw.length>MAX_BYTES)fail();
  const value=unmarshalCanonical<Token>(raw);
  if(!fields(value,'v,type,creator_ik_pk,recipient_ik_pk,sealed,signature') || value.v!==1 || value.type!==TYPE
    || !bytes(value.creator_ik_pk,32)||!bytes(value.recipient_ik_pk,32)||!bytes(value.signature,64)
    || !(value.sealed instanceof Uint8Array)||!value.sealed.length)fail();
  return value as unknown as Token;
}
export function isCurrentEpochInvite(token:string):boolean {
  try {parse(token);return true;}catch{return false;}
}
/** Authenticate public routing without opening a recipient's private snapshot. */
export function inspectCurrentEpochInvite(token:string):{creatorPublicKey:Uint8Array;recipientPublicKey:Uint8Array} {
 const value=parse(token);
 if(!suite.verify(value.creator_ik_pk,marshalCanonical(unsigned(value)),value.signature))throw new Error('Invalid group invitation signature');
 return{creatorPublicKey:value.creator_ik_pk,recipientPublicKey:value.recipient_ik_pk};
}
export function createCurrentEpochInvite(identity:Identity,conversation:Conversation,state:GroupState,recipient:Uint8Array,rekeyId:Uint8Array,issuedAt=now(),ttl=MAX_AGE):string {
  const creator=state.creatorKeyID();
  if(conversation.type!=='group'||!creator||!equal(creator,identity.keyID)||!state.isAdmin(identity.keyID))throw new Error('Only the existing group creator can issue a current-epoch invitation');
  if(!uint(conversation.currentEpoch)||conversation.currentEpoch<1||conversation.currentEpoch>0xffffffff||!bytes(conversation.keys.root,32)||!bytes(conversation.id,16)||!bytes(recipient,32)||!bytes(rekeyId,16))fail();
  if(!uint(issuedAt)||!uint(ttl)||ttl<1||ttl>MAX_AGE)fail();
  const roster=snapshot(state.snapshot(),identity.publicKey,recipient);
  const plain=marshalCanonical({v:1,conv_id:conversation.id,conv_epoch:conversation.currentEpoch,group_key:conversation.keys.root,rekey_id:rekeyId,group_state:roster,issued_at:issuedAt,expires_at:issuedAt+ttl});
  if(plain.length>49152)fail();
  const value:Unsigned={v:1,type:TYPE,creator_ik_pk:identity.publicKey,recipient_ik_pk:recipient,sealed:sealSecret(identity.privateKey,recipient,plain)};
  const raw=marshalCanonical({...value,signature:suite.sign(identity.privateKey,marshalCanonical(value))});
  if(raw.length>MAX_BYTES)fail();return base64UrlEncode(raw);
}
export function openCurrentEpochInvite(identity:Identity,token:string,expected:{conversationId?:Uint8Array;creatorPublicKey?:Uint8Array;allowExpired?:boolean}={},at=now()):CurrentEpochBootstrap {
  const outer=parse(token);
  if(!equal(outer.recipient_ik_pk,identity.publicKey))throw new Error('This invitation is sealed to another participant');
  if(expected.creatorPublicKey && !equal(expected.creatorPublicKey,outer.creator_ik_pk))throw new Error('Invitation creator does not match this workspace');
  if(!suite.verify(outer.creator_ik_pk,marshalCanonical(unsigned(outer)),outer.signature))throw new Error('Invalid group invitation signature');
  const raw=openSecret(identity.privateKey,outer.creator_ik_pk,outer.sealed);if(raw.length>49152)fail();
  const plain=unmarshalCanonical<Record<string,unknown>>(raw);
  if(!fields(plain,'v,conv_id,conv_epoch,group_key,rekey_id,group_state,issued_at,expires_at') || plain.v!==1
    ||!bytes(plain.conv_id,16)||!uint(plain.conv_epoch)||plain.conv_epoch<1||plain.conv_epoch>0xffffffff
    ||!bytes(plain.group_key,32)||!bytes(plain.rekey_id,16)||!uint(plain.issued_at)||!uint(plain.expires_at)
    ||plain.issued_at>at+300||plain.expires_at<=plain.issued_at||plain.expires_at-plain.issued_at>MAX_AGE)fail();
  if(plain.expires_at<=at && !expected.allowExpired)throw new Error('Current-epoch invitation expired; request a fresh invitation from the creator');
  if(expected.conversationId && !equal(expected.conversationId,plain.conv_id))throw new Error('Invitation belongs to a different workspace');
  const roster=snapshot(plain.group_state,outer.creator_ik_pk,identity.publicKey);const state=new GroupState();state.applyGenesis(roster);
  const derived=suite.deriveEpochKeys(plain.group_key,plain.conv_id,plain.conv_epoch);
  return {conversation:{id:plain.conv_id,type:'group',name:state.groupName,keys:{root:plain.group_key,...derived},participants:state.listMembers(),createdAt:new Date(roster.created_at*1000),currentEpoch:plain.conv_epoch},state,creatorPublicKey:outer.creator_ik_pk,rekeyId:plain.rekey_id,issuedAt:plain.issued_at,expiresAt:plain.expires_at};
}
