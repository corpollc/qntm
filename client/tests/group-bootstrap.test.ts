import {describe,it,expect} from 'vitest';
import {generateIdentity,createInvite,createConversation,deriveConversationKeys,GroupState,createGroupGenesisBody,parseGroupGenesisBody,createRekey,applyRekey,createMessage,serializeEnvelope,decryptMessage,createCurrentEpochInvite,openCurrentEpochInvite,base64UrlDecode,base64UrlEncode,marshalCanonical,unmarshalCanonical,resolveRekeyCandidates,compareMessageIDs} from '../src/index.js';
function setup(){
 const owner=generateIdentity(),member=generateIdentity(),outsider=generateIdentity();const invitation=createInvite(owner,'group');const original=createConversation(invitation,deriveConversationKeys(invitation));const state=new GroupState();state.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Company','',owner,[member.publicKey])));
 const body=createRekey(owner,original,state);const envelope=createMessage(owner,original,'group_rekey',body.bodyBytes);const current={...original,keys:{...original.keys}};applyRekey(current,body.newGroupKey,1);
 return{owner,member,outsider,state,original,current,envelope};
}
describe('Current epoch group bootstrap',()=>{
 it('delivers only the current keys to the intended admitted participant with immutable creator and roster',()=>{
  const f=setup();const token=createCurrentEpochInvite(f.owner,f.current,f.state,f.member.publicKey,f.envelope.msg_id);const joined=openCurrentEpochInvite(f.member,token,{conversationId:f.current.id,creatorPublicKey:f.owner.publicKey});
  expect(joined.conversation.keys).toEqual(f.current.keys);expect(joined.conversation.currentEpoch).toBe(1);expect(joined.state.snapshot()).toEqual(f.state.snapshot());expect(joined.conversation.epochKeys).toBeUndefined();expect(joined.conversation.inviteToken).toBeUndefined();
  const old=createMessage(f.owner,f.original,'text',new TextEncoder().encode('Private before admission'));expect(()=>decryptMessage(old,joined.conversation)).toThrow();
  const fresh=createMessage(f.owner,f.current,'text',new TextEncoder().encode('Current work'));expect(decryptMessage(fresh,joined.conversation).verified).toBe(true);
 });
 it('rejects unadmitted recipients, wrong identity, creator, conversation and expiry',()=>{
  const f=setup();expect(()=>createCurrentEpochInvite(f.owner,f.current,f.state,f.outsider.publicKey,f.envelope.msg_id)).toThrow(/admitted/);expect(()=>createCurrentEpochInvite(f.member,f.current,f.state,f.owner.publicKey,f.envelope.msg_id)).toThrow(/creator/);
  const token=createCurrentEpochInvite(f.owner,f.current,f.state,f.member.publicKey,f.envelope.msg_id,1000,600);
  expect(()=>openCurrentEpochInvite(f.outsider,token,{},1100)).toThrow(/another participant/);expect(()=>openCurrentEpochInvite(f.member,token,{creatorPublicKey:f.outsider.publicKey},1100)).toThrow(/creator/);expect(()=>openCurrentEpochInvite(f.member,token,{conversationId:new Uint8Array(16)},1100)).toThrow(/different/);expect(()=>openCurrentEpochInvite(f.member,token,{},1600)).toThrow(/expired/);
 });
 it('rejects altered sealed data/signature and bounds untrusted input',()=>{
  const f=setup();const token=createCurrentEpochInvite(f.owner,f.current,f.state,f.member.publicKey,f.envelope.msg_id);const data=unmarshalCanonical<any>(base64UrlDecode(token));data.sealed[10]^=1;expect(()=>openCurrentEpochInvite(f.member,base64UrlEncode(marshalCanonical(data)))).toThrow(/signature/);expect(()=>openCurrentEpochInvite(f.member,'a'.repeat(100000))).toThrow();
 });
 it('binds new membership controls to their signed source epoch',()=>{
  const f=setup();const envelope=createMessage(f.owner,f.current,'group_remove',marshalCanonical({removed_members:[f.member.keyID],removed_at:100,reason:''}));const body=unmarshalCanonical<any>(decryptMessage(envelope,f.current).inner.body);expect(body.group_epoch).toBe(1);
 });
});
describe('Canonical competing rekey selection',()=>{
 it('selects the same lowest authenticated ID in either order and for both participants',()=>{
  const f=setup();const candidates=[0,1].map(()=>createMessage(f.owner,f.original,'group_rekey',createRekey(f.owner,f.original,f.state).bodyBytes));candidates.sort((a,b)=>compareMessageIDs(a.msg_id,b.msg_id));const wires=candidates.map(serializeEnvelope);
  for(const identity of [f.owner,f.member])for(const order of [wires,[...wires].reverse()]){const resolution=resolveRekeyCandidates(identity,f.original,f.state,order)!;expect(Array.from(resolution.envelope.msg_id)).toEqual(Array.from(candidates[0].msg_id));expect(resolution.conversation?.keys).toEqual(resolveRekeyCandidates(f.owner,f.original,f.state,wires)?.conversation?.keys);}
 });
 it('ignores unauthorized, wrong-roster and invalid-signature candidates before ordering',()=>{
  const f=setup();const valid=serializeEnvelope(f.envelope);const unauthorized=serializeEnvelope(createMessage(f.outsider,f.original,'group_rekey',createRekey(f.outsider,f.original,f.state).bodyBytes));const changed=new Uint8Array(valid);changed[changed.length-10]^=1;
  expect(Array.from(resolveRekeyCandidates(f.member,f.original,f.state,[unauthorized,changed,valid])!.envelope.msg_id)).toEqual(Array.from(f.envelope.msg_id));
 });
});

import {readFileSync} from 'node:fs';
for(const language of ['typescript','python'])it(`opens ${language} current-epoch token and converges ${language} rekeys in both orders`,()=>{
 const f=JSON.parse(readFileSync(new URL(`./group-bootstrap-${language}.json`,import.meta.url),'utf8'));
 const bytes=(s:string)=>new Uint8Array(Buffer.from(s,'hex'));
 const member=Object.fromEntries(Object.entries(f.member).map(([k,v])=>[k,bytes(v as string)])) as any;
 const joined=openCurrentEpochInvite(member,f.token,{conversationId:bytes(f.source.id),creatorPublicKey:bytes(f.owner.publicKey)},f.at+1);
 expect(Buffer.from(joined.conversation.keys.root).toString('hex')).toBe(f.root);
 const source={id:bytes(f.source.id),type:'group' as const,keys:Object.fromEntries(Object.entries(f.source.keys).map(([k,v])=>[k,bytes(v as string)])) as any,participants:[],createdAt:new Date(),currentEpoch:0};
 const state=new GroupState();state.applyGenesis(parseGroupGenesisBody(new Uint8Array(Buffer.from(f.roster_b64,'base64'))));
 const wires=f.wires.map((x:string)=>new Uint8Array(Buffer.from(x,'base64')));
 for(const order of [wires,[...wires].reverse()]) {
   const result=resolveRekeyCandidates(member,source,state,order,{allowExpired:true})!;
   expect(Buffer.from(result.envelope.msg_id).toString('hex')).toBe(f.winner_id);
   expect(Buffer.from(result.conversation!.keys.root).toString('hex')).toBe(f.root);
 }
});


it('requires an explicit pinned control delegate for gateway rekeys without adding a gateway member',()=>{
 const f=setup(),gateway=generateIdentity(),impostor=generateIdentity();
 const wire=serializeEnvelope(createMessage(gateway,f.original,'group_rekey',createRekey(gateway,f.original,f.state).bodyBytes));
 expect(resolveRekeyCandidates(f.member,f.original,f.state,[wire])).toBeNull();
 expect(resolveRekeyCandidates(f.member,f.original,f.state,[wire],{authorizedControlSigner:impostor.publicKey})).toBeNull();
 expect(resolveRekeyCandidates(f.member,f.original,f.state,[wire],{authorizedControlSigner:gateway.publicKey})?.conversation?.currentEpoch).toBe(1);
 expect(f.state.isMember(gateway.keyID)).toBe(false);
 expect(f.state.creatorKeyID()).toEqual(f.owner.keyID);
});
