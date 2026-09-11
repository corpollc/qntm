// Synthetic identities for protocol vectors only. Never use these keys outside tests.
import * as q from '../dist/index.js';
import {writeFileSync} from 'node:fs';
const hex=x=>Buffer.from(x).toString('hex');
const owner=q.generateIdentity(),member=q.generateIdentity();const invite=q.createInvite(owner,'group');
const original=q.createConversation(invite,q.deriveConversationKeys(invite));
const state=new q.GroupState();state.applyGenesis(q.parseGroupGenesisBody(q.createGroupGenesisBody('Interop company','Synthetic QSP1.2 vector',owner,[member.publicKey])));
const wires=[0,1].map(()=>q.serializeEnvelope(q.createMessage(owner,original,'group_rekey',q.createRekey(owner,original,state).bodyBytes)));
const winner=q.resolveRekeyCandidates(owner,original,state,wires);const at=Math.floor(Date.now()/1000);
const token=q.createCurrentEpochInvite(owner,winner.conversation,state,member.publicKey,winner.envelope.msg_id,at);
const value={purpose:'Synthetic public test keys; never operational',at,owner:Object.fromEntries(Object.entries(owner).map(([k,v])=>[k,hex(v)])),member:Object.fromEntries(Object.entries(member).map(([k,v])=>[k,hex(v)])),token,
 source:{id:hex(original.id),epoch:0,keys:Object.fromEntries(Object.entries(original.keys).map(([k,v])=>[k,hex(v)]))},roster_b64:Buffer.from(q.marshalCanonical(state.snapshot())).toString('base64'),wires:wires.map(w=>Buffer.from(w).toString('base64')),winner_id:hex(winner.envelope.msg_id),root:hex(winner.conversation.keys.root)};
writeFileSync(new URL('./group-bootstrap-typescript.json',import.meta.url),JSON.stringify(value,null,2)+'\n');
