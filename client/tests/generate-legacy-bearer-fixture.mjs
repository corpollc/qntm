// Public synthetic identities and ciphertexts, never operational keys.
import * as q from '../dist/index.js';
import {writeFileSync} from 'node:fs';
const hex=x=>Buffer.from(x).toString('hex');
const owner=q.generateIdentity(),peer=q.generateIdentity();
const invite=q.createInvite(owner,'group');const conversation=q.createConversation(invite,q.deriveConversationKeys(invite));
const at=Math.floor(Date.now()/1000);
const genesis=q.serializeEnvelope(q.createMessage(owner,conversation,'group_genesis',q.createGroupGenesisBody('Legacy bearer vector','',owner,[])));
const hello=q.serializeEnvelope(q.createMessage(peer,conversation,'text',new TextEncoder().encode('Legacy bearer hello')));
const forbidden=q.serializeEnvelope(q.createMessage(peer,conversation,'group_add',q.createGroupAddBody(peer,[q.generateIdentity().publicKey])));
const value={purpose:'Public synthetic QSPv1.0 bearer-invite boundary fixture',at,owner:Object.fromEntries(Object.entries(owner).map(([k,v])=>[k,hex(v)])),peer_public_key:hex(peer.publicKey),peer_key_id:hex(peer.keyID),invite_token:q.inviteToToken(invite),genesis:Buffer.from(genesis).toString('base64'),hello:Buffer.from(hello).toString('base64'),forbidden_control:Buffer.from(forbidden).toString('base64')};
writeFileSync(new URL('./legacy-bearer-typescript.json',import.meta.url),JSON.stringify(value,null,2)+'\n');
