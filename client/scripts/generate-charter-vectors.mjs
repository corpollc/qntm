// Run after npm run build. Deterministic keys are public test material only.
import { writeFileSync } from 'node:fs';
import { sha512 } from '@noble/hashes/sha512';
import { ed25519 } from '@noble/curves/ed25519';
import { charterAgentId, charterKey, createCharter, createCharterStatement, signCharterStatement, charterGovernanceCommitment, charterStatementHash, charterJsonBytes } from '../dist/charter/index.js';
const registry='test.registry', at='2026-09-08T12:00:00Z';
function identity(byte) { const seed=new Uint8Array(32).fill(byte), publicKey=ed25519.getPublicKey(seed);return {publicKey,privateKey:new Uint8Array([...seed,...publicKey]),keyID:new Uint8Array()}; }
const agent=identity(1), parent=identity(2), other=identity(3), op=identity(4);
const set=(...ids)=>({keys:ids.map(i=>charterKey(i.publicKey)),threshold:ids.length});
const sign=(s,...ids)=>ids.reduce((s,i)=>signCharterStatement(s,i),s);
const make=(governance=set(agent),opts={})=>createCharter({registry,agent,governance,issuedAt:at,...opts});
const next=(head,type,body,...ids)=>sign(createCharterStatement(head,type,body,at),...ids);
const copy=x=>JSON.parse(JSON.stringify(x));
const cases=[];
function add(name,valid,chain,expectedRegistry=registry) { cases.push({name,valid,registry:expectedRegistry,agent_id:charterAgentId(agent.publicKey),chain,head_hash:charterStatementHash(chain.at(-1))}); }
const self=make();add('self-charter',true,[self]);
const child=sign(make(set(parent),{agentRights:['statement','liveness.update'],extensions:{'studio.example':{art:['music',null,{'10':'ten','2':'two'}]},['__proto__']:{}}}),parent);
add('parent-governed child',true,[child]);
add('missing governance acceptance',false,[make(set(parent))]);
const noAgent=copy(child);noAgent.signatures=noAgent.signatures.filter(s=>s.kid!==child.signed.agent_id);add('missing agent signature',false,[noAgent]);
const quorum=sign(make(set(parent,other)),parent,other);add('threshold charter',true,[quorum]);
const insufficient=copy(quorum);insufficient.signatures.pop();add('threshold not met',false,[insufficient]);
const duplicates=copy(quorum);duplicates.signatures.push(duplicates.signatures[1]);add('duplicate signature cannot meet quorum',false,[duplicates]);
const forged=copy(self);forged.signed.body.extensions={experiment:true};add('signature tampering',false,[forged]);
add('cross-registry replay',false,[self],'other.registry');
const info=next(child,'statement',{namespace:'anything/new',data:{governance:set(agent),agent_rights:['governance.rotate'],creative:[null,42,'🎨']},schema:'urn:example:v1'},agent);
add('agent informational statement cannot change authority',true,[child,info]);
add('informational signer cannot elevate',false,[child,info,next(info,'governance.rotate',{governance:set(agent)},agent)]);
add('parent can amend constitution',true,[child,next(child,'constitution.amend',{values:['curiosity','care']},parent)]);
add('agent cannot amend parent-governed constitution',false,[child,next(child,'constitution.amend',null,agent)]);
add('ungranted informational right',false,[self,next(self,'statement',{namespace:'test',data:null},other)]);
add('null experimental data',true,[self,next(self,'statement',{namespace:'test',data:null},agent)]);
add('empty namespace',false,[self,next(self,'statement',{namespace:'',data:{}},agent)]);
add('missing experimental data',false,[self,next(self,'statement',{namespace:'test'},agent)]);
const frozen=make(null,{agentRights:['statement']});add('frozen charter',true,[frozen]);add('frozen means all later writes rejected',false,[frozen,next(frozen,'statement',{namespace:'test',data:null},agent)]);
const rotate=next(child,'governance.rotate',{governance:set(other)},parent);
add('outgoing quorum authorizes rotation',true,[child,rotate]);
add('incoming quorum has authority after rotation',true,[child,rotate,next(rotate,'constitution.amend',['new'],other)]);
add('outgoing key loses authority',false,[child,rotate,next(rotate,'constitution.amend',['old'],parent)]);
const committed=sign(make(set(parent),{nextGovernanceCommitment:charterGovernanceCommitment(set(other))}),parent);
add('committed rotation',true,[committed,next(committed,'governance.rotate',{governance:set(other)},parent)]);
add('rotation commitment mismatch',false,[committed,next(committed,'governance.rotate',{governance:set(agent)},parent)]);
add('precommitment cannot recover lost quorum',false,[committed,next(committed,'governance.rotate',{governance:set(other)},other)]);
const terminal=next(committed,'agent.decommission',{reason:'retired'},parent);add('precommitment does not prevent decommission',true,[committed,terminal]);add('decommission is terminal',false,[committed,terminal,next(terminal,'liveness.update',{},parent)]);
const delegation=next(child,'opkey.delegate',{kid:charterAgentId(op.publicKey),scope:'messaging',expires_at:at},parent);
add('operational delegation and revocation',true,[child,delegation,next(delegation,'opkey.revoke',{kid:charterAgentId(op.publicKey)},parent)]);
add('operational key has no registry authority',false,[child,delegation,next(delegation,'statement',{namespace:'test',data:null},op)]);
add('cannot revoke unknown operational key',false,[child,next(child,'opkey.revoke',{kid:charterAgentId(op.publicKey)},parent)]);
add('successor statement',true,[child,next(child,'agent.successor',{agent_id:charterAgentId(other.publicKey)},parent)]);
add('self succession rejected',false,[self,next(self,'agent.successor',{agent_id:self.signed.agent_id},agent)]);
add('timestamps do not order history',true,[child,sign(createCharterStatement(child,'liveness.update',{status:'here'},'2020-01-01T00:00:00Z'),agent)]);
const gap=copy(info);gap.signed.seq=2;add('sequence gap',false,[child,sign(gap,agent)]);
const fork=copy(info);fork.signed.prev_hash='f'.repeat(64);add('previous hash mismatch',false,[child,sign(fork,agent)]);
add('charter cannot be replaced',false,[self,self]);
const unknown=copy(info);unknown.signed.type='custom.authority';add('unknown core type fails closed',false,[child,sign(unknown,agent)]);
for (const [name,mutate] of [
  ['invalid calendar date',s=>s.signed.issued_at='2026-02-30T00:00:00Z'],
  ['null sequence',s=>s.signed.seq=null],
  ['missing sequence',s=>delete s.signed.seq],
  ['unsafe sequence',s=>s.signed.seq=9007199254740992],
  ['duplicate governor',s=>s.signed.body.governance.keys.push(s.signed.body.governance.keys[0])],
  ['invalid agent right',s=>s.signed.body.agent_rights=['governance.rotate']],
  ['wrong agent public key',s=>s.signed.body.agent_pubkey=charterKey(other.publicKey).pubkey],
  ['zero quorum',s=>s.signed.body.governance.threshold=0],
]) { const s=copy(self);mutate(s);add(name,false,[sign(s,agent)]); }
// Valid signatures must not turn malformed or torsion governance keys into authority.
const torsion = ed25519.ExtendedPoint.fromHex(new Uint8Array(32));
const badKeys = [
  ['identity', ed25519.ExtendedPoint.ZERO.toRawBytes()],
  ['small-order', torsion.toRawBytes()],
  ['mixed torsion', ed25519.ExtendedPoint.BASE.add(torsion).toRawBytes()],
  ['noncanonical', Uint8Array.from([0xee, ...new Array(30).fill(0xff), 0x7f])],
];
for (const [name, publicKey] of badKeys) {
  const s = copy(self);
  s.signed.body.governance.keys.push(charterKey(publicKey));
  add(`reject ${name} governance key`, false, [sign(s, agent)]);
}
// A cofactored equation accepts this signature with mixed-torsion R. The
// charter profile and Go verifier reject it despite an ordinary agent key.
const torsionSignature = copy(self);
const rPoint = ed25519.ExtendedPoint.BASE.add(torsion).toRawBytes();
const msg = charterJsonBytes(torsionSignature.signed);
const fromLE = bytes => BigInt('0x'+Buffer.from(bytes).reverse().toString('hex'));
const challenge = fromLE(sha512(new Uint8Array([...rPoint,...agent.publicKey,...msg]))) % ed25519.CURVE.n;
const scalar = ed25519.utils.getExtendedPublicKey(agent.privateKey.slice(0,32)).scalar;
const sValue = (1n+challenge*scalar)%ed25519.CURVE.n;
const sBytes = Buffer.from(sValue.toString(16).padStart(64,'0'),'hex').reverse();
const signature = new Uint8Array([...rPoint,...sBytes]);
if (!ed25519.verify(signature,msg,agent.publicKey,{zip215:false})) throw new Error('Invalid torsion regression fixture');
torsionSignature.signatures[0].sig = Buffer.from(signature).toString('base64url');
add('reject cofactored-only signature',false,[torsionSignature]);
const json=[
  ...[128,129].map(depth=>({name:`scalar nesting ${depth}`,input:'['.repeat(depth)+'0'+']'.repeat(depth),canonical:depth===128?'['.repeat(depth)+'0'+']'.repeat(depth):null})),
  ...[129,130].map(depth=>({name:`empty nesting ${depth}`,input:'['.repeat(depth)+']'.repeat(depth),canonical:depth===129?'['.repeat(depth)+']'.repeat(depth):null})),
  {name:'UTF-16 and integer key order',input:'{"2":2,"10":10,"\\ue000":1,"😀":2}',canonical:'{"10":10,"2":2,"😀":2,"\ue000":1}'},
  {name:'ECMAScript numbers',input:'[333333333.33333329,1E30,4.50,2e-3,1e-27,-0,1e-6,1e-7]',canonical:'[333333333.3333333,1e+30,4.5,0.002,1e-27,0,0.000001,1e-7]'},
  {name:'Unicode escape and null',input:'{"a":"\\u0061\\ud83d\\ude00","b":null}',canonical:'{"a":"a😀","b":null}'},
  ...['{"a":1,"a":2}','{"a":1,"\\u0061":2}','"\\ud800"','"\\udc00"','"\\ud800\\u0041"','"\\udc00\\ud800"','[1e999]','[1,]','{"a":undefined}'].map((input,i)=>({name:`invalid JSON ${i}`,input,canonical:null})),
];
writeFileSync(new URL('../../specs/test-vectors/charter-registry-v02.json',import.meta.url),JSON.stringify({draft_version:'0.2',cases,json},null,2)+'\n');
console.log(`Wrote ${cases.length} authority and ${json.length} canonicalization vectors`);
