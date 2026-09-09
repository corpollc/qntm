import { describe,it,expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateIdentity } from '../src/identity/index.js';
import { canonicalizeCharterJson, parseCharterJson, replayCharterChain, createCharter, createCharterStatement, signCharterStatement, charterKey, charterAgentId, charterGovernanceCommitment, parseCharterStatement } from '../src/charter/index.js';
import type { CharterStatement } from '../src/charter/index.js';
const vectors=JSON.parse(readFileSync(new URL('../../specs/test-vectors/charter-registry-v02.json',import.meta.url),'utf8'));
describe('Charter Registry v0.2 shared vectors',()=>{
  for (const v of vectors.cases) it(v.name,()=>{
    const replay=()=>replayCharterChain(v.chain,{registry:v.registry,agentId:v.agent_id});
    if(v.valid) expect(replay().headHash).toBe(v.head_hash);else expect(replay).toThrow();
  });
  for (const v of vectors.json) it(v.name,()=>{
    const canonical=()=>canonicalizeCharterJson(parseCharterJson(v.input));
    if(v.canonical===null) expect(canonical).toThrow();else expect(canonical()).toBe(v.canonical);
  });
});
describe('charter construction and JSON boundaries',()=>{
  it('preserves experiments without mutating input or interpreting namespace content',()=>{
    const agent=generateIdentity(),governance={keys:[charterKey(agent.publicKey)],threshold:1};
    const extensions=JSON.parse('{"__proto__":{"admin":true},"freeform":[1,null,"music"]}');
    const genesis=createCharter({registry:'local',agent,governance,extensions,agentRights:['statement']});
    extensions.freeform.push('changed');
    const event=signCharterStatement(createCharterStatement(genesis,'statement',{namespace:'__proto__',data:{governance:null}}),agent);
    const state=replayCharterChain([genesis,event],{registry:'local',agentId:charterAgentId(agent.publicKey)});
    expect(state.governance).toEqual(governance);expect(state.charter.extensions!.freeform).toEqual([1,null,'music']);
    expect(state.statements[0].namespace).toBe('__proto__');expect(({} as {admin?:boolean}).admin).toBeUndefined();
  });
  it('commitments include threshold but ignore the order of the key list',()=>{
    const a=charterKey(generateIdentity().publicKey),b=charterKey(generateIdentity().publicKey);
    expect(charterGovernanceCommitment({keys:[a,b],threshold:2})).toBe(charterGovernanceCommitment({keys:[b,a],threshold:2}));
    expect(charterGovernanceCommitment({keys:[a,b],threshold:1})).not.toBe(charterGovernanceCommitment({keys:[a,b],threshold:2}));
  });
  it('signing is immutable and idempotent for the same signer',()=>{
    const agent=generateIdentity(),s=createCharter({registry:'local',agent,governance:null});const before=JSON.stringify(s);
    const signed=signCharterStatement(s,agent);expect(JSON.stringify(s)).toBe(before);expect(signed.signatures).toHaveLength(1);
    expect(parseCharterStatement(JSON.stringify(signed))).toEqual(signed);
  });
  it('rejects non-JSON values and getters without invoking them',()=>{
    let called=false;const accessor={get secret(){called=true;return 'x'}};const cycle:any={};cycle.self=cycle;
    const symbol={a:1,[Symbol('x')]:2};const sparse=new Array(1);
    for(const value of [undefined,NaN,Infinity,1n,new Date(),accessor,cycle,symbol,sparse,{x:undefined},'\ud800']) expect(()=>canonicalizeCharterJson(value)).toThrow();
    expect(called).toBe(false);
  });
  it('rejects excessive JSON nesting',()=>{expect(()=>parseCharterJson('['.repeat(129)+'0'+']'.repeat(129))).toThrow();});
  it('requires explicit expected registry and agent',()=>{
    const s=vectors.cases[0].chain as CharterStatement[];
    expect(()=>replayCharterChain(s,{registry:'test.registry',agentId:'0'.repeat(32)})).toThrow(/audience/);
  });
});
