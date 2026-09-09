import { beforeAll,afterAll,describe,it,expect } from 'vitest';
import { execFileSync,spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { mkdtempSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { generateIdentity } from '../src/identity/index.js';
import { createCharter,createCharterStatement,signCharterStatement,charterKey,charterAgentId,CharterRegistryClient,CharterRegistryError,verifyCharterHeads,verifyCharterInclusion,verifyCharterConsistency,verifyCharterChainResponse,auditCharterSnapshot } from '../src/charter/index.js';
import type { CharterTrust,CharterHeads,CharterStatement,CharterInclusion,CharterChainResponse } from '../src/charter/index.js';

const registry='interop.registry';
const directory=mkdtempSync(join(tmpdir(),'qntm-charter-interop-'));
const binary=join(directory,'registrar');
let process:ChildProcess,base:string,client:CharterRegistryClient,trust:CharterTrust;
const clone=<T>(x:T):T=>JSON.parse(JSON.stringify(x));
async function start() {
  process=spawn(binary,['--listen','127.0.0.1:0','--data-dir',directory,'--registry',registry],{stdio:['ignore','pipe','pipe']});
  const info=await new Promise<{listen:string;registrar:CharterTrust['registrar']}>((resolve,reject)=>{
    let output='',errors='';const timer=setTimeout(()=>reject(new Error(`registrar startup timed out: ${errors}`)),15_000);
    process.stderr!.on('data',data=>{errors+=data});
    process.once('error',err=>{clearTimeout(timer);reject(err)});
    process.once('exit',code=>{clearTimeout(timer);reject(new Error(`registrar exited ${code}: ${errors}`))});
    process.stdout!.on('data',data=>{output+=data;if(output.includes('\n')){clearTimeout(timer);try{resolve(JSON.parse(output.split('\n')[0]))}catch(err){reject(err)}}});
  });
  base=`http://${info.listen}`;
  if(trust) expect(info.registrar).toEqual(trust.registrar);
  trust={registry,registrar:info.registrar};client=new CharterRegistryClient(base,trust);
}
async function stop(signal:NodeJS.Signals='SIGTERM') {
  if(process?.exitCode===null && process.signalCode===null) {const exited=once(process,'exit');process.kill(signal);await exited;}
}
beforeAll(async()=>{
  execFileSync('go',['build','-o',binary,'./cmd/charter-registry'],{cwd:fileURLToPath(new URL('../../charter-registry',import.meta.url)),stdio:'pipe',timeout:60_000});
  await start();
});
afterAll(async()=>{await stop();rmSync(directory,{recursive:true,force:true});});

describe('TypeScript client against the Go registrar',()=>{
  it('publishes, proves, audits, rejects forks, and survives an abrupt restart',async()=>{
    const empty=await client.heads();expect(empty.log.signed.tree_size).toBe(0);
    expect((await client.chain('0'.repeat(32))).record).toBeNull();
    const parent=generateIdentity(),agents=Array.from({length:3},()=>generateIdentity());
    const chains:CharterStatement[][]=[];
    for(const agent of agents) {
      const charter=signCharterStatement(createCharter({registry,agent,governance:{keys:[charterKey(parent.publicKey)],threshold:1},agentRights:['statement','liveness.update'],extensions:{'studio.example':{preferences:['music','🎨'],optional:null,numbers:[1e-7,333333333.33333329]}}}),parent);
      chains.push([charter]);const receipt=await client.submit(charter);expect(receipt.index).toBe(chains.length-1);
    }
    for(let turn=0;turn<2;turn++) for(let i=0;i<agents.length;i++) {
      const chain=chains[i],prev=chain.at(-1)!;
      const statement=signCharterStatement(createCharterStatement(prev,'statement',{namespace:'unregistered/experiment',data:{'10':10,'2':2,turn,governance:null}}),agents[i]);
      await client.submit(statement);chain.push(statement);
    }
    const heads=await client.heads();expect(heads.log.signed.tree_size).toBe(9);
    const entries=await client.log(heads);auditCharterSnapshot(entries,heads,trust);
    const tampered=clone(entries);tampered[0].received_at='2020-01-01T00:00:00Z';expect(()=>auditCharterSnapshot(tampered,heads,trust)).toThrow();
    const allHeads:CharterHeads[]=[];
    for(let size=0;size<=9;size++) {
      const head=await client.heads(size);allHeads.push(head);
      for(let index=0;index<size;index++) {
        const response=await fetch(`${base}/v1/inclusion/${index}?size=${size}`);const value=await response.json() as {heads:CharterHeads;inclusion:CharterInclusion};
        verifyCharterHeads(value.heads,trust);verifyCharterInclusion(value.inclusion,head.log.signed);
        const bad=clone(value.inclusion);bad.index=size;expect(()=>verifyCharterInclusion(bad,head.log.signed)).toThrow();
        bad.index=index;bad.siblings.push('0'.repeat(64));expect(()=>verifyCharterInclusion(bad,head.log.signed)).toThrow();
      }
      for(const agent of agents) {
        const result=await client.chain(charterAgentId(agent.publicKey),size);
        if(result.record) expect(result.record.governance!.keys).toEqual([charterKey(parent.publicKey)]);
      }
      for(const absent of ['0'.repeat(32),'f'.repeat(32),charterAgentId(parent.publicKey)]) expect((await client.chain(absent,size)).record).toBeNull();
    }
    for(let from=0;from<=9;from++) for(let to=from;to<=9;to++) {
      const proof=await client.consistency(allHeads[from],allHeads[to]);
      if(proof.length) {const bad=[...proof];bad[0]='0'.repeat(64);expect(()=>verifyCharterConsistency(allHeads[from].log.signed,allHeads[to].log.signed,bad)).toThrow();}
    }
    const agentId=charterAgentId(agents[0].publicKey),complete=await client.chain(agentId);
    const truncated=clone(complete.evidence);truncated.chain.pop();expect(()=>verifyCharterChainResponse(truncated,trust,agentId)).toThrow(/Incomplete/);
    const hidden=clone(complete.evidence);hidden.proof.present=false;hidden.chain=[];expect(()=>verifyCharterChainResponse(hidden,trust,agentId)).toThrow(/non-membership/);
    const wrongTrust={registry,registrar:charterKey(generateIdentity().publicKey)};expect(()=>verifyCharterHeads(heads,wrongTrust)).toThrow();
    const wrongAudience={...trust,registry:'other.registry'};expect(()=>verifyCharterHeads(heads,wrongAudience)).toThrow();
    await expect(client.submit(chains[0][0])).rejects.toMatchObject({status:409,code:'sequence_conflict'});
    const previous=chains[0].at(-1)!;
    const attack=signCharterStatement(createCharterStatement(previous,'governance.rotate',{governance:{keys:[charterKey(agents[0].publicKey)],threshold:1}}),agents[0]);
    await expect(client.submit(attack)).rejects.toMatchObject({status:422,code:'authority_rejected'});
    const candidates=['one','two'].map(data=>signCharterStatement(createCharterStatement(previous,'statement',{namespace:'concurrent',data}),agents[0]));
    const results=await Promise.allSettled(candidates.map(s=>client.submit(s)));
    expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
    const rejected=results.find(r=>r.status==='rejected') as PromiseRejectedResult;expect(rejected.reason).toBeInstanceOf(CharterRegistryError);
    const before=await client.heads();await stop('SIGKILL');await start();expect(await client.heads()).toEqual(before);
    const after=await client.chain(agentId);expect(after.record!.sequence).toBe(3);expect(after.record!.statements).toHaveLength(3);
    await client.consistency(heads,before);auditCharterSnapshot(await client.log(before),before,trust);
  });
  it('self-certifies, experiments in a namespace, and enforces a live threshold transition',async()=>{
    const agent=generateIdentity(),second=generateIdentity(),third=generateIdentity();
    const self={keys:[charterKey(agent.publicKey)],threshold:1};
    const charter=createCharter({registry,agent,governance:self,agentRights:['statement'],extensions:{'open.studio':{purpose:'experiment freely'}}});
    await client.submit(charter);
    const experiment=signCharterStatement(createCharterStatement(charter,'statement',{namespace:'open.studio/creative',data:{ideas:['music','robot gardens']}}),agent);
    await client.submit(experiment);
    const shared={keys:[charterKey(agent.publicKey),charterKey(second.publicKey),charterKey(third.publicKey)],threshold:2};
    const rotated=signCharterStatement(createCharterStatement(experiment,'governance.rotate',{governance:shared}),agent);
    await client.submit(rotated);
    const unilateral=signCharterStatement(createCharterStatement(rotated,'governance.rotate',{governance:self}),agent);
    await expect(client.submit(unilateral)).rejects.toMatchObject({status:422,code:'authority_rejected'});
    await client.submit(signCharterStatement(unilateral,second));
    const {record}=await client.chain(charterAgentId(agent.publicKey));
    expect(record!.governance).toEqual(self);
    expect(record!.statements[0]).toMatchObject({namespace:'open.studio/creative',data:{ideas:['music','robot gardens']}});
    const heads=await client.heads();auditCharterSnapshot(await client.log(heads),heads,trust);
  });

  it('rejects insecure remote endpoints and malformed agent paths before sending',async()=>{
    expect(()=>new CharterRegistryClient('http://example.com',trust)).toThrow(/HTTPS/);
    expect(()=>new CharterRegistryClient('https://user:password@example.com',trust)).toThrow(/base URL/);
    await expect(client.chain('../info')).rejects.toThrow(/agent ID/);
  });
});
