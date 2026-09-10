import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { generateIdentity, createInvite, createConversation, deriveConversationKeys, createMessage,
  decryptMessage, deserializeEnvelope, serializeEnvelope, inviteFromURL, QSP1Suite,
  prepareAttachment, parseAttachment, assembleAttachment, uploadAttachment, downloadAttachment,
  MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_PARTS, ATTACHMENT_PART_BYTES } from '../src/index.js';
const bytes = (n:number) => Uint8Array.from({length:n},(_,i)=>i%251);
const utf8 = (value:unknown) => new TextEncoder().encode(JSON.stringify(value));
const unhex = (s:string) => Uint8Array.from(s.match(/../g)!,byte=>parseInt(byte,16));
function sample(size=70000) {
  const identity=generateIdentity();const invite=createInvite(identity,'group');
  const parent=createConversation(invite,deriveConversationKeys(invite));const data=bytes(size);
  const context={conversationId:parent.id,epoch:parent.currentEpoch,senderPublicKey:identity.publicKey};
  return {identity,parent,data,context,prepared:prepareAttachment(identity,parent,data,'review.pdf','application/pdf')};
}
describe('Canonical qntm attachments',()=>{
  it('reassembles exact bytes from unordered relay parts, ignores duplicates, and fits relay limits',()=>{
    const {prepared,data,context}=sample();
    expect(prepared.envelopes.length).toBe(3);
    expect(prepared.envelopes.every(wire=>wire.length<65536)).toBe(true);
    expect(assembleAttachment(prepared.body,context,[...prepared.envelopes].reverse().concat(prepared.envelopes[0]))).toEqual(data);
    expect(JSON.stringify(prepared.descriptor).includes('relay')).toBe(false);
  });
  it('supports empty files and rejects oversized files before encryption',()=>{
    const empty=sample(0);expect(assembleAttachment(empty.prepared.body,empty.context,empty.prepared.envelopes)).toEqual(new Uint8Array());
    expect(()=>prepareAttachment(empty.identity,empty.parent,new Uint8Array(MAX_ATTACHMENT_BYTES+1),'big.pdf')).toThrow(/8 MiB/);
  });
  it('binds sender, conversation and epoch to authenticated parent context',()=>{
    const {prepared,context}=sample();
    expect(()=>parseAttachment(prepared.body,{...context,senderPublicKey:generateIdentity().publicKey})).toThrow(/sender/);
    expect(()=>parseAttachment(prepared.body,{...context,epoch:context.epoch+1})).toThrow(/epoch/);
    expect(()=>parseAttachment(prepared.body,{...context,conversationId:bytes(16)})).toThrow(/conversation/);
  });
  it('rejects truncated parts, modified ciphertext, hash mismatch and expired references',()=>{
    const {prepared,context}=sample();
    expect(()=>assembleAttachment(prepared.body,context,prepared.envelopes.slice(1))).toThrow(/missing/);
    const corrupt=prepared.envelopes.map(w=>new Uint8Array(w));corrupt[0][corrupt[0].length-25]^=1;
    expect(()=>assembleAttachment(prepared.body,context,corrupt)).toThrow();
    const descriptor=JSON.parse(new TextDecoder().decode(prepared.body));descriptor.sha256='0'.repeat(64);
    expect(()=>assembleAttachment(utf8(descriptor),context,prepared.envelopes)).toThrow(/SHA-256/);
    descriptor.expires_ts=1;expect(()=>assembleAttachment(utf8(descriptor),context,prepared.envelopes)).toThrow(/expired/);
    expect(()=>assembleAttachment(prepared.body,context,Array(MAX_ATTACHMENT_PARTS*2+1).fill(prepared.envelopes[0]))).toThrow(/limit/);
    expect(()=>assembleAttachment(prepared.body,context,[new Uint8Array(65537)])).toThrow(/limit/);
  });
  it('rejects unsafe filenames, unknown fields, duplicate IDs and inconsistent sizes',()=>{
    const {prepared,context}=sample();
    for(const edit of [
      (d:any)=>d.name='../x.pdf', (d:any)=>d.name='a\n.pdf', (d:any)=>d.extra=true,
      (d:any)=>d.parts[1].message_id=d.parts[0].message_id, (d:any)=>d.size=1,
      (d:any)=>d.media_type='text/html;script', (d:any)=>d.parts.push(d.parts[0]),
    ]) {const d=structuredClone(prepared.descriptor);edit(d);expect(()=>parseAttachment(utf8(d),context)).toThrow();}
  });
  it('validates authenticated part order even if a sender changes the manifest wire hashes',()=>{
    const {prepared,context}=sample();const d=structuredClone(prepared.descriptor);d.parts.reverse();
    expect(()=>assembleAttachment(utf8(d),context,prepared.envelopes)).toThrow(/order/);
  });
  it('uses existing QSP key rotation to exclude former members from future attachment descriptors',()=>{
    const {identity,parent,prepared}=sample();const old={...parent,keys:{...parent.keys}};
    const suite=new QSP1Suite();const root=suite.generateGroupKey();
    const future={...parent,currentEpoch:1,keys:{root,...suite.deriveEpochKeys(root,parent.id,1)}};
    const newFile=prepareAttachment(identity,future,bytes(500),'next.pdf','application/pdf');
    const envelope=createMessage(identity,future,'blobref',newFile.body);
    expect(()=>decryptMessage(envelope,old)).toThrow();
    const verified=decryptMessage(envelope,future);
    expect(parseAttachment(verified.inner.body,{conversationId:future.id,epoch:1,senderPublicKey:verified.inner.sender_ik_pk}).name).toBe('next.pdf');
    expect(prepared.descriptor.invite_token).not.toBe(newFile.descriptor.invite_token);
  });
  it('retries exact encrypted parts after a partial upload and downloads without a document URL',async()=>{
    const {prepared,data,context}=sample();const sent:Uint8Array[]=[];let fail=true;
    const transport={postMessage:async (_channel:Uint8Array,wire:Uint8Array)=>{sent.push(wire);if(fail&&sent.length===2)throw new Error('offline');},
      receiveMessages:async (_channel:Uint8Array,from=0,max=0,timeout=0)=>{expect(from).toBe(0);expect(max).toBe(512);expect(timeout).toBe(30000);return {messages:prepared.envelopes};}};
    await expect(uploadAttachment(transport,prepared,context)).rejects.toThrow('offline');
    fail=false;await uploadAttachment(transport,prepared,context);
    expect(sent[0]).toEqual(sent[2]);expect(sent[1]).toEqual(sent[3]);
    expect(await downloadAttachment(transport,prepared.body,context)).toEqual(data);
  });
  it('creates maximum-size manifests within the descriptor and envelope limits',()=>{
    const {prepared,parent,identity}=sample(MAX_ATTACHMENT_BYTES);
    expect(prepared.envelopes.length).toBe(MAX_ATTACHMENT_PARTS);
    expect(prepared.body.length).toBeLessThan(48*1024);
    expect(serializeEnvelope(createMessage(identity,parent,'blobref',prepared.body)).length).toBeLessThan(65536);
  }, 30000);
});

const pythonFixture=fileURLToPath(new URL('./attachment-python.json',import.meta.url));
it('decrypts a real Python-produced parent and multi-part file exactly',()=>{
  const f=JSON.parse(readFileSync(pythonFixture,'utf8'));
  const invite=inviteFromURL(f.parent_invite_token);const parent=createConversation(invite,deriveConversationKeys(invite));
  const envelope=deserializeEnvelope(Uint8Array.from(Buffer.from(f.parent_envelope_b64,'base64')));
  const verified=decryptMessage(envelope,parent);
  const data=assembleAttachment(verified.inner.body,{conversationId:envelope.conv_id,epoch:envelope.conv_epoch,senderPublicKey:verified.inner.sender_ik_pk},f.parts_b64.map((p:string)=>Uint8Array.from(Buffer.from(p,'base64'))));
  expect(data).toEqual(Uint8Array.from(Buffer.from(f.plaintext_b64,'base64')));
});
