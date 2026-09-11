/** Participant-held attachments over ordinary QSP relay envelopes. See docs/attachments.md. */
import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { createInvite, inviteToToken, inviteFromURL, createConversation, deriveConversationKeys } from '../invite/index.js';
import { createMessage, decryptMessage, serializeEnvelope, deserializeEnvelope, defaultTTL } from '../message/index.js';
import { uint8ArrayEquals } from '../identity/index.js';
import type { Conversation, Identity } from '../types.js';

export const ATTACHMENT_TYPE = 'qntm.attachment.v1';
export const ATTACHMENT_PART_BYTES = 32768;
export const MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024;
export const MAX_ATTACHMENT_PARTS = MAX_ATTACHMENT_BYTES / ATTACHMENT_PART_BYTES;
export const MAX_ATTACHMENT_DESCRIPTOR_BYTES = 48 * 1024;
const suite = new QSP1Suite();
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
function fail(message = 'Invalid attachment descriptor'): never { throw new Error(message); }
function record(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail();
}
function integer(value: unknown, low: number, high: number): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < low || (value as number) > high) fail();
}
function hexString(value: unknown, length: number): asserts value is string {
  if (typeof value !== 'string' || !new RegExp(`^[a-f0-9]{${length}}$`).test(value)) fail();
}
function label(value: unknown, max: number): asserts value is string {
  if (typeof value !== 'string' || !value.trim() || encoder.encode(value).length > max || /[\u0000-\u001f\u007f]/.test(value)) fail();
}
export interface AttachmentContext { conversationId: Uint8Array; epoch: number; senderPublicKey: Uint8Array }
export interface AttachmentDescriptor {
  type: typeof ATTACHMENT_TYPE;
  name: string;
  media_type: string;
  size: number;
  sha256: string;
  parent_conv_id: string;
  parent_epoch: number;
  invite_token: string;
  expires_ts: number;
  parts: {message_id: string; sha256: string}[];
}
export interface PreparedAttachment { descriptor: AttachmentDescriptor; body: Uint8Array; envelopes: Uint8Array[] }
export interface AttachmentTransport {
  postMessage(conversationId: Uint8Array, envelope: Uint8Array): Promise<unknown>;
  receiveMessages(conversationId: Uint8Array, fromSequence?: number, maxMessages?: number, timeoutMs?: number): Promise<{messages: Uint8Array[]}>;
}

/** Context MUST come from the authenticated parent QSP envelope and verified sender. */
export function parseAttachment(body: Uint8Array, context: AttachmentContext): AttachmentDescriptor {
  if (!(body instanceof Uint8Array) || body.length > MAX_ATTACHMENT_DESCRIPTOR_BYTES) fail();
  let value: unknown;
  try { value = JSON.parse(decoder.decode(body)); } catch { return fail(); }
  record(value, ['type','name','media_type','size','sha256','parent_conv_id','parent_epoch','invite_token','expires_ts','parts']);
  if (value.type !== ATTACHMENT_TYPE) fail('Unsupported attachment format');
  label(value.name,255); if (/[\\/]/.test(value.name) || value.name === '.' || value.name === '..') fail('Invalid attachment filename');
  label(value.media_type,120); if (!/^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/.test(value.media_type)) fail('Invalid attachment media type');
  integer(value.size,0,MAX_ATTACHMENT_BYTES); hexString(value.sha256,64); hexString(value.parent_conv_id,32);
  integer(value.parent_epoch,0,0xffffffff); integer(value.expires_ts,1,Number.MAX_SAFE_INTEGER);
  if (context.conversationId.length !== 16 || context.senderPublicKey.length !== 32 || value.parent_conv_id !== hex(context.conversationId) || value.parent_epoch !== context.epoch) fail('Attachment belongs to a different conversation or epoch');
  if (typeof value.invite_token !== 'string' || value.invite_token.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(value.invite_token)) fail();
  const invite = inviteFromURL(value.invite_token);
  if (invite.type !== 'direct' || invite.conv_id.length !== 16 || !uint8ArrayEquals(invite.inviter_ik_pk, context.senderPublicKey) || uint8ArrayEquals(invite.conv_id,context.conversationId)) fail('Attachment sender or channel mismatch');
  if (!Array.isArray(value.parts) || value.parts.length !== Math.max(1,Math.ceil(value.size / ATTACHMENT_PART_BYTES)) || value.parts.length > MAX_ATTACHMENT_PARTS) fail('Invalid attachment part count');
  const ids = new Set<string>();
  for (const part of value.parts) {
    record(part,['message_id','sha256']); hexString(part.message_id,32); hexString(part.sha256,64);
    if (ids.has(part.message_id)) fail('Duplicate attachment part'); ids.add(part.message_id);
  }
  return value as unknown as AttachmentDescriptor;
}

/** Encrypt/sign all bytes offline. Persist the exact result before the first network write. */
export function prepareAttachment(identity: Identity, parent: Conversation, bytes: Uint8Array, name: string, mediaType = 'application/octet-stream'): PreparedAttachment {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_ATTACHMENT_BYTES) fail('Attachments are limited to 8 MiB');
  const invite = createInvite(identity,'direct');
  const conversation = createConversation(invite,deriveConversationKeys(invite));
  const envelopes: Uint8Array[] = [];
  const parts: AttachmentDescriptor['parts'] = [];
  let expiry = Number.MAX_SAFE_INTEGER;
  for (let index = 0; index < Math.max(1,Math.ceil(bytes.length/ATTACHMENT_PART_BYTES)); index++) {
    const body = marshalCanonical({v:1,index,data:bytes.slice(index*ATTACHMENT_PART_BYTES,(index+1)*ATTACHMENT_PART_BYTES)});
    const envelope = createMessage(identity,conversation,'blob.part',body,undefined,defaultTTL());
    const wire = serializeEnvelope(envelope);
    envelopes.push(wire); parts.push({message_id:hex(envelope.msg_id),sha256:hex(suite.hash(wire))});
    expiry = Math.min(expiry,envelope.expiry_ts);
  }
  const descriptor: AttachmentDescriptor = {type:ATTACHMENT_TYPE,name,media_type:mediaType,size:bytes.length,sha256:hex(suite.hash(bytes)),parent_conv_id:hex(parent.id),parent_epoch:parent.currentEpoch,invite_token:inviteToToken(invite),expires_ts:expiry,parts};
  const body = encoder.encode(JSON.stringify(descriptor));
  parseAttachment(body,{conversationId:parent.id,epoch:parent.currentEpoch,senderPublicKey:identity.publicKey});
  return {descriptor,body,envelopes};
}

/** Reassemble only the exact signed parts referenced by a verified parent message. */
export function assembleAttachment(body: Uint8Array, context: AttachmentContext, envelopes: Uint8Array[]): Uint8Array {
  const descriptor = parseAttachment(body,context);
  if (Math.floor(Date.now()/1000) > descriptor.expires_ts) fail('Attachment has expired; ask its sender to resend it');
  if (envelopes.length > MAX_ATTACHMENT_PARTS*2) fail('Attachment replay exceeds the message limit');
  const invite = inviteFromURL(descriptor.invite_token);
  const conversation = createConversation(invite,deriveConversationKeys(invite));
  const byHash = new Map<string,Uint8Array>();
  for (const wire of envelopes) {
    if (!(wire instanceof Uint8Array) || wire.length > 65536) fail('Attachment envelope exceeds the size limit');
    byHash.set(hex(suite.hash(wire)),wire);
  }
  const result = new Uint8Array(descriptor.size);
  let minimumExpiry = Number.MAX_SAFE_INTEGER;
  for (const [index,part] of descriptor.parts.entries()) {
    const wire = byHash.get(part.sha256);
    if (!wire) fail('Attachment parts are missing or expired; ask its sender to resend it');
    const envelope = deserializeEnvelope(wire);
    if (hex(envelope.msg_id) !== part.message_id || envelope.conv_epoch !== 0 || envelope.expiry_ts < descriptor.expires_ts) fail('Attachment part identity mismatch');
    minimumExpiry = Math.min(minimumExpiry,envelope.expiry_ts);
    const message = decryptMessage(envelope,conversation);
    if (message.inner.body_type !== 'blob.part' || !uint8ArrayEquals(message.inner.sender_ik_pk,context.senderPublicKey)) fail('Attachment part sender mismatch');
    const payload = unmarshalCanonical<unknown>(message.inner.body);
    record(payload,['v','index','data']);
    const expected = Math.min(ATTACHMENT_PART_BYTES,descriptor.size-index*ATTACHMENT_PART_BYTES);
    if (payload.v !== 1 || payload.index !== index || !(payload.data instanceof Uint8Array) || payload.data.length !== expected) fail('Attachment part order or size mismatch');
    result.set(payload.data,index*ATTACHMENT_PART_BYTES);
  }
  if (minimumExpiry !== descriptor.expires_ts) fail('Attachment expiry does not match its signed parts');
  if (hex(suite.hash(result)) !== descriptor.sha256) fail('Attachment SHA-256 verification failed');
  return result;
}

/** Retries reuse exact envelopes. Publish the parent blobref only after this succeeds. */
export async function uploadAttachment(transport: AttachmentTransport, prepared: PreparedAttachment, context: AttachmentContext, progress?: (sent:number,total:number)=>void): Promise<void> {
  assembleAttachment(prepared.body,context,prepared.envelopes);
  const descriptor = parseAttachment(prepared.body,context);
  const channel = inviteFromURL(descriptor.invite_token).conv_id;
  // Match each manifest hash explicitly so duplicate or reordered input cannot skip a part.
  const wires = new Map(prepared.envelopes.map(wire=>[hex(suite.hash(wire)),wire]));
  for (const [index,part] of descriptor.parts.entries()) {
    await transport.postMessage(channel,wires.get(part.sha256)!);
    progress?.(index+1,descriptor.parts.length);
  }
}

/** The relay comes from the participant's conversation configuration, never a document URL. */
export async function downloadAttachment(transport: AttachmentTransport, body: Uint8Array, context: AttachmentContext): Promise<Uint8Array> {
  const descriptor = parseAttachment(body,context);
  if (Math.floor(Date.now()/1000) > descriptor.expires_ts) fail('Attachment has expired; ask its sender to resend it');
  const result = await transport.receiveMessages(inviteFromURL(descriptor.invite_token).conv_id,0,MAX_ATTACHMENT_PARTS*2,30000);
  return assembleAttachment(body,context,result.messages);
}
