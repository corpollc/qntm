import { QSP1Suite } from '../crypto/qsp1.js';
import { withLocalCharterInfo } from '../charter-info/index.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { keyIDFromPublicKey, validateIdentity, generateMessageID, uint8ArrayEquals } from '../identity/index.js';
import { PROTOCOL_VERSION, DEFAULT_SUITE, PROTO_PREFIX, DEFAULT_TTL_SECONDS, DEFAULT_HANDSHAKE_TTL_SECONDS } from '../constants.js';
import type {
  Identity, Conversation, OuterEnvelope, InnerPayload,
  Message, AADStruct, Signable,
} from '../types.js';

const suite = new QSP1Suite();

export function createMessage(
  senderIdentity: Identity,
  conversation: Conversation,
  bodyType: string,
  body: Uint8Array,
  refs: unknown[] | undefined = undefined,
  ttlSeconds: number = DEFAULT_TTL_SECONDS,
): OuterEnvelope {
  validateIdentity(senderIdentity);

  const msgID = generateMessageID();
  const now = Math.floor(Date.now() / 1000);
  const expiryTS = now + ttlSeconds;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0 || !Number.isSafeInteger(expiryTS)) {
    throw new Error('message TTL must be a positive safe integer within the timestamp range');
  }

  // QSP v1.2 membership authority is bound inside the signed body, too.
  // Legacy verifiers hash this additional field as part of the ordinary body.
  if (conversation.type === 'group' && ['group_genesis','group_add','group_remove','group_rekey'].includes(bodyType)) {
    const control = unmarshalCanonical<Record<string, unknown>>(body);
    body = marshalCanonical({...control, group_epoch: conversation.currentEpoch});
  }

  // Create body structure for hashing
  const bodyStruct: Record<string, unknown> = {
    body_type: bodyType,
    body,
  };
  if (refs && refs.length > 0) {
    bodyStruct.refs = refs;
  }

  const bodyStructBytes = marshalCanonical(bodyStruct);
  const bodyHash = suite.hash(bodyStructBytes);

  // Create signable structure
  const signable: Record<string, unknown> = {
    proto: PROTO_PREFIX,
    suite: DEFAULT_SUITE,
    conv_id: conversation.id,
    msg_id: msgID,
    created_ts: now,
    expiry_ts: expiryTS,
    sender_kid: senderIdentity.keyID,
    body_hash: bodyHash,
  };

  const signableBytes = marshalCanonical(signable);
  const signature = suite.sign(senderIdentity.privateKey, signableBytes);

  // Create inner payload
  const innerPayload: Record<string, unknown> = {
    sender_ik_pk: senderIdentity.publicKey,
    sender_kid: senderIdentity.keyID,
    body_type: bodyType,
    body,
    sig_alg: 'Ed25519',
    signature,
  };
  if (refs && refs.length > 0) {
    innerPayload.refs = refs;
  }

  const innerPayloadBytes = marshalCanonical(innerPayload);

  // Create AAD structure
  const aadStruct: Record<string, unknown> = {
    v: PROTOCOL_VERSION,
    suite: DEFAULT_SUITE,
    conv_id: conversation.id,
    msg_id: msgID,
    created_ts: now,
    expiry_ts: expiryTS,
    conv_epoch: conversation.currentEpoch,
  };

  const aadBytes = marshalCanonical(aadStruct);

  // Derive nonce and encrypt
  const nonce = suite.deriveNonce(conversation.keys.nonceKey, msgID);
  const ciphertext = suite.encrypt(conversation.keys.aeadKey, nonce, innerPayloadBytes, aadBytes);
  const aadHash = suite.hash(aadBytes);

  return {
    v: PROTOCOL_VERSION,
    suite: DEFAULT_SUITE,
    conv_id: conversation.id,
    msg_id: msgID,
    created_ts: now,
    expiry_ts: expiryTS,
    conv_epoch: conversation.currentEpoch,
    ciphertext,
    aad_hash: aadHash,
  };
}

export interface DecryptMessageOptions {
  /** Verify saved history after expiry. Never use for live receive or action authorization. */
  allowExpired?: boolean;
}

export function decryptMessage(
  envelope: OuterEnvelope,
  conversation: Conversation,
  options: DecryptMessageOptions = {},
): Message {
  validateEnvelope(envelope);

  // Check expiry
  if (options.allowExpired !== true && checkExpiry(envelope)) {
    throw new Error('message has expired');
  }

  // Check conversation ID matches
  if (!uint8ArrayEquals(envelope.conv_id, conversation.id)) {
    throw new Error('conversation ID mismatch');
  }

  // Reconstruct AAD
  const aadStruct: Record<string, unknown> = {
    v: envelope.v,
    suite: envelope.suite,
    conv_id: envelope.conv_id,
    msg_id: envelope.msg_id,
    created_ts: envelope.created_ts,
    expiry_ts: envelope.expiry_ts,
    conv_epoch: envelope.conv_epoch,
  };

  const aadBytes = marshalCanonical(aadStruct);

  // Verify AAD hash if present
  if (envelope.aad_hash && envelope.aad_hash.length > 0) {
    const computedAADHash = suite.hash(aadBytes);
    if (!uint8ArrayEquals(envelope.aad_hash, computedAADHash)) {
      throw new Error('AAD hash mismatch');
    }
  }

  // Derive nonce and decrypt
  const nonce = suite.deriveNonce(conversation.keys.nonceKey, envelope.msg_id);
  const innerPayloadBytes = suite.decrypt(conversation.keys.aeadKey, nonce, envelope.ciphertext, aadBytes);

  // Deserialize inner payload
  const inner = unmarshalCanonical<InnerPayload>(innerPayloadBytes);
  validateInnerPayload(inner);

  // Verify signature
  const verified = verifyMessageSignature(envelope, inner);
  if (!verified) {
    throw new Error('invalid message signature');
  }

  // Verify sender key ID matches public key
  const computedKID = keyIDFromPublicKey(inner.sender_ik_pk);
  if (!uint8ArrayEquals(inner.sender_kid, computedKID)) {
    throw new Error('sender key ID does not match public key');
  }

  return withLocalCharterInfo({
    envelope,
    inner,
    verified,
  });
}

export function verifyMessageSignature(
  envelope: OuterEnvelope,
  innerPayload: InnerPayload,
): boolean {
  // Reconstruct body structure for hashing
  const bodyStruct: Record<string, unknown> = {
    body_type: innerPayload.body_type,
    body: innerPayload.body,
  };
  if (innerPayload.refs && innerPayload.refs.length > 0) {
    bodyStruct.refs = innerPayload.refs;
  }

  const bodyStructBytes = marshalCanonical(bodyStruct);
  const bodyHash = suite.hash(bodyStructBytes);

  // Reconstruct signable
  const signable: Record<string, unknown> = {
    proto: PROTO_PREFIX,
    suite: envelope.suite,
    conv_id: envelope.conv_id,
    msg_id: envelope.msg_id,
    created_ts: envelope.created_ts,
    expiry_ts: envelope.expiry_ts,
    sender_kid: innerPayload.sender_kid,
    body_hash: bodyHash,
  };

  const signableBytes = marshalCanonical(signable);
  return suite.verify(innerPayload.sender_ik_pk, signableBytes, innerPayload.signature);
}

const MAX_CIPHERTEXT_BYTES = 65536;

export function validateEnvelope(envelope: OuterEnvelope): void {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('invalid message envelope');
  }
  if (envelope.v !== PROTOCOL_VERSION) {
    throw new Error(`unsupported protocol version: ${envelope.v}`);
  }
  if (envelope.suite !== DEFAULT_SUITE) {
    throw new Error(`unsupported crypto suite: ${envelope.suite}`);
  }
  if (!(envelope.conv_id instanceof Uint8Array) || envelope.conv_id.length !== 16) {
    throw new Error('invalid conversation ID: expected 16-byte Uint8Array');
  }
  if (!(envelope.msg_id instanceof Uint8Array) || envelope.msg_id.length !== 16) {
    throw new Error('invalid message ID: expected 16-byte Uint8Array');
  }
  if (typeof envelope.conv_epoch !== 'number' || !Number.isSafeInteger(envelope.conv_epoch) || envelope.conv_epoch < 0) {
    throw new Error(`invalid conversation epoch: ${envelope.conv_epoch}`);
  }
  if (typeof envelope.created_ts !== 'number' || !Number.isSafeInteger(envelope.created_ts) || envelope.created_ts <= 0) {
    throw new Error(`invalid created timestamp: ${envelope.created_ts}`);
  }
  if (typeof envelope.expiry_ts !== 'number' || !Number.isSafeInteger(envelope.expiry_ts) || envelope.expiry_ts <= envelope.created_ts) {
    throw new Error('expiry timestamp must be after created timestamp');
  }
  if (!(envelope.ciphertext instanceof Uint8Array)) {
    throw new Error('invalid ciphertext: expected Uint8Array');
  }
  if (envelope.ciphertext.length === 0) {
    throw new Error('ciphertext is empty');
  }
  if (envelope.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new Error(`ciphertext exceeds maximum size (${MAX_CIPHERTEXT_BYTES} bytes)`);
  }
  if (envelope.aad_hash !== undefined) {
    if (!(envelope.aad_hash instanceof Uint8Array) || envelope.aad_hash.length !== 32) {
      throw new Error('invalid aad_hash: expected 32-byte Uint8Array');
    }
  }

  const maxFutureSkew = 600; // 10 minutes
  if (envelope.created_ts > Math.floor(Date.now() / 1000) + maxFutureSkew) {
    throw new Error('message created timestamp is too far in the future');
  }
}

export function validateInnerPayload(inner: InnerPayload): void {
  if (!inner || typeof inner !== 'object' || Array.isArray(inner)) {
    throw new Error('invalid inner payload');
  }
  const maybeMsgId = (inner as unknown as Record<string, unknown>).msg_id;
  if (maybeMsgId !== undefined && (!(maybeMsgId instanceof Uint8Array) || maybeMsgId.length !== 16)) {
    throw new Error('invalid inner message ID: expected 16-byte Uint8Array');
  }
  if (!(inner.sender_ik_pk instanceof Uint8Array)) {
    throw new Error('invalid sender public key: expected Uint8Array');
  }
  if (inner.sender_ik_pk.length !== 32) {
    throw new Error(`invalid sender public key length: ${inner.sender_ik_pk.length}`);
  }
  if (!(inner.sender_kid instanceof Uint8Array) || inner.sender_kid.length !== 16) {
    throw new Error('invalid sender key ID: expected 16-byte Uint8Array');
  }
  if (inner.sig_alg !== 'Ed25519') {
    throw new Error(`unsupported signature algorithm: ${inner.sig_alg}`);
  }
  if (!(inner.signature instanceof Uint8Array)) {
    throw new Error('invalid signature: expected Uint8Array');
  }
  if (inner.signature.length !== 64) {
    throw new Error(`invalid signature length: ${inner.signature.length}`);
  }
  if (typeof inner.body_type !== 'string' || !inner.body_type) {
    throw new Error('body type is empty');
  }
  if (!(inner.body instanceof Uint8Array)) {
    throw new Error('invalid message body: expected Uint8Array');
  }
  if (inner.refs !== undefined && !Array.isArray(inner.refs)) {
    throw new Error('invalid message refs: expected array');
  }
}

export function serializeEnvelope(envelope: OuterEnvelope): Uint8Array {
  return marshalCanonical(envelope);
}

export function deserializeEnvelope(data: Uint8Array): OuterEnvelope {
  const envelope = unmarshalCanonical<OuterEnvelope>(data);
  validateEnvelope(envelope);
  return envelope;
}

export function checkExpiry(envelope: OuterEnvelope): boolean {
  return Math.floor(Date.now() / 1000) > envelope.expiry_ts;
}

export function defaultTTL(): number {
  return DEFAULT_TTL_SECONDS;
}

export function defaultHandshakeTTL(): number {
  return DEFAULT_HANDSHAKE_TTL_SECONDS;
}
