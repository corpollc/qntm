import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { keyIDFromPublicKey, validateIdentity, generateMessageID, uint8ArrayEquals } from '../identity/index.js';
import { PROTOCOL_VERSION, DEFAULT_SUITE, PROTO_PREFIX, DEFAULT_TTL_SECONDS, DEFAULT_HANDSHAKE_TTL_SECONDS } from '../constants.js';
const suite = new QSP1Suite();
export function createMessage(senderIdentity, conversation, bodyType, body, refs, ttlSeconds) {
    validateIdentity(senderIdentity);
    const msgID = generateMessageID();
    const now = Math.floor(Date.now() / 1000);
    const expiryTS = now + ttlSeconds;
    // Create body structure for hashing
    const bodyStruct = {
        body_type: bodyType,
        body,
    };
    if (refs && refs.length > 0) {
        bodyStruct.refs = refs;
    }
    const bodyStructBytes = marshalCanonical(bodyStruct);
    const bodyHash = suite.hash(bodyStructBytes);
    // Create signable structure
    const signable = {
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
    const innerPayload = {
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
    const aadStruct = {
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
export function decryptMessage(envelope, conversation) {
    validateEnvelope(envelope);
    // Check expiry
    if (Math.floor(Date.now() / 1000) > envelope.expiry_ts) {
        throw new Error('message has expired');
    }
    // Check conversation ID matches
    if (!uint8ArrayEquals(envelope.conv_id, conversation.id)) {
        throw new Error('conversation ID mismatch');
    }
    // Reconstruct AAD
    const aadStruct = {
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
    const inner = unmarshalCanonical(innerPayloadBytes);
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
    return {
        envelope,
        inner,
        verified,
    };
}
export function verifyMessageSignature(envelope, innerPayload) {
    // Reconstruct body structure for hashing
    const bodyStruct = {
        body_type: innerPayload.body_type,
        body: innerPayload.body,
    };
    if (innerPayload.refs && innerPayload.refs.length > 0) {
        bodyStruct.refs = innerPayload.refs;
    }
    const bodyStructBytes = marshalCanonical(bodyStruct);
    const bodyHash = suite.hash(bodyStructBytes);
    // Reconstruct signable
    const signable = {
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
export function validateEnvelope(envelope) {
    if (envelope.v !== PROTOCOL_VERSION) {
        throw new Error(`unsupported protocol version: ${envelope.v}`);
    }
    if (envelope.suite !== DEFAULT_SUITE) {
        throw new Error(`unsupported crypto suite: ${envelope.suite}`);
    }
    if (envelope.created_ts <= 0) {
        throw new Error(`invalid created timestamp: ${envelope.created_ts}`);
    }
    if (envelope.expiry_ts <= envelope.created_ts) {
        throw new Error('expiry timestamp must be after created timestamp');
    }
    if (envelope.ciphertext.length === 0) {
        throw new Error('ciphertext is empty');
    }
    const maxFutureSkew = 600; // 10 minutes
    if (envelope.created_ts > Math.floor(Date.now() / 1000) + maxFutureSkew) {
        throw new Error('message created timestamp is too far in the future');
    }
}
export function validateInnerPayload(inner) {
    if (inner.sender_ik_pk.length !== 32) {
        throw new Error(`invalid sender public key length: ${inner.sender_ik_pk.length}`);
    }
    if (inner.sig_alg !== 'Ed25519') {
        throw new Error(`unsupported signature algorithm: ${inner.sig_alg}`);
    }
    if (inner.signature.length !== 64) {
        throw new Error(`invalid signature length: ${inner.signature.length}`);
    }
    if (!inner.body_type) {
        throw new Error('body type is empty');
    }
}
export function serializeEnvelope(envelope) {
    return marshalCanonical(envelope);
}
export function deserializeEnvelope(data) {
    const envelope = unmarshalCanonical(data);
    validateEnvelope(envelope);
    return envelope;
}
export function checkExpiry(envelope) {
    return Math.floor(Date.now() / 1000) > envelope.expiry_ts;
}
export function defaultTTL() {
    return DEFAULT_TTL_SECONDS;
}
export function defaultHandshakeTTL() {
    return DEFAULT_HANDSHAKE_TTL_SECONDS;
}
//# sourceMappingURL=index.js.map