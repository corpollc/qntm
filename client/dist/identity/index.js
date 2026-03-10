import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { randomBytes } from '@noble/hashes/utils';
const suite = new QSP1Suite();
export function generateIdentity() {
    const { publicKey, privateKey } = suite.generateIdentityKey();
    const keyID = suite.computeKeyID(publicKey);
    return { privateKey, publicKey, keyID };
}
export function keyIDFromPublicKey(pubkey) {
    return suite.computeKeyID(pubkey);
}
export function verifyKeyID(pubkey, keyID) {
    const computed = suite.computeKeyID(pubkey);
    return uint8ArrayEquals(computed, keyID);
}
export function serializeIdentity(identity) {
    return marshalCanonical({
        private_key: identity.privateKey,
        public_key: identity.publicKey,
        key_id: identity.keyID,
    });
}
export function deserializeIdentity(data) {
    const obj = unmarshalCanonical(data);
    if (obj.private_key.length !== 64) {
        throw new Error(`invalid private key length: ${obj.private_key.length}`);
    }
    if (obj.public_key.length !== 32) {
        throw new Error(`invalid public key length: ${obj.public_key.length}`);
    }
    const identity = {
        privateKey: new Uint8Array(obj.private_key),
        publicKey: new Uint8Array(obj.public_key),
        keyID: new Uint8Array(obj.key_id),
    };
    if (!verifyKeyID(identity.publicKey, identity.keyID)) {
        throw new Error('key ID does not match public key');
    }
    return identity;
}
export function publicKeyToString(pubkey) {
    return base64UrlEncode(pubkey);
}
export function publicKeyFromString(s) {
    const data = base64UrlDecode(s);
    if (data.length !== 32) {
        throw new Error(`invalid public key length: ${data.length}`);
    }
    return data;
}
export function keyIDToString(keyID) {
    return base64UrlEncode(keyID);
}
export function keyIDFromString(s) {
    const data = base64UrlDecode(s);
    if (data.length !== 16) {
        throw new Error(`invalid key ID length: ${data.length}`);
    }
    return data;
}
export function generateConversationID() {
    return randomBytes(16);
}
export function generateMessageID() {
    return randomBytes(16);
}
export function validateIdentity(identity) {
    if (identity.privateKey.length !== 64) {
        throw new Error(`invalid private key length: ${identity.privateKey.length}`);
    }
    if (identity.publicKey.length !== 32) {
        throw new Error(`invalid public key length: ${identity.publicKey.length}`);
    }
    if (!verifyKeyID(identity.publicKey, identity.keyID)) {
        throw new Error('key ID does not match public key');
    }
    // Test that the key pair works for signing
    const testMessage = new TextEncoder().encode('validation test');
    const signature = suite.sign(identity.privateKey, testMessage);
    if (!suite.verify(identity.publicKey, testMessage, signature)) {
        throw new Error('public key cannot verify signature from private key');
    }
}
// Helpers
function uint8ArrayEquals(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}
function base64UrlEncode(data) {
    const binary = String.fromCharCode(...data);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlDecode(s) {
    // Add padding back
    const padded = s + '==='.slice(0, (4 - (s.length % 4)) % 4);
    const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
export { uint8ArrayEquals, base64UrlEncode, base64UrlDecode };
//# sourceMappingURL=index.js.map