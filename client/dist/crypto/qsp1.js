import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdf, extract, expand } from '@noble/hashes/hkdf';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/hashes/utils';
import { INFO_AEAD, INFO_NONCE, INFO_ROOT, INFO_AEAD_V11, INFO_NONCE_V11, INFO_WRAP_V11, } from '../constants.js';
import { marshalCanonical, unmarshalCanonical } from './cbor.js';
import { ed25519PublicKeyToX25519, ed25519PrivateKeyToX25519, x25519SharedSecret } from './x25519.js';
export class QSP1Suite {
    name() {
        return 'QSP-1';
    }
    generateIdentityKey() {
        const privateKey = ed25519.utils.randomPrivateKey();
        const publicKey = ed25519.getPublicKey(privateKey);
        // Ed25519 private key in Go is 64 bytes (seed + public key)
        const fullPrivate = new Uint8Array(64);
        fullPrivate.set(privateKey, 0);
        fullPrivate.set(publicKey, 32);
        return { publicKey, privateKey: fullPrivate };
    }
    computeKeyID(publicKey) {
        const hash = sha256(publicKey);
        return hash.slice(0, 16);
    }
    generateGroupKey() {
        return randomBytes(32);
    }
    deriveRootKey(inviteSecret, inviteSalt, convID) {
        const info = new TextEncoder().encode(INFO_ROOT);
        const infoWithConvID = new Uint8Array(info.length + convID.length);
        infoWithConvID.set(info);
        infoWithConvID.set(convID, info.length);
        return hkdf(sha256, inviteSecret, inviteSalt, infoWithConvID, 32);
    }
    deriveConversationKeys(rootKey, convID) {
        const infoAead = new TextEncoder().encode(INFO_AEAD);
        const infoNonce = new TextEncoder().encode(INFO_NONCE);
        const aeadInfo = new Uint8Array(infoAead.length + convID.length);
        aeadInfo.set(infoAead);
        aeadInfo.set(convID, infoAead.length);
        const nonceInfo = new Uint8Array(infoNonce.length + convID.length);
        nonceInfo.set(infoNonce);
        nonceInfo.set(convID, infoNonce.length);
        // Go uses HKDF-Expand only (rootKey is already a PRK)
        return {
            aeadKey: expand(sha256, rootKey, aeadInfo, 32),
            nonceKey: expand(sha256, rootKey, nonceInfo, 32),
        };
    }
    deriveEpochKeys(groupKey, convID, epoch) {
        if (epoch === 0) {
            return this.deriveConversationKeys(groupKey, convID);
        }
        const epochBytes = new Uint8Array(4);
        new DataView(epochBytes.buffer).setUint32(0, epoch, false); // big-endian
        const infoAead = new TextEncoder().encode(INFO_AEAD_V11);
        const infoNonce = new TextEncoder().encode(INFO_NONCE_V11);
        const aeadInfo = new Uint8Array(infoAead.length + convID.length + 4);
        aeadInfo.set(infoAead);
        aeadInfo.set(convID, infoAead.length);
        aeadInfo.set(epochBytes, infoAead.length + convID.length);
        const nonceInfo = new Uint8Array(infoNonce.length + convID.length + 4);
        nonceInfo.set(infoNonce);
        nonceInfo.set(convID, infoNonce.length);
        nonceInfo.set(epochBytes, infoNonce.length + convID.length);
        // Go uses HKDF-Expand only (groupKey is already a PRK)
        return {
            aeadKey: expand(sha256, groupKey, aeadInfo, 32),
            nonceKey: expand(sha256, groupKey, nonceInfo, 32),
        };
    }
    deriveNonce(nonceKey, msgID) {
        const h = hmac(sha256, nonceKey, msgID);
        return h.slice(0, 24);
    }
    encrypt(aeadKey, nonce, plaintext, aad) {
        const cipher = xchacha20poly1305(aeadKey, nonce, aad);
        return cipher.encrypt(plaintext);
    }
    decrypt(aeadKey, nonce, ciphertext, aad) {
        const cipher = xchacha20poly1305(aeadKey, nonce, aad);
        return cipher.decrypt(ciphertext);
    }
    sign(privateKey, message) {
        // Use 32-byte seed (first 32 bytes of 64-byte key)
        const seed = privateKey.slice(0, 32);
        return ed25519.sign(message, seed);
    }
    verify(publicKey, message, signature) {
        try {
            return ed25519.verify(signature, message, publicKey);
        }
        catch {
            return false;
        }
    }
    hash(data) {
        return sha256(data);
    }
    wrapKeyForRecipient(newGroupKey, recipientEd25519PK, recipientKID, convID) {
        const recipientX25519PK = ed25519PublicKeyToX25519(recipientEd25519PK);
        const { publicKey: ekPK, privateKey: ekSK } = this._generateX25519Keypair();
        const shared = x25519SharedSecret(ekSK, recipientX25519PK);
        // Go: PRK = HKDF-Extract(ss, convID), then Expand(PRK, InfoWrap||recipientKID)
        const prk = extract(sha256, shared, convID);
        const info = new TextEncoder().encode(INFO_WRAP_V11);
        const fullInfo = new Uint8Array(info.length + recipientKID.length);
        fullInfo.set(info);
        fullInfo.set(recipientKID, info.length);
        const wrapKey = expand(sha256, prk, fullInfo, 32);
        const nonce = randomBytes(24);
        const cipher = xchacha20poly1305(wrapKey, nonce);
        const ct = cipher.encrypt(newGroupKey);
        return marshalCanonical({ ek_pk: ekPK, nonce, ct });
    }
    unwrapKeyForRecipient(wrappedData, recipientEd25519SK, recipientKID, convID) {
        const { ek_pk: ekPK, nonce, ct } = unmarshalCanonical(wrappedData);
        const recipientX25519SK = ed25519PrivateKeyToX25519(recipientEd25519SK);
        const shared = x25519SharedSecret(recipientX25519SK, ekPK);
        // Go: PRK = HKDF-Extract(ss, convID), then Expand(PRK, InfoWrap||recipientKID)
        const prk = extract(sha256, shared, convID);
        const info = new TextEncoder().encode(INFO_WRAP_V11);
        const fullInfo = new Uint8Array(info.length + recipientKID.length);
        fullInfo.set(info);
        fullInfo.set(recipientKID, info.length);
        const wrapKey = expand(sha256, prk, fullInfo, 32);
        const cipher = xchacha20poly1305(wrapKey, nonce);
        return cipher.decrypt(ct);
    }
    _generateX25519Keypair() {
        const privateKey = randomBytes(32);
        const publicKey = x25519.getPublicKey(privateKey);
        return { publicKey, privateKey };
    }
}
//# sourceMappingURL=qsp1.js.map