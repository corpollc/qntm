import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdf, extract, expand } from '@noble/hashes/hkdf';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/hashes/utils';
import {
  INFO_AEAD, INFO_NONCE, INFO_ROOT, INFO_AEAD_V11, INFO_NONCE_V11, INFO_WRAP_V11,
} from '../constants.js';
import { marshalCanonical, unmarshalCanonical } from './cbor.js';
import { ed25519PublicKeyToX25519, ed25519PrivateKeyToX25519, x25519SharedSecret } from './x25519.js';

export class QSP1Suite {
  name(): string {
    return 'QSP-1';
  }

  generateIdentityKey(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    // Ed25519 private key in Go is 64 bytes (seed + public key)
    const fullPrivate = new Uint8Array(64);
    fullPrivate.set(privateKey, 0);
    fullPrivate.set(publicKey, 32);
    return { publicKey, privateKey: fullPrivate };
  }

  computeKeyID(publicKey: Uint8Array): Uint8Array {
    const hash = sha256(publicKey);
    return hash.slice(0, 16);
  }

  generateGroupKey(): Uint8Array {
    return randomBytes(32);
  }

  deriveRootKey(inviteSecret: Uint8Array, inviteSalt: Uint8Array, convID: Uint8Array): Uint8Array {
    const info = new TextEncoder().encode(INFO_ROOT);
    const infoWithConvID = new Uint8Array(info.length + convID.length);
    infoWithConvID.set(info);
    infoWithConvID.set(convID, info.length);
    return hkdf(sha256, inviteSecret, inviteSalt, infoWithConvID, 32);
  }

  deriveConversationKeys(rootKey: Uint8Array, convID: Uint8Array): { aeadKey: Uint8Array; nonceKey: Uint8Array } {
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

  deriveEpochKeys(groupKey: Uint8Array, convID: Uint8Array, epoch: number): { aeadKey: Uint8Array; nonceKey: Uint8Array } {
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

  deriveNonce(nonceKey: Uint8Array, msgID: Uint8Array): Uint8Array {
    const h = hmac(sha256, nonceKey, msgID);
    return h.slice(0, 24);
  }

  encrypt(aeadKey: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    const cipher = xchacha20poly1305(aeadKey, nonce, aad);
    return cipher.encrypt(plaintext);
  }

  decrypt(aeadKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
    const cipher = xchacha20poly1305(aeadKey, nonce, aad);
    return cipher.decrypt(ciphertext);
  }

  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    // Use 32-byte seed (first 32 bytes of 64-byte key)
    const seed = privateKey.slice(0, 32);
    return ed25519.sign(message, seed);
  }

  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    try {
      return ed25519.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  }

  hash(data: Uint8Array): Uint8Array {
    return sha256(data);
  }

  wrapKeyForRecipient(
    newGroupKey: Uint8Array,
    recipientEd25519PK: Uint8Array,
    recipientKID: Uint8Array,
    convID: Uint8Array,
  ): Uint8Array {
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

  unwrapKeyForRecipient(
    wrappedData: Uint8Array,
    recipientEd25519SK: Uint8Array,
    recipientKID: Uint8Array,
    convID: Uint8Array,
  ): Uint8Array {
    const { ek_pk: ekPK, nonce, ct } = unmarshalCanonical<{ ek_pk: Uint8Array; nonce: Uint8Array; ct: Uint8Array }>(wrappedData);

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

  private _generateX25519Keypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { publicKey, privateKey };
  }
}
