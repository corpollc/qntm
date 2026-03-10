export declare class QSP1Suite {
    name(): string;
    generateIdentityKey(): {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    computeKeyID(publicKey: Uint8Array): Uint8Array;
    generateGroupKey(): Uint8Array;
    deriveRootKey(inviteSecret: Uint8Array, inviteSalt: Uint8Array, convID: Uint8Array): Uint8Array;
    deriveConversationKeys(rootKey: Uint8Array, convID: Uint8Array): {
        aeadKey: Uint8Array;
        nonceKey: Uint8Array;
    };
    deriveEpochKeys(groupKey: Uint8Array, convID: Uint8Array, epoch: number): {
        aeadKey: Uint8Array;
        nonceKey: Uint8Array;
    };
    deriveNonce(nonceKey: Uint8Array, msgID: Uint8Array): Uint8Array;
    encrypt(aeadKey: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
    decrypt(aeadKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array;
    sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array;
    verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
    hash(data: Uint8Array): Uint8Array;
    wrapKeyForRecipient(newGroupKey: Uint8Array, recipientEd25519PK: Uint8Array, recipientKID: Uint8Array, convID: Uint8Array): Uint8Array;
    unwrapKeyForRecipient(wrappedData: Uint8Array, recipientEd25519SK: Uint8Array, recipientKID: Uint8Array, convID: Uint8Array): Uint8Array;
    private _generateX25519Keypair;
}
