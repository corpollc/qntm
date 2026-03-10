import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { keyIDFromPublicKey, validateIdentity, generateConversationID, base64UrlEncode, base64UrlDecode, uint8ArrayEquals, } from '../identity/index.js';
import { PROTOCOL_VERSION, DEFAULT_SUITE } from '../constants.js';
import { randomBytes } from '@noble/hashes/utils';
const suite = new QSP1Suite();
export function createInvite(inviterIdentity, convType) {
    validateIdentity(inviterIdentity);
    const convID = generateConversationID();
    const inviteSecret = randomBytes(32);
    const inviteSalt = randomBytes(32);
    return {
        v: PROTOCOL_VERSION,
        suite: DEFAULT_SUITE,
        type: convType,
        conv_id: convID,
        inviter_ik_pk: inviterIdentity.publicKey,
        invite_salt: inviteSalt,
        invite_secret: inviteSecret,
    };
}
export function serializeInvite(invite) {
    return marshalCanonical(invite);
}
export function deserializeInvite(data) {
    const invite = unmarshalCanonical(data);
    validateInvite(invite);
    return invite;
}
export function validateInvite(invite) {
    if (invite.v !== PROTOCOL_VERSION) {
        throw new Error(`unsupported protocol version: ${invite.v}`);
    }
    if (invite.suite !== DEFAULT_SUITE) {
        throw new Error(`unsupported crypto suite: ${invite.suite}`);
    }
    if (invite.type !== 'direct' && invite.type !== 'group') {
        throw new Error(`invalid conversation type: ${invite.type}`);
    }
    if (invite.inviter_ik_pk.length !== 32) {
        throw new Error(`invalid inviter public key length: ${invite.inviter_ik_pk.length}`);
    }
    if (invite.invite_salt.length < 16 || invite.invite_salt.length > 32) {
        throw new Error(`invalid invite salt length: ${invite.invite_salt.length}`);
    }
    if (invite.invite_secret.length !== 32) {
        throw new Error(`invalid invite secret length: ${invite.invite_secret.length}`);
    }
}
export function inviteToToken(invite) {
    const data = serializeInvite(invite);
    return base64UrlEncode(data);
}
export function inviteToURL(invite, baseURL) {
    const token = inviteToToken(invite);
    const url = new URL(baseURL);
    url.hash = token;
    return url.toString();
}
export function inviteFromURL(inviteURL) {
    let fragment;
    try {
        const url = new URL(inviteURL);
        fragment = url.hash.replace(/^#/, '');
    }
    catch {
        // Treat as bare token
        fragment = inviteURL;
    }
    if (!fragment) {
        throw new Error('no invite data in URL fragment');
    }
    const data = base64UrlDecode(fragment);
    return deserializeInvite(data);
}
export function deriveConversationKeys(invite) {
    validateInvite(invite);
    const rootKey = suite.deriveRootKey(invite.invite_secret, invite.invite_salt, invite.conv_id);
    const { aeadKey, nonceKey } = suite.deriveConversationKeys(rootKey, invite.conv_id);
    return {
        root: rootKey,
        aeadKey,
        nonceKey,
    };
}
export function createConversation(invite, keys) {
    validateInvite(invite);
    const inviterKeyID = keyIDFromPublicKey(invite.inviter_ik_pk);
    return {
        id: invite.conv_id,
        type: invite.type,
        keys,
        participants: [inviterKeyID],
        createdAt: new Date(),
        currentEpoch: 0,
    };
}
export function addParticipant(conv, pubkey) {
    const keyID = keyIDFromPublicKey(pubkey);
    for (const existing of conv.participants) {
        if (uint8ArrayEquals(existing, keyID)) {
            return; // Already a participant
        }
    }
    conv.participants.push(keyID);
}
export function isParticipant(conv, pubkey) {
    const keyID = keyIDFromPublicKey(pubkey);
    for (const participant of conv.participants) {
        if (uint8ArrayEquals(participant, keyID)) {
            return true;
        }
    }
    return false;
}
//# sourceMappingURL=index.js.map