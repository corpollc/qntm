/** 16-byte conversation identifier */
export type ConversationID = Uint8Array;
/** 16-byte message identifier */
export type MessageID = Uint8Array;
/** 16-byte key identifier: Trunc16(SHA-256(ed25519_public_key)) */
export type KeyID = Uint8Array;
export interface Identity {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    keyID: KeyID;
}
export interface InvitePayload {
    v: number;
    suite: string;
    type: 'direct' | 'group';
    conv_id: ConversationID;
    inviter_ik_pk: Uint8Array;
    invite_salt: Uint8Array;
    invite_secret: Uint8Array;
}
export interface ConversationKeys {
    root: Uint8Array;
    aeadKey: Uint8Array;
    nonceKey: Uint8Array;
}
export interface EpochKeys {
    epoch: number;
    groupKey: Uint8Array;
    aeadKey: Uint8Array;
    nonceKey: Uint8Array;
    expiresAt?: number;
}
export type ConversationType = 'direct' | 'group' | 'announce';
export interface Conversation {
    id: ConversationID;
    name?: string;
    type: ConversationType;
    keys: ConversationKeys;
    participants: KeyID[];
    createdAt: Date;
    currentEpoch: number;
    epochKeys?: EpochKeys[];
}
export interface OuterEnvelope {
    v: number;
    suite: string;
    conv_id: ConversationID;
    msg_id: MessageID;
    created_ts: number;
    expiry_ts: number;
    conv_epoch: number;
    ciphertext: Uint8Array;
    aad_hash?: Uint8Array;
}
export interface InnerPayload {
    sender_ik_pk: Uint8Array;
    sender_kid: KeyID;
    body_type: string;
    body: Uint8Array;
    refs?: unknown[];
    sig_alg: string;
    signature: Uint8Array;
}
export interface Message {
    envelope: OuterEnvelope;
    inner: InnerPayload;
    verified: boolean;
}
export interface AADStruct {
    v: number;
    suite: string;
    conv_id: ConversationID;
    msg_id: MessageID;
    created_ts: number;
    expiry_ts: number;
    conv_epoch: number;
}
export interface Signable {
    proto: string;
    suite: string;
    conv_id: ConversationID;
    msg_id: MessageID;
    created_ts: number;
    expiry_ts: number;
    sender_kid: KeyID;
    body_hash: Uint8Array;
}
export interface ThresholdRule {
    service: string;
    endpoint: string;
    verb: string;
    m: number;
    n?: number;
}
export interface Credential {
    id: string;
    service: string;
    value: string;
    header_name: string;
    header_value: string;
    description?: string;
}
export interface Signer {
    kid: string;
    public_key: string;
    label: string;
}
export interface Org {
    id: string;
    signers: Signer[];
    rules: ThresholdRule[];
    credentials?: Record<string, Credential>;
}
export type RequestStatus = 'pending' | 'approved' | 'executed' | 'expired';
export type GateMessageType = 'gate.request' | 'gate.approval' | 'gate.executed';
export interface GateConversationMessage {
    type: GateMessageType;
    org_id: string;
    request_id: string;
    verb?: string;
    target_endpoint?: string;
    target_service?: string;
    target_url?: string;
    payload?: unknown;
    expires_at?: string;
    executed_at?: string;
    execution_status_code?: number;
    signer_kid: string;
    signature: string;
}
export interface GateSignable {
    org_id: string;
    request_id: string;
    verb: string;
    target_endpoint: string;
    target_service: string;
    target_url: string;
    expires_at_unix: number;
    payload_hash: Uint8Array;
}
export interface ApprovalSignable {
    org_id: string;
    request_id: string;
    request_hash: Uint8Array;
}
export interface ScanResult {
    found: boolean;
    threshold_met: boolean;
    expired: boolean;
    signer_kids: string[];
    threshold: number;
    request?: GateConversationMessage;
    status: RequestStatus;
}
export interface ExecutionResult {
    status_code: number;
    content_type?: string;
    content_length: number;
}
export interface ExecuteResult {
    org_id: string;
    request_id: string;
    verb: string;
    target_endpoint: string;
    target_service: string;
    status: RequestStatus;
    signature_count: number;
    signer_kids: string[];
    threshold: number;
    expires_at: string;
    execution_result?: ExecutionResult;
}
