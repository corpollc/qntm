/** 16-byte conversation identifier */
export type ConversationID = Uint8Array;

/** 16-byte message identifier */
export type MessageID = Uint8Array;

/** 16-byte key identifier: Trunc16(SHA-256(ed25519_public_key)) */
export type KeyID = Uint8Array;

export interface Identity {
  privateKey: Uint8Array; // Ed25519 private key (64 bytes)
  publicKey: Uint8Array;  // Ed25519 public key (32 bytes)
  keyID: KeyID;           // Derived from publicKey
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

// AAD structure for AEAD authentication
export interface AADStruct {
  v: number;
  suite: string;
  conv_id: ConversationID;
  msg_id: MessageID;
  created_ts: number;
  expiry_ts: number;
  conv_epoch: number;
}

// Structure that gets signed
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

// Gate types
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
  public_key: string; // base64
  label: string;
}

export interface Org {
  id: string;
  signers: Signer[];
  rules: ThresholdRule[];
  credentials?: Record<string, Credential>;
}

export type RequestStatus = 'pending' | 'approved' | 'executed' | 'expired';

export type GateMessageType =
  | 'gate.request'
  | 'gate.approval'
  | 'gate.disapproval'
  | 'gate.executed'
  | 'gate.expired'
  | 'gate.promote'
  | 'gate.config'
  | 'gate.secret'
  | 'gate.revoke'
  | 'gate.result';

export interface GateConversationMessage {
  type: GateMessageType;
  conv_id: string;
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

  // Recipe fields (optional -- populated when request originates from a recipe)
  recipe_name?: string;
  arguments?: Record<string, string>;
}

// Recipe types

export interface RecipeParam {
  name: string;
  description: string;
  required: boolean;
  default?: string;
  type: string; // "string" | "integer" | "boolean"
}

export interface Recipe {
  name: string;
  description: string;
  service: string;
  verb: string;
  endpoint: string;
  target_url: string;
  risk_tier: string;
  threshold: number;
  content_type?: string;
  path_params?: RecipeParam[];
  query_params?: RecipeParam[];
  body_schema?: Record<string, unknown>;
  body_example?: Record<string, unknown>;
}

export interface RecipeCatalog {
  profiles: Record<string, unknown>;
  recipes: Record<string, Recipe>;
}

// Gateway payload types

export interface PromotePayload {
  type: 'gate.promote';
  conv_id: string;
  gateway_kid: string;
  rules: ThresholdRule[];
}

export interface ConfigPayload {
  type: 'gate.config';
  rules: ThresholdRule[];
}

export interface RevokePayload {
  type: 'gate.revoke';
  secret_id?: string;  // Revoke specific secret by ID
  service?: string;    // Revoke all secrets for service
}

export interface SecretPayload {
  type: 'gate.secret';
  secret_id: string;
  service: string;
  header_name: string;
  header_template: string;
  encrypted_blob: Uint8Array;
  sender_kid: string;
  ttl?: number; // seconds until expiry; 0 or omitted means no expiry
}

/** Body of a gate.expired notification message, sent when a credential's
 *  TTL has elapsed. The gateway can USE secrets but cannot CREATE or
 *  REFRESH them -- humans must re-provision. */
export interface ExpiredPayload {
  type: 'gate.expired';
  secret_id: string;
  service: string;
  expired_at: string; // ISO 8601 / RFC3339 timestamp
  message: string;    // Human-readable description
}

export interface GateSignable {
  conv_id: string;
  request_id: string;
  verb: string;
  target_endpoint: string;
  target_service: string;
  target_url: string;
  expires_at_unix: number;
  payload_hash: Uint8Array;
  eligible_signer_kids: string[];
  required_approvals: number;
}

export interface ApprovalSignable {
  conv_id: string;
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
  conv_id: string;
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
