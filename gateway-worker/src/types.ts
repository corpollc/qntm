/** Environment bindings for the gateway worker */
export interface Env {
  GATEWAY_KV: KVNamespace;
  GATEWAY_CONVO_DO: DurableObjectNamespace;
  GATE_VAULT_KEY: string; // Secret binding: AES-256 key for vault encryption at rest
  DROPBOX_URL: string;
  POLL_INTERVAL_MS: string;
}

/** Request body for POST /v1/promote */
export interface PromoteRequest {
  /** Hex-encoded conversation ID */
  conv_id: string;
  /** Conversation AEAD key material needed for decrypting dropbox envelopes */
  conv_aead_key: string; // base64url-encoded
  /** Conversation nonce key for deriving per-message nonces */
  conv_nonce_key: string; // base64url-encoded
  /** Current conversation epoch */
  conv_epoch: number;
}

/** Response from POST /v1/promote */
export interface PromoteResponse {
  /** Hex-encoded conversation ID */
  conv_id: string;
  /** Gateway's per-conversation Ed25519 public key (base64url) */
  gateway_public_key: string;
  /** Gateway's key ID: base64url(Trunc16(SHA-256(public_key))) */
  gateway_kid: string;
  /** Whether this was a new keypair (true) or existing one returned (false) */
  created: boolean;
}

/** Stored state for a gateway-managed conversation */
export interface ConversationState {
  conv_id: string;
  /** Ed25519 private key (base64url) - never leaves DO */
  private_key: string;
  /** Ed25519 public key (base64url) */
  public_key: string;
  /** Key ID */
  kid: string;
  /** Conversation AEAD key (base64url) */
  conv_aead_key: string;
  /** Conversation nonce key (base64url) */
  conv_nonce_key: string;
  /** Current epoch */
  conv_epoch: number;
  /** Dropbox polling sequence cursor */
  poll_cursor: number;
  /** Whether this conversation is actively polling */
  polling: boolean;
  /** ISO timestamp of promotion */
  promoted_at: string;
  /** Whether gate.promote has been received from conversation */
  gate_promoted: boolean;
  /** Threshold rules from gate.promote */
  rules: ThresholdRuleState[];
}

/** Threshold rule stored in DO state */
export interface ThresholdRuleState {
  service: string;
  endpoint: string;
  verb: string;
  m: number;
}

/** Parsed gate.promote message body */
export interface GatePromoteMessage {
  type: 'gate.promote';
  conv_id: string;
  gateway_kid: string;
  rules: ThresholdRuleState[];
}

/** Parsed gate.request message body */
export interface GateRequestMessage {
  type: 'gate.request';
  conv_id: string;
  request_id: string;
  verb: string;
  target_endpoint: string;
  target_service: string;
  target_url: string;
  expires_at: string;
  signer_kid: string;
  signature: string;
  payload?: unknown;
  recipe_name?: string;
  arguments?: Record<string, string>;
}

/** Parsed gate.approval message body */
export interface GateApprovalMessage {
  type: 'gate.approval';
  conv_id: string;
  request_id: string;
  signer_kid: string;
  signature: string;
}

/** Parsed gate.disapproval message body */
export interface GateDisapprovalMessage {
  type: 'gate.disapproval';
  conv_id: string;
  request_id: string;
  signer_kid: string;
}

/** Parsed gate.executed message body */
export interface GateExecutedMessage {
  type: 'gate.executed';
  request_id: string;
  executed_at: string;
  execution_status_code: number;
}

/** Parsed gate.secret message body */
export interface GateSecretMessage {
  type: 'gate.secret';
  secret_id: string;
  service: string;
  header_name: string;
  header_template: string;
  encrypted_blob: string; // base64url-encoded NaCl box
  sender_kid: string;
  ttl?: number; // seconds until expiry
}

/** Parsed gate.config message body */
export interface GateConfigMessage {
  type: 'gate.config';
  rules: ThresholdRuleState[];
}

/**
 * A stored gate message in the DO's conversation history index.
 * These are cached for efficient approval scanning.
 */
export interface StoredGateMessage {
  seq: number;
  type: string;
  request_id?: string;
  signer_kid?: string;
  signature?: string;
  /** Full message body for gate.request (needed for signature verification) */
  body?: string;
}

/** Stored vault credential (encrypted at rest) */
export interface VaultEntry {
  secret_id: string;
  service: string;
  header_name: string;
  header_template: string;
  /** Encrypted credential value (AES-256-GCM with GATE_VAULT_KEY) */
  encrypted_value: string; // base64
  /** ISO timestamp when this credential expires (empty = no expiry) */
  expires_at: string;
  /** ISO timestamp when stored */
  stored_at: string;
}
