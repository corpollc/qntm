# qntm Protocol Type Specification

Canonical type definitions for implementing qntm protocol clients.
All types use CBOR canonical encoding (RFC 8949 Section 4.2.1) on the wire.

## Constants

| Name | Value | Description |
|------|-------|-------------|
| ProtocolVersion | `1` | QSP protocol version |
| DefaultSuite | `"QSP-1"` | Cryptographic suite identifier |
| MaxGroupSize | `128` | Maximum group members |
| EpochGracePeriodSeconds | `86400` | 24h key retention after rekey |

## Crypto Constants

| Name | Value | Description |
|------|-------|-------------|
| ProtoPrefix | `"qntm/qsp/v1"` | Protocol prefix for signables |
| InfoRoot | `"qntm/qsp/v1/root"` | HKDF info for root key |
| InfoAEAD | `"qntm/qsp/v1/aead"` | HKDF info for AEAD key (epoch 0) |
| InfoNonce | `"qntm/qsp/v1/nonce"` | HKDF info for nonce key (epoch 0) |
| InfoAEADv11 | `"qntm/qsp/v1.1/aead"` | HKDF info for epoch 1+ AEAD |
| InfoNoncev11 | `"qntm/qsp/v1.1/nonce"` | HKDF info for epoch 1+ nonce |
| InfoWrapv11 | `"qntm/qsp/v1.1/wrap"` | HKDF info for key wrapping |

## Core Identity Types

### KeyID
- **Size**: 16 bytes
- **Derivation**: `Trunc16(SHA-256(ed25519_public_key))`
- **Encoding**: base64url no-padding (RFC 4648 Section 5)

### ConversationID
- **Size**: 16 bytes
- **Generation**: Random

### MessageID
- **Size**: 16 bytes
- **Generation**: Random

### Identity
```
{
  private_key: Ed25519PrivateKey  // 64 bytes
  public_key:  Ed25519PublicKey   // 32 bytes
  key_id:      KeyID              // 16 bytes, derived from public_key
}
```

## Wire Format Types (CBOR)

### OuterEnvelope
```cbor
{
  "v":          int           // Protocol version (1)
  "suite":      string        // "QSP-1"
  "conv_id":    bytes[16]     // Conversation ID
  "msg_id":     bytes[16]     // Message ID
  "created_ts": int           // Unix timestamp seconds
  "expiry_ts":  int           // Unix timestamp seconds
  "conv_epoch": uint          // Epoch number (0 = initial)
  "ciphertext": bytes         // Encrypted InnerPayload
  "aad_hash":   bytes?        // Optional AAD hash
}
```

### InnerPayload (encrypted, inside ciphertext)
```cbor
{
  "sender_ik_pk": bytes[32]   // Ed25519 public key
  "sender_kid":   bytes[16]   // Sender KeyID
  "body_type":    string      // Message type identifier
  "body":         bytes       // Message body
  "refs":         array?      // Optional references
  "sig_alg":      string      // "Ed25519"
  "signature":    bytes[64]   // Ed25519 signature
}
```

### Body Types
| Type | Description |
|------|-------------|
| `"text"` | Plain text message |
| `"json"` | JSON body |
| `"cbor"` | CBOR body |
| `"invite"` | Conversation invite |
| `"group_rekey"` | Group epoch rekey |
| `"ack"` | Acknowledgment |

### AADStruct (Additional Authenticated Data)
```cbor
{
  "v":          int
  "suite":      string
  "conv_id":    bytes[16]
  "msg_id":     bytes[16]
  "created_ts": int
  "expiry_ts":  int
  "conv_epoch": uint
}
```

### Signable (signed to produce InnerPayload.signature)
```cbor
{
  "proto":      string        // "qntm/qsp/v1"
  "suite":      string        // "QSP-1"
  "conv_id":    bytes[16]
  "msg_id":     bytes[16]
  "created_ts": int
  "expiry_ts":  int
  "sender_kid": bytes[16]
  "body_hash":  bytes[32]     // SHA-256 of body
}
```

### InvitePayload
```cbor
{
  "v":              int           // 1
  "suite":          string        // "QSP-1"
  "type":           string        // "direct" | "group"
  "conv_id":        bytes[16]
  "inviter_ik_pk":  bytes[32]     // Ed25519 public key
  "invite_salt":    bytes[32]
  "invite_secret":  bytes[32]
}
```

## Conversation Types

### ConversationKeys
```json
{
  "root":      bytes[32],   // Root key from HKDF
  "aead_key":  bytes[32],   // XChaCha20-Poly1305 key
  "nonce_key": bytes[32]    // Nonce derivation key
}
```

### EpochKeys
```json
{
  "epoch":      uint,
  "group_key":  bytes[32],  // k_group for this epoch
  "aead_key":   bytes[32],
  "nonce_key":  bytes[32],
  "expires_at": int?        // Unix timestamp
}
```

### Conversation
```json
{
  "id":            bytes[16],
  "name":          string?,
  "type":          "direct" | "group" | "announce",
  "keys":          ConversationKeys,
  "participants":  KeyID[],
  "created_at":    timestamp,
  "current_epoch": uint,
  "epoch_keys":    EpochKeys[]?
}
```

## Gate API Types (JSON)

### ThresholdRule
```json
{
  "service":  string,    // "*" = any
  "endpoint": string,    // "*" = any
  "verb":     string,    // HTTP verb, "*" = any
  "m":        int,       // Required signatures
  "n":        int        // Total possible (informational)
}
```
**Priority**: exact(service+endpoint+verb) > service+verb > service > default

### Credential
```json
{
  "id":           string,
  "service":      string,
  "value":        string,
  "header_name":  string,     // Default: "Authorization"
  "header_value": string,     // Template: "{value}" replaced
  "description":  string
}
```

### Signer
```json
{
  "kid":        string,                // base64url KeyID
  "public_key": string,                // base64 Ed25519 public key
  "label":      string
}
```

### Org
```json
{
  "id":          string,
  "signers":     Signer[],
  "rules":       ThresholdRule[],
  "credentials": { [id: string]: Credential }
}
```

### GateConversationMessage
```json
{
  "type":                  "gate.request" | "gate.approval" | "gate.executed",
  "org_id":                string,
  "request_id":            string,
  // Request-only fields:
  "verb":                  string?,       // HTTP verb
  "target_endpoint":       string?,
  "target_service":        string?,
  "target_url":            string?,
  "payload":               json?,         // Raw JSON
  "expires_at":            timestamp?,
  // Executed-only fields:
  "executed_at":           timestamp?,
  "execution_status_code": int?,
  // Common fields:
  "signer_kid":            string,
  "signature":             string         // base64url
}
```

### RequestStatus
`"pending" | "approved" | "executed" | "expired"`

### ScanResult
```json
{
  "found":         boolean,
  "threshold_met": boolean,
  "expired":       boolean,
  "signer_kids":   string[],
  "threshold":     int,
  "request":       GateConversationMessage?,
  "status":        RequestStatus
}
```

### ExecuteResult
```json
{
  "org_id":           string,
  "request_id":       string,
  "verb":             string,
  "target_endpoint":  string,
  "target_service":   string,
  "status":           RequestStatus,
  "signature_count":  int,
  "signer_kids":      string[],
  "threshold":        int,
  "expires_at":       timestamp,
  "execution_result": ExecutionResult?
}
```

### ExecutionResult
```json
{
  "status_code":    int,
  "content_type":   string?,
  "content_length": int
}
```

## Gate CBOR Signing Types

### GateSignable (signed for request authorization)
```cbor
{
  "org_id":          string,
  "request_id":      string,
  "verb":            string,
  "target_endpoint": string,
  "target_service":  string,
  "target_url":      string,
  "expires_at_unix": int,
  "payload_hash":    bytes[32]    // SHA-256 of payload
}
```

### ApprovalSignable (signed for approval)
```cbor
{
  "org_id":       string,
  "request_id":   string,
  "request_hash": bytes[32]       // SHA-256 of CBOR(GateSignable)
}
```

## Gate API Endpoints

| Method | Path | Auth | Request | Success | Error |
|--------|------|------|---------|---------|-------|
| POST | `/v1/orgs` | Admin | Org | 201 Org | 400, 401, 409 |
| GET | `/v1/orgs/{id}` | None | - | 200 Org | 404 |
| POST | `/v1/orgs/{id}/credentials` | Admin | Credential | 201 | 400, 401, 404 |
| POST | `/v1/orgs/{id}/messages` | None | GateConversationMessage | 200/202 ExecuteResult | 400, 404 |
| GET | `/v1/orgs/{id}/scan/{req}` | None | - | 200 ScanResult | 404, 405 |
| POST | `/v1/orgs/{id}/execute/{req}` | None | - | 200/202 ExecuteResult | 400, 404, 405 |
| GET | `/health` | None | - | 200 `{"status":"ok"}` | - |

### Response Codes for POST /messages
- **200 OK**: Threshold met, request executed. `status: "executed"`
- **202 Accepted**: Threshold not met or already executed. `status: "pending"` or `status: "executed"`
- **400 Bad Request**: Invalid signature, unknown signer, duplicate request, expired, bad JSON

## Cryptographic Operations

### Key Derivation
1. **Root key**: `HKDF-Extract(invite_secret, invite_salt)` then `HKDF-Expand(prk, "qntm/qsp/v1/root" || conv_id, 32)`
2. **AEAD key**: `HKDF-Expand(root, "qntm/qsp/v1/aead" || conv_id, 32)`
3. **Nonce key**: `HKDF-Expand(root, "qntm/qsp/v1/nonce" || conv_id, 32)`
4. **Message nonce**: `Trunc24(HMAC-SHA256(nonce_key, msg_id))`

### Encryption
- Algorithm: XChaCha20-Poly1305
- Key: 32 bytes (AEAD key)
- Nonce: 24 bytes (derived from nonce key + message ID)
- AAD: CBOR(AADStruct)

### Signing
- Algorithm: Ed25519
- Message: CBOR(Signable)
- Signature: 64 bytes
