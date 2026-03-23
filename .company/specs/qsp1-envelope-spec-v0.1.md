# QSP-1 Envelope Specification — v0.1 DRAFT

## Status
Draft. Three implementations exist (Python/qntm, TypeScript/APS, Python/AgentID). This spec formalizes what's been proven in production.

## Overview
A QSP-1 envelope is a CBOR-encoded map containing an encrypted message, sender identity, and signature. It is transported as base64 over the qntm relay HTTP API.

## Wire Format

```
envelope_b64 = Base64(CBOR(envelope_map))
```

## Envelope Fields

| Field | CBOR Key | Type | Required | Description |
|-------|----------|------|----------|-------------|
| Version | `v` | uint | YES | Protocol version. MUST be `1`. |
| Conversation | `conv` | bstr(16) | YES | Conversation ID (16 bytes). |
| Sender | `sender` | bstr(16) | YES | `Trunc16(SHA-256(ed25519_public_key))` |
| Sequence | `seq` | uint | NO | Sender-local sequence number. |
| Timestamp | `ts` | uint | YES | Unix milliseconds (UTC). |
| Message ID | `msg_id` | bstr(16) | YES | Random 16-byte message identifier. Used for nonce derivation. |
| Ciphertext | `ciphertext` | bstr | YES | XChaCha20-Poly1305 encrypted payload. |
| AAD Hash | `aad_hash` | bstr(32) | YES | `SHA-256(conv_id)`. Bound as AAD during encryption. |
| Signature | `sig` | bstr(64) | YES | `Ed25519.sign(ciphertext, sender_private_key)` |
| DID | `did` | tstr | NO | Sender's DID URI (e.g. `did:aps:z...`, `did:agentid:agent_xxx`). Identity metadata — NOT covered by signature. |

### Deprecated Aliases (bridge compatibility)

Implementations SHOULD use canonical field names above. For backwards compatibility, receivers SHOULD accept these aliases:

| Alias | Canonical |
|-------|-----------|
| `nonce` | Derived from `msg_id` — if present, use as raw nonce instead of deriving |
| `ct` | `ciphertext` |
| `aad` | `aad_hash` |

## Cryptographic Operations

### Key Derivation (from invite token)

```
root_key  = HKDF-SHA256(ikm=invite_secret, salt=invite_salt, info="qntm/qsp/v1/root"  || conv_id, len=32)
aead_key  = HKDF-Expand-SHA256(prk=root_key, info="qntm/qsp/v1/aead"  || conv_id, len=32)
nonce_key = HKDF-Expand-SHA256(prk=root_key, info="qntm/qsp/v1/nonce" || conv_id, len=32)
```

### Nonce Derivation

```
nonce = Trunc24(HMAC-SHA256(nonce_key, msg_id))
```

### Encryption

```
ciphertext = XChaCha20-Poly1305.Encrypt(key=aead_key, nonce=nonce, plaintext=payload, aad=conv_id)
```

### Signature

```
sig = Ed25519.Sign(signing_key, ciphertext)
```

The signature covers only the ciphertext, not the full envelope. This allows relay-level metadata (seq, ts) to be updated without invalidating the signature.

## Sender Identity

The `sender` field is a compact 16-byte key ID:
```
sender = SHA-256(ed25519_public_key)[:16]
```

This is a routing identifier, not a DID. DID resolution (`did:agentid`, `did:aps`, etc.) is an identity-layer concern above the transport.

### DID Extension (SHIPPED)

The optional `did` field (text string) contains the sender's DID URI. This allows receivers to resolve the full identity document without a separate lookup. Backwards compatible — receivers that don't understand DIDs ignore the field.

Supported DID methods:
- `did:aps:<ed25519-public-key-multibase>` — Agent Passport System (self-sovereign)
- `did:agentid:<agent-identifier>` — AgentID (CA-issued + trust scores)
- `did:key:<multibase-encoded-key>` — W3C DID Key method (generic)

The `did` field is NOT covered by the envelope signature — it's identity metadata, not transport data. Receivers MUST verify the DID resolves to the same Ed25519 public key as the `sender` key ID.

## Transport

### Send

```
POST /v1/send
Content-Type: application/json

{
  "conv_id": "<hex string>",
  "envelope_b64": "<base64 encoded CBOR>"
}
```

### Subscribe (WebSocket)

```
GET /v1/subscribe?conv_id=<hex>&cursor=<seq>
Upgrade: websocket
```

Messages arrive as WebSocket text frames containing JSON with `envelope_b64`.

## Known-Answer Test Vectors

### Invite Material
```
invite_secret: a6d89c17fb6da9e56f368c2b562978ccd434900a835062d0fdfb5b31f0bdaaa2
invite_salt:   99c74e4a41450c294a3ffb6473141ef3ca9e97f7afbc98ffc80f45793944dd80
conv_id:       dca83b70ccd763a89b5953b2cd2ee678
```

### Derived Keys
```
root_key:  5b9f2361408c3932d4685d8ccb9733a1da980086c49a7b6615f6bca5e1a67c01
aead_key:  b557d6071c2237eff670aa965f8f3bb516f9ba1d788166f8faf7388f5a260ec3
nonce_key: d88a1a1dee9dd0761a61a228a368ad72c15b96108c04cb072cc2b8fd63056c4f
```

### Verified By
- Python (qntm native) — `cryptography` library
- TypeScript (APS bridge) — `@noble/hashes`
- Python (AgentID bridge) — `cryptography` library

## Changelog
- v0.1.1 (2026-03-23): Added optional `did` field for DID metadata. Shipped in Python client, 2 tests. Backwards compatible.
- v0.1 (2026-03-23): Initial draft. Formalizes what's proven across 3 implementations.
