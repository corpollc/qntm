# QSP-1 Envelope Specification — v1.0 RATIFIED

## Status
**RATIFIED — UNANIMOUS.** Approved by all 4 founding Working Group members on 2026-03-24.

### Ratification Record
| Member | Project | Sign-off | Date (UTC) | Implementation |
|--------|---------|----------|------------|----------------|
| qntm | qntm (Python) | ✅ Author | 2026-03-23 | `python-dist/` — reference implementation |
| aeoess | Agent Passport System (TypeScript) | ✅ Signed off | 2026-03-24 00:21 | `0c466ee` — full conformance: Ed25519 signing, canonical fields, 24 bridge tests |
| FransDevelopment | Open Agent Trust Registry | ✅ Signed off | 2026-03-24 00:31 | OATR Spec 10 §6.2 — confirmed exact alignment |
| haroldmalikfrimpong-ops | AgentID (Python) | ✅ Signed off | 2026-03-24 01:04 | All 6 conformance requirements verified, relay script conformant |

Three implementations exist (Python/qntm, TypeScript/APS, Python/AgentID). FransDevelopment's encrypted transport spec (OATR Spec 10) references QSP-1 for conformance. All four founding WG members (qntm, APS, AgentID, OATR) and three additional issuers (ArkForge, Agora, arcede) have registered in the Open Agent Trust Registry. This spec formalizes what's been proven in production across 7 registered issuers.

## Normative References

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

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
| Expiry | `expiry_ts` | uint | NO | Unix milliseconds (UTC). If present, relays SHOULD reject messages past this time. See §6.2. |

### Deprecated Aliases (bridge compatibility)

Implementations MUST emit canonical field names. For backwards compatibility, receivers SHOULD accept these aliases until **v1.1 or 6 months after v1.0 ratification** (whichever comes first), at which point support for aliases MAY be removed.

| Alias | Canonical | Notes |
|-------|-----------|-------|
| `nonce` | Derived from `msg_id` | If present as raw 24-byte nonce, use directly instead of deriving from `msg_id` |
| `ct` | `ciphertext` | |
| `aad` | `aad_hash` | |

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

## Expiry Enforcement (§6.2)

Per OATR Spec 10 §6.2 (FransDevelopment):

- If `expiry_ts` is present and the current time exceeds it, the relay SHOULD reject the message with HTTP 400 and reason `expired`.
- If `expiry_ts` is absent, the relay MUST pass the message through (graceful degradation).
- Senders SHOULD set `expiry_ts` for time-sensitive operations (API approvals, ephemeral sessions).
- Receivers SHOULD check `expiry_ts` after decryption and discard expired payloads.

This provides backwards compatibility: legacy senders that omit `expiry_ts` are unaffected. New senders opt into relay-level expiry enforcement.

## Error Handling (§6)

### Receiver Behavior

| Condition | Action |
|-----------|--------|
| CBOR decode failure | MUST skip envelope, SHOULD log error |
| Unknown CBOR keys | MUST ignore (forward compatibility) |
| `v` != 1 | MUST reject envelope |
| Signature verification failure | MUST reject envelope, MUST NOT process plaintext |
| Nonce derivation produces different nonce than expected | MUST reject envelope |
| `expiry_ts` present and expired | SHOULD discard, MAY log |
| `did` present but does not resolve to `sender` key | SHOULD warn, MAY continue processing (DID is metadata, not transport) |

### Relay Behavior

| Condition | Action |
|-----------|--------|
| Malformed JSON request | MUST return HTTP 400 |
| Missing required fields (`conv_id`, `envelope_b64`) | MUST return HTTP 400 |
| `expiry_ts` present and expired | SHOULD return HTTP 400 with `{"error": "expired"}` |
| `envelope_b64` not valid base64 | SHOULD return HTTP 400 |
| Valid envelope | MUST store and deliver to subscribers |

Relays are honest-but-curious: they store and forward CBOR envelopes but MUST NOT require access to plaintext. Relays SHOULD validate envelope structure (base64 decode, CBOR parse) but MUST NOT validate signatures (they don't have recipient keys).

## Security Considerations (§7)

### 7.1 Threat Model

The relay is assumed to be an **honest-but-curious** adversary:
- It faithfully stores and delivers envelopes (honest)
- It may inspect envelope metadata: `conv`, `sender`, `seq`, `ts`, `did`, `expiry_ts` (curious)
- It CANNOT read plaintext (XChaCha20-Poly1305 encryption with key material derived from invite secret)
- It CANNOT forge signatures (Ed25519 signing key held only by sender)

### 7.2 Replay Protection

Each envelope contains a unique `msg_id` (16 random bytes). The nonce is derived deterministically from `msg_id`:
```
nonce = Trunc24(HMAC-SHA256(nonce_key, msg_id))
```

Receivers SHOULD maintain a window of recently-seen `msg_id` values and reject duplicates. The `seq` field provides an additional ordering signal — receivers MAY reject envelopes with `seq` values below a threshold.

### 7.3 Nonce Reuse Prevention

Nonces are derived from random `msg_id` values via HMAC-SHA256, not generated directly. This ensures:
- Two messages with the same `msg_id` produce the same nonce (idempotent replay)
- Two messages with different `msg_id` values produce different nonces with overwhelming probability (collision resistance of HMAC-SHA256 truncated to 24 bytes)

Implementations MUST generate `msg_id` from a cryptographically secure random source.

### 7.4 Forward Secrecy

QSP-1 v1.0 uses a **static shared secret** model (invite token → HKDF → conversation keys). This means:
- Compromise of the invite secret reveals ALL past and future messages in that conversation
- This is a deliberate trade-off: the invite model is simpler for agent-to-agent integration than X3DH prekey infrastructure

Implementations requiring forward secrecy SHOULD layer a Double Ratchet protocol on top of QSP-1 (as the qntm reference implementation does internally). A future QSP-2 spec MAY formalize Double Ratchet integration.

### 7.5 AAD Binding

The `conv_id` is bound as Additional Authenticated Data (AAD) during encryption:
```
ciphertext = XChaCha20-Poly1305.Encrypt(key, nonce, plaintext, aad=conv_id)
```

This prevents cross-conversation attacks: an envelope encrypted for conversation A cannot be transplanted into conversation B — decryption will fail due to AAD mismatch.

### 7.6 Signature Scope

The Ed25519 signature covers **only the ciphertext**, not the full envelope:
```
sig = Ed25519.Sign(signing_key, ciphertext)
```

This is intentional:
- Relay-level metadata (`seq`, `ts`) can be updated by the relay without invalidating the signature
- The ciphertext is the only field that proves the sender had the signing key AND the encryption key
- Metadata fields are untrusted by design — receivers derive trust from the ciphertext and signature

### 7.7 DID Field Trust

The `did` field is NOT covered by the envelope signature. An attacker who controls the relay could substitute a different DID. Mitigation:
- Receivers MUST verify the DID resolves to an Ed25519 public key whose `Trunc16(SHA-256(pubkey))` matches the `sender` field
- The `sender` field IS bound to the signature via the signing key

### 7.8 Key Separation

RECOMMENDED: Use separate key material for different trust surfaces:
- **Transport key:** Ed25519 key pair for QSP-1 envelope signing and AEAD key derivation
- **DID key:** Ed25519 key pair for DID Document `verificationMethod`
- **OATR key:** Ed25519 key pair for attestation issuer registration

This practice is already followed by archedark-ada (Agora) and RECOMMENDED for all issuers.

## Versioning (§8)

The `v` field MUST be `1` for this specification. Implementations:
- MUST reject envelopes with `v` > 1 (fail-safe)
- MUST NOT attempt to decode unknown versions
- Version negotiation is out of scope for v1.0

Future versions (v2+) will be published as separate specifications. Implementations SHOULD support concurrent operation of multiple versions during transition periods.

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

### Full Roundtrip Vector

Using the invite material above with a fixed sender key and message:

```
# Sender key (Ed25519 seed)
seed:        deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef
public_key:  8aa49008d58bad4ccd3494960da49848331a78bc06e23c36d731322c35b35fa9
sender:      1f60f7ef29e27d280400a7f3e5f4899c    # Trunc16(SHA-256(public_key))

# Message
msg_id:      0102030405060708090a0b0c0d0e0f10
plaintext:   "Hello from QSP-1 test vector"       # 28 bytes

# Derived nonce
nonce:       a7f98b27bb1aab6f8b216a587dc78b1b53f6b23ce7fe3413

# Ciphertext (XChaCha20-Poly1305, AAD = conv_id)
ciphertext:  e6be3866938c2e8085cfdbc61102cc4f3dc66638528e37e47e81e8ce954b1824086f3c52de0a66085c309425

# AAD hash
aad_hash:    b17148a47096a25b259b276fd03632231e308b8e29ed898eab8ecbae6ad4d7b9

# Signature (Ed25519.Sign(seed, ciphertext))
sig:         dd47f05e079dd4460c90da592a6cc7de472ccbc748fa620063af969f061e2cb4e741dd759ff2409169458390d48be9060db36eff1575f3c50b182ff3a1d25a0d
```

A conforming implementation MUST produce identical `nonce`, `ciphertext`, `sender`, and `aad_hash` from the same inputs. The `sig` will differ if the implementation uses a different Ed25519 key — verify by checking `Ed25519.Verify(public_key, sig, ciphertext)` returns true.

## Encoding Conventions

### Multibase Encoding (WG Decision — Wave 37-38)

Public keys in DID documents and WG specs MUST use **`z`-prefixed base58btc** (multibase) as the canonical encoding. Hex encoding is accepted as an alias.

**Canonical:** `z6QQ5asBUnXiM4JsgfnG36...` (base58btc with `z` prefix)
**Alias:** `64b94613478dd1e4cd504f6f68ad6d4ad7fa02ea05516a8906fab1ed08317c46` (hex)

This was agreed by all three founding WG members (qntm, APS, AgentID) on A2A #1672:
- aeoess (APS): will update `createDID()` to emit multibase by default
- haroldmalikfrimpong-ops (AgentID): already uses z-prefix, no changes needed
- qntm: `did:key` resolution already handles multibase; `did:web` resolution accepts both

Implementations SHOULD emit multibase and MUST accept both encodings.

### Sender ID Derivation

`Trunc16(SHA-256(ed25519_public_key))` — first 16 bytes of the SHA-256 hash.

This derivation is shared by:
- qntm: envelope `sender` field
- ArkForge: `buyer_fingerprint` in proof receipts
- Proven interop: `resolve_did_to_ed25519("did:web:trust.arkforge.tech")` → sender_id `174e20acd605f8ce6fca394246729bd7` (tested wave 38)

## Changelog
- v1.0-rc1 (2026-03-23): Release candidate. Added `expiry_ts` field (OPTIONAL, §6.2 enforcement per OATR Spec 10). Added Security Considerations (§7): threat model, replay protection, nonce reuse, forward secrecy, AAD binding, signature scope, DID trust, key separation. Added Error Handling (§6). Added Versioning (§8). Formalized RFC 2119 language. Deprecated alias sunset timeline (v1.1 or 6 months). Full roundtrip test vector. 7 registered OATR issuers, 4 founding WG members.
- v0.1.1 (2026-03-23): Added optional `did` field for DID metadata. Multibase encoding convention (`z`-prefix base58btc canonical, hex alias). Sender ID derivation cross-project alignment documented (ArkForge buyer_fingerprint). Shipped in Python client. Backwards compatible.
- v0.1 (2026-03-23): Initial draft. Formalizes what's proven across 3 implementations.
