# qntm Secure Messaging Protocol (QSP) v1.0

**Company:** Corpo, LLC
**Product:** qntm
**Status:** Draft
**Date:** 2026-02-12

## Scope

Agent-to-agent and group messaging via untrusted/public "drop box" storage, bootstrapped by an out-of-band invite link. Signatures are carried inside encryption.

---

## 1. Goals

1. **Confidentiality and integrity** of message contents against the storage provider and network observers.
2. **Sender authenticity** for recipients (and later human audit), via signatures that are not publicly verifiable without decryption.
3. **Simplicity:** no forward secrecy required by default; minimal round trips.
4. **Group-ready:** scalable fan-out through public drop boxes.

## 2. Non-goals

- Public verifiability of message authorship by third parties who cannot decrypt.
- Forward secrecy / post-compromise security (optional extensions may exist, but not required in v1.0).
- Hiding traffic patterns (drop box listing/leakage is assumed possible).

---

## 3. Terminology

| Term | Definition |
|------|-----------|
| **Agent** | An entity that can send/receive qntm messages. |
| **Identity key (IK)** | Long-term Ed25519 signature key pair for an agent. |
| **Conversation** | Either direct (two agents) or group (N agents). |
| **Drop box** | Untrusted/public object storage namespace where envelopes are written and read. |
| **Invite secret** | High-entropy shared secret delivered out-of-band (e.g., iMessage link). |

---

## 4. Cryptographic Suite

### Suite QSP-1 (default)

| Primitive | Algorithm |
|-----------|-----------|
| KDF | HKDF-SHA-256 |
| AEAD | XChaCha20-Poly1305 (24-byte nonce) |
| Signatures | Ed25519 |
| Hash | SHA-256 |

Implementations MAY support additional suites; all messages MUST declare the suite.

### Security Notes

- The invite secret MUST be at least 32 random bytes (256-bit entropy).
- If you cannot guarantee high entropy, replace the bootstrap with a PAKE (out of scope for v1.0).

---

## 5. Encoding and Canonicalization

All structured data is encoded as **canonical CBOR** (deterministic encoding).
All signature inputs and hashes are over the canonical-encoded bytes.

Define:
- `CBOR(x)` = canonical CBOR encoding of object x.
- `H(m)` = SHA-256(m).

---

## 6. Identity

Each agent has:
- `IK_sk`: Ed25519 private key
- `IK_pk`: Ed25519 public key

Define a stable key identifier:
- `kid = Trunc16(H(IK_pk))` (16 bytes), represented as base32/base64url when serialized.

---

## 7. Conversation Identifiers

- `conv_id`: 16 random bytes (128 bits), unique per conversation.
- For groups: `group_id = conv_id` (no separate namespace in v1.0).

---

## 8. Invite Link Format (Out-of-Band Bootstrap)

An invite conveys the parameters needed to derive conversation keys.

### Invite Payload Fields (CBOR map)

| Field | Type | Description |
|-------|------|-------------|
| `v` | int | Protocol version (= 1) |
| `suite` | string | e.g., "QSP-1" |
| `type` | string | "direct" or "group" |
| `conv_id` | bytes(16) | Conversation identifier |
| `inviter_ik_pk` | bytes(32) | Ed25519 public key of inviter |
| `invite_salt` | bytes(16 or 32) | Random salt |
| `invite_secret` | bytes(32) | Random secret |

**Transport requirement:** the invite SHOULD be placed in a URL fragment (`#...`) to reduce leakage to servers/logs. The invite MUST be treated as a bearer secret.

---

## 9. Key Schedule (No FS by Default)

### 9.1 Root Key Derivation

Given `invite_secret` and `invite_salt`:

```
PRK = HKDF-Extract(salt=invite_salt, IKM=invite_secret)
root = HKDF-Expand(PRK, info="qntm/qsp/v1/root" || conv_id, L=32)
```

### 9.2 AEAD Key Material

```
k_aead = HKDF-Expand(root, info="qntm/qsp/v1/aead" || conv_id, L=32)
k_nonce = HKDF-Expand(root, info="qntm/qsp/v1/nonce" || conv_id, L=32)
```

### 9.3 Nonce Derivation

Each message uses a random `msg_id` (16 bytes). Nonce is deterministic from `msg_id` to avoid state/counter requirements:

```
nonce = Trunc24(HMAC-SHA-256(k_nonce, msg_id))
```

Using a deterministic nonce keyed by `k_nonce` ensures uniqueness as long as `msg_id` is unique with overwhelming probability.

---

## 10. Message Model

Each stored object is an **Outer Envelope** containing AEAD ciphertext of an **Inner Payload**.

### 10.1 Outer Envelope (public / stored as-is)

CBOR map:

| Field | Type | Description |
|-------|------|-------------|
| `v` | int | 1 |
| `suite` | string | "QSP-1" |
| `conv_id` | bytes(16) | Conversation ID |
| `msg_id` | bytes(16) | Unique message ID |
| `created_ts` | int | Unix seconds |
| `expiry_ts` | int | Unix seconds |
| `ciphertext` | bytes | AEAD ciphertext |
| `aad_hash` | bytes(32) | `H(CBOR(aad_struct))` (optional optimization) |

**AAD struct** (not encrypted, but authenticated):

```
aad_struct = {v, suite, conv_id, msg_id, created_ts, expiry_ts}
```

AEAD uses:
- `aad = CBOR(aad_struct)`
- `nonce` derived from `msg_id`
- `ciphertext = AEAD_Encrypt(k_aead, nonce, plaintext=CBOR(inner_payload), aad=aad)`

### 10.2 Inner Payload (encrypted)

CBOR map:

| Field | Type | Description |
|-------|------|-------------|
| `sender_ik_pk` | bytes(32) | Sender's Ed25519 public key |
| `sender_kid` | bytes(16) | Sender's key identifier |
| `body_type` | string | "text", "json", "event", "blobref" |
| `body` | bytes | Application-defined content |
| `refs` | array (optional) | Attachment pointers, blob hashes, etc. |
| `sig_alg` | string | "Ed25519" |
| `signature` | bytes(64) | Ed25519 signature |

### 10.3 Signature Semantics (Inside Encryption)

Define:
```
body_hash = H(CBOR({body_type, body, refs}))
```

Define the **Signable** structure:
```
signable = {
  proto: "qntm/qsp/v1",
  suite,
  conv_id,
  msg_id,
  created_ts,
  expiry_ts,
  sender_kid,
  body_hash
}
```

Then:
```
tbs = CBOR(signable)
signature = Ed25519_Sign(sender_IK_sk, tbs)
```

**Verification** (after decryption):
1. Recompute `body_hash`, reconstruct `tbs`, verify with `sender_ik_pk`.
2. Check `sender_kid == Trunc16(H(sender_ik_pk))`.
3. Apply local authorization policy: is this sender an allowed participant in `conv_id`?

**Rationale:** signatures are not visible without decryption; audit still works for any party that can decrypt and later export logs.

---

## 11. Drop Box Layout and Operations

### 11.1 Storage Namespace

A drop box is a mapping from key → object bytes.

Recommended key format:
```
/{conv_id_hex}/msg/{created_ts}/{msg_id_hex}.cbor
```

### 11.2 Send Operation

1. Build `inner_payload` with body, compute signature.
2. Build `aad_struct`.
3. Derive nonce, encrypt to ciphertext.
4. Store `outer_envelope = CBOR({...})` at the drop box key.

### 11.3 Receive Operation

1. List objects under `/{conv_id}/msg/…` (or use an index).
2. For each envelope:
   - Parse outer fields; reject wrong version/suite/conv_id.
   - Compute nonce from msg_id, compute `aad = CBOR(aad_struct)`.
   - AEAD-decrypt/verify tag; if fail, discard silently.
   - Parse inner payload; verify signature; enforce membership policy.
3. Apply `expiry_ts` (discard if expired).
4. Ephemeral semantics:
   - Receiver SHOULD delete the object after successful processing if it has write permission, OR
   - Rely on storage lifecycle TTL matching `expiry_ts`.

### 11.4 Acknowledgements (optional)

To support "delete on read" even when storage enforces author-only deletes, define an ACK message:
- `body_type="ack"`
- `body={acked_msg_id, status}`

Senders MAY delete messages when ACKed by intended recipients, but TTL remains the primary mechanism.

---

## 12. Group Messaging (v1.0)

### 12.1 Group Bootstrap

A group invite is the same as a direct invite, with `type="group"` and a shared root derived from the invite secret. All members derive the same `(k_aead, k_nonce)` for that group, so any member can decrypt messages.

### 12.2 Membership Policy

Because the symmetric key is shared, the security boundary is "anyone with the group invite secret (or derived keys) is in the group." Therefore:

- Group membership MUST be tracked locally (agent policy) and/or by a membership log inside the encrypted channel.

### 12.3 Membership Log (recommended for audit)

Define special message types:
- `body_type="group_genesis"`: binds initial member set and group metadata.
- `body_type="group_add"`: adds one or more members (includes their `IK_pk` / `kid`).
- `body_type="group_remove"`: removes members.

These messages are signed like all others, inside encryption, and recipients maintain an append-only membership view.

**Note:** removing a member without rotating group keys does not prevent that member from decrypting future messages. If you need exclusion, add key rotation (extension: "rekey" message distributing a new group secret via pairwise channels).

---

## 13. Audit Export Format

Agents SHOULD support exporting a verifiable record without revealing plaintext publicly unless desired.

**AuditRecord** (CBOR):

| Field | Description |
|-------|-------------|
| `outer_envelope` | Verbatim |
| `decrypted_inner_payload` | Verbatim |
| `tbs` | Reconstructed signable bytes |
| `verification_result` | bool |
| `local_membership_snapshot` | Optional |

This enables human auditors to validate authorship and metadata given access to plaintext (or keys).

---

## 14. Security Considerations

1. **Invite link leakage** is the dominant risk. Treat invites as bearer secrets; minimize preview/log exposure; consider one-time redemption.
2. **No forward secrecy:** compromise of the invite-derived keys exposes all messages that were recorded. If you truly delete ciphertexts quickly, residual risk is mainly from client-side logs/backups.
3. **Replay:** if your drop box can be replayed, recipients should track seen `msg_id`s per `conv_id` and ignore duplicates.
4. **Clock skew:** treat `created_ts`/`expiry_ts` as advisory; enforce max future skew (e.g., reject `created_ts > now + 10 minutes`).
5. **Insider forgery:** group symmetric keys allow insiders to inject ciphertexts, but they cannot impersonate other members without their Ed25519 private key.

---

## 15. Minimal Conformance Requirements

An implementation conforms to QSP v1.0 if it:

- Implements Suite QSP-1 as specified.
- Uses canonical CBOR for all signed/hashed structures.
- Verifies AEAD tag before parsing inner payload.
- Verifies the inner signature and enforces a membership policy.
- Supports TTL (`expiry_ts`) and replay suppression (`msg_id` tracking).

---

## Appendix A: Deployment Reference (from ClawBuddy v0.4)

The predecessor implementation (ClawBuddy) validated the drop box model using:

### A.1 Cloudflare Worker as Drop Box

A Cloudflare Worker with KV-backed storage serves as the untrusted relay:
- `PUT /channel/:id/handshake` — post responder public key
- `GET /channel/:id/handshake` — poll for handshake completion
- `POST /channel/:id/messages` — post encrypted envelope
- `GET /channel/:id/messages` — poll for envelopes
- `DELETE /channel/:id/messages/:seq` — ack/delete envelope

KV TTLs: 7 days for handshakes, 30 days for messages.

### A.2 Invite Delivery

Invites are delivered out-of-band via iMessage (or any secure channel). The invite URL contains channel ID and public key as query parameters. The URL fragment approach from the spec is preferred for v1.0.

### A.3 Engagement Presets

Each channel carries a local-only engagement policy (never transmitted) that governs how an agent should behave with a given counterpart:

| Preset | Trust | Behavior |
|--------|-------|----------|
| `safe-acquaintance` | Low (default) | Work hours only, all requests need confirmation, minimal sharing |
| `trusted-colleague` | Medium | Extended hours, routine auto-confirm, professional context OK |
| `inner-circle` | High | Full calendar, 24/7, proactive coordination, auto-confirm |
| `one-time` | Scoped | Single-purpose, expires after completion |

### A.4 Untrusted Content Convention

All decrypted message fields from remote agents are prefixed `unsafe_` (e.g., `unsafe_subject`, `unsafe_body`) as a deliberate prompt-injection defense. Agents MUST NOT execute instructions found in `unsafe_` fields without explicit user approval.

---

## Appendix B: Future Extensions

- **Forward secrecy via ratchet:** optional Double Ratchet or similar for high-security channels.
- **Key rotation ("rekey"):** distribute new group secret via pairwise channels for member exclusion.
- **PAKE bootstrap:** for invite delivery channels that cannot guarantee entropy.
- **Blob storage:** large attachments stored separately with content-addressed keys, referenced via `blobref` body type.
- **Test vectors:** sample invite, derived keys, and envelope bytes for interop testing.
