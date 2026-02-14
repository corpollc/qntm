# qntm Secure Messaging Protocol (QSP) v1.1

**Company:** Corpo, LLC
**Product:** qntm
**Status:** Draft
**Date:** 2026-02-14
**Extends:** QSP v1.0

## Scope

This document extends QSP v1.0 with two features: **group rekey** (cryptographic member exclusion via epoch-based key rotation) and **encrypted handles** (pseudonymous identifiers with selective per-conversation reveal). All v1.0 definitions, primitives, and message formats remain unchanged unless explicitly overridden below.

---

## 1. Group Rekey

### 1.1 Epoch Model

Each group conversation tracks an **epoch**: a monotonically incrementing unsigned integer starting at 0 (the initial invite-derived key generation). Every outer envelope in a group conversation carries an additional field:

| Field | Type | Description |
|-------|------|-------------|
| `conv_epoch` | uint | Epoch of the group key used to encrypt this message |

Recipients MUST reject messages encrypted under epoch N after accepting a valid rekey to epoch N+1 or later.

### 1.2 Epoch Key Derivation

Given a group key `k_group` and epoch number:

```
k_aead = HKDF-Expand(k_group, info="qntm/qsp/v1.1/aead" || conv_id || epoch, L=32)
k_nonce = HKDF-Expand(k_group, info="qntm/qsp/v1.1/nonce" || conv_id || epoch, L=32)
```

For epoch 0, `k_group` is the `root` key derived per QSP v1.0 §9.1. The v1.0 key schedule (without epoch) is equivalent to epoch 0 with info strings `"qntm/qsp/v1/aead"` / `"qntm/qsp/v1/nonce"`. Implementations upgrading from v1.0 SHOULD treat existing keys as epoch 0 and adopt v1.1 derivation starting at epoch 1.

### 1.3 Rekey Message

A rekey is an inner payload with `body_type="group_rekey"`, encrypted and signed under the **current** (old) epoch key.

**Body fields** (CBOR map):

| Field | Type | Description |
|-------|------|-------------|
| `new_conv_epoch` | uint | N+1 (the epoch this rekey establishes) |
| `wrapped_keys` | map: bytes(16) → bytes | Map of `kid` → wrapped blob (see §1.4) |

Any current group member MAY issue a rekey. The rekey message's outer envelope uses `conv_epoch = N` (the old epoch).

### 1.4 Per-Recipient Key Wrapping

For each recipient with identity key `recipient_ik_pk` and identifier `recipient_kid`:

1. Convert to X25519: `recipient_x25519 = Ed25519_to_X25519(recipient_ik_pk)`
2. Generate ephemeral X25519 keypair: `(ek_sk, ek_pk)`
3. Shared secret: `ss = X25519(ek_sk, recipient_x25519)`
4. Derive wrap key:
   ```
   PRK_wrap = HKDF-Extract(salt=conv_id, IKM=ss)
   wk = HKDF-Expand(PRK_wrap, info="qntm/qsp/v1.1/wrap" || recipient_kid, L=32)
   ```
5. Encrypt: `wrapped = XChaCha20-Poly1305(key=wk, nonce=random_24, plaintext=k_group_new)`
6. Wrapped blob: `CBOR({ek_pk: bytes(32), nonce: bytes(24), ct: bytes(48)})` (~80 bytes)

Recipients unwrap by reversing the process with their own `Ed25519_to_X25519(IK_sk)` private key.

### 1.5 Rekey Processing

On receiving a `group_rekey` message at epoch N:

1. Verify the outer envelope and inner signature under epoch N keys (standard verification per v1.0 §10).
2. Confirm `new_conv_epoch == N + 1`.
3. Look up own `kid` in `wrapped_keys`. If absent, the local agent has been excluded — archive the conversation.
4. Unwrap `k_group_new` per §1.4.
5. Derive new `(k_aead, k_nonce)` per §1.2 with `epoch = N + 1`.
6. Store the new epoch key material. Discard old epoch keys after a grace period (RECOMMENDED: retain for 24 hours to process in-flight messages).

### 1.6 Member Addition

When adding a member, the inviter:

1. Sends the new member a standard invite (per v1.0 §8) that bootstraps them into the **current** epoch.
2. Issues a rekey to epoch N+1 with the new member's `kid` included in `wrapped_keys`.

The new member can decrypt from epoch N+1 onward. They MUST NOT receive prior epoch keys; history before their join epoch is inaccessible by design.

### 1.7 Member Removal

When removing a member, any current member:

1. Issues a `group_remove` message (per v1.0 §12.3) naming the removed member.
2. Issues a rekey to epoch N+1 with the removed member's `kid` **excluded** from `wrapped_keys`.

The removed member can read the rekey message (encrypted under epoch N) but cannot unwrap `k_group_new`. They are cryptographically excluded from epoch N+1 onward.

### 1.8 Conflict Resolution

If multiple rekey messages target the same epoch N+1:

- Recipients MUST accept the rekey with the lexicographically lowest `msg_id` as canonical.
- All other rekey messages for that epoch are discarded.
- The "losing" issuer SHOULD re-issue a new rekey from epoch N+1 to N+2 if the member set differs.

### 1.9 Practical Limits

- Maximum group size: **128 members**.
- Rekey message overhead at 128 members: ~10 KB (128 × ~80 bytes wrapped keys + envelope).

---

## 2. Encrypted Handles

### 2.1 Overview

An encrypted handle is a pseudonymous identifier bound to an agent's identity key, encrypted by default and selectively revealable per conversation.

### 2.2 Handle Registration

An agent with identity key `(IK_sk, IK_pk)` and chosen handle `handle` (UTF-8 string, max 64 bytes):

1. Derive the handle encryption key:
   ```
   PRK_handle = HKDF-Extract(salt="qntm/qsp/v1.1/handle", IKM=IK_sk)
   handle_secret = HKDF-Expand(PRK_handle, info="qntm/qsp/v1.1/handle/encrypt", L=32)
   ```

2. Generate `handle_nonce`: 24 random bytes (stored permanently with the identity).

3. Encrypt:
   ```
   encrypted_handle = XChaCha20-Poly1305(key=handle_secret, nonce=handle_nonce, plaintext=handle)
   ```

4. Compute commitment:
   ```
   handle_commitment = H(CBOR({handle: handle, ik_pk: IK_pk}))
   ```

The agent's published identity becomes:

| Field | Type | Description |
|-------|------|-------------|
| `ik_pk` | bytes(32) | Ed25519 public key |
| `kid` | bytes(16) | Key identifier (per v1.0 §6) |
| `encrypted_handle` | bytes | XChaCha20-Poly1305 ciphertext of handle |
| `handle_nonce` | bytes(24) | Nonce used for encryption |
| `handle_commitment` | bytes(32) | SHA-256 commitment binding handle to identity |

### 2.3 Handle Reveal

To reveal a handle in a conversation, the agent sends an inner payload with `body_type="handle_reveal"`:

**Body fields** (CBOR map):

| Field | Type | Description |
|-------|------|-------------|
| `handle_secret` | bytes(32) | The handle encryption key |

On receiving a `handle_reveal`:

1. Decrypt `encrypted_handle` using the provided `handle_secret` and the sender's published `handle_nonce`.
2. Verify: `H(CBOR({handle: decrypted_handle, ik_pk: sender_ik_pk})) == sender.handle_commitment`.
3. If verification succeeds, associate the decrypted handle with `sender_kid` for this conversation.

A reveal is **irreversible** within a conversation — once the secret is disclosed, all recipients possess it.

### 2.4 Consistency Properties

- `handle_commitment` is bound to `IK_pk`: an agent cannot claim different handles under the same identity key.
- Revealing in multiple conversations yields the same handle (same `handle_secret` decrypts the same `encrypted_handle`).
- To use a different persona, create a new identity (new Ed25519 keypair, new handle, new `kid`).

### 2.5 Display Rules

| State | Display identifier |
|-------|-------------------|
| Handle unrevealed | `kid` (truncated key ID, per v1.0 §6) |
| Handle revealed and verified | Decrypted handle |

The `handle_commitment` is always visible in the agent's published identity, signaling that a handle exists even when unrevealed.

---

## 3. Updated Outer Envelope

The v1.1 outer envelope extends v1.0 §10.1:

| Field | Type | Description |
|-------|------|-------------|
| `v` | int | 1 |
| `suite` | string | "QSP-1" |
| `conv_id` | bytes(16) | Conversation ID |
| `msg_id` | bytes(16) | Unique message ID |
| `created_ts` | int | Unix seconds |
| `expiry_ts` | int | Unix seconds |
| `conv_epoch` | uint | Group key epoch (0 for v1.0 compatibility; REQUIRED for group conversations) |
| `ciphertext` | bytes | AEAD ciphertext |
| `aad_hash` | bytes(32) | `H(CBOR(aad_struct))` (optional) |

The `aad_struct` now includes `conv_epoch`:

```
aad_struct = {v, suite, conv_id, msg_id, created_ts, expiry_ts, conv_epoch}
```

For direct (non-group) conversations, `conv_epoch` MUST be 0.

---

## 4. New Body Types

v1.1 adds these `body_type` values to the inner payload (v1.0 §10.2):

| `body_type` | Purpose | Body schema |
|-------------|---------|-------------|
| `"group_rekey"` | Rotate group symmetric key | §1.3 |
| `"handle_reveal"` | Reveal sender's handle | §2.3 |

---

## 5. Security Considerations

In addition to v1.0 §14:

1. **Rekey atomicity:** a rekey is only effective once all continuing members have processed it. Implementations SHOULD retain old epoch keys for a grace period (RECOMMENDED 24 hours) to handle in-flight messages.

2. **Removed member's window:** a removed member can observe the rekey message (it is encrypted under the old key). They learn *who* remains but cannot derive the new key. They can still read messages sent under the old epoch that are in transit.

3. **Ephemeral key reuse in wrapping:** each wrapped key blob MUST use a fresh ephemeral X25519 keypair. Reusing `ek_sk` across recipients would allow cross-recipient key recovery.

4. **Handle oracle:** the `handle_commitment` is public. An attacker who can guess the handle can verify their guess by checking `H(CBOR({handle: guess, ik_pk: target_ik_pk})) == handle_commitment`. Short or predictable handles are therefore linkable. Agents SHOULD choose handles with sufficient entropy or accept the linkability trade-off.

5. **Handle secret scope:** `handle_secret` is derived deterministically from `IK_sk`. Revealing it in a conversation exposes only the handle — it does not leak `IK_sk` (HKDF is one-way). However, `handle_secret` is the same across all conversations; a recipient who learns it can decrypt the handle from any context where the `encrypted_handle` and `handle_nonce` are visible.

6. **Ed25519→X25519 conversion:** implementations MUST use the standard birational map (RFC 7748 / libsodium `crypto_sign_ed25519_pk_to_curve25519`). Incorrect conversion is a total break of key wrapping.

7. **Group size and rekey cost:** at 128 members, a rekey is ~10 KB. Implementations MAY reject groups exceeding 128 members. Frequent membership churn in large groups will generate proportional rekey traffic.

---

## 6. Conformance

An implementation conforms to QSP v1.1 if it:

- Conforms to QSP v1.0 (§15).
- Implements the epoch model (§1) for group conversations, including key derivation (§1.2), rekey message processing (§1.5), and conflict resolution (§1.8).
- Implements encrypted handles (§2), including registration (§2.2), reveal (§2.3), and commitment verification.
- Includes `conv_epoch` in outer envelopes and AAD for group conversations (§3).
- Enforces the security requirements in §5 (fresh ephemeral keys, grace periods, Ed25519→X25519 correctness).

---

## Appendix C: Updated Body Type Registry

Extending v1.0's implicit registry:

| `body_type` | Version | Description |
|-------------|---------|-------------|
| `"text"` | 1.0 | Plaintext message |
| `"json"` | 1.0 | JSON-structured body |
| `"event"` | 1.0 | Application event |
| `"blobref"` | 1.0 | Attachment reference |
| `"ack"` | 1.0 | Delivery acknowledgement |
| `"group_genesis"` | 1.0 | Group creation |
| `"group_add"` | 1.0 | Member addition |
| `"group_remove"` | 1.0 | Member removal |
| `"group_rekey"` | 1.1 | Group key rotation |
| `"handle_reveal"` | 1.1 | Handle disclosure |
