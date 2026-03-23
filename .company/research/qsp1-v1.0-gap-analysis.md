# QSP-1 v1.0 Gap Analysis
Created: 2026-03-23 (Wave 42)
DRI: Founder

## Current State: v0.1.1 DRAFT
- 3 implementations (qntm Python, APS TypeScript, AgentID Python)
- FransDevelopment Spec 10 references QSP-1 for conformance
- All field names, crypto operations, and test vectors proven in interop

## Gaps to v1.0

### 1. expiry_ts (HIGH — FransDevelopment PR #11)
**Status:** FransDevelopment proposed §6.2 wording, approved wave 41.
**Gap:** Not in envelope field table. FransDevelopment's Spec 10 §6.2 defines graceful degradation. Relay enforces when present, passes through when absent.
**Action:** Add `expiry_ts` to envelope field table as OPTIONAL (uint, Unix milliseconds). Document relay enforcement behavior. Reference OATR Spec 10 §6.2.

### 2. Deprecated Aliases Sunset (MEDIUM)
**Status:** Bridge compatibility table exists (nonce, ct, aad).
**Gap:** No sunset timeline. Risk: implementations continue emitting aliases indefinitely.
**Action:** Add sunset date (e.g., v1.1 or 6 months after v1.0). Spec MUST emit canonical, SHOULD accept aliases until sunset.

### 3. Security Considerations Section (HIGH — standard requirement)
**Status:** Missing entirely.
**Gap:** Any ratified spec needs a security analysis. Key topics:
- Replay protection (msg_id uniqueness, sequence windowing)
- Nonce reuse prevention (HMAC-SHA256 derivation from msg_id)
- Forward secrecy properties (invite token model = static shared secret; no Double Ratchet in spec)
- Relay as honest-but-curious adversary model
- AAD binding to conversation_id prevents cross-conversation attacks
- Ed25519 signature covers ciphertext only (relay can update metadata — feature, not bug)
- DID field not signed — identity spoofing mitigated by sender_id verification
**Action:** Write §7 Security Considerations.

### 4. Error Handling / Failure Modes (MEDIUM)
**Status:** Not specified.
**Gap:** What should implementations do on:
- CBOR decode failure?
- Signature verification failure?
- Nonce derivation mismatch?
- Unknown CBOR keys?
**Action:** Add §6 Error Handling. MUST ignore unknown fields (forward compatibility). MUST reject bad signatures. SHOULD log and skip malformed envelopes.

### 5. Versioning / Upgrade Path (LOW — but needed for v1.0)
**Status:** `v` field exists, MUST be 1.
**Gap:** What happens when v=2? How do implementations negotiate versions?
**Action:** Add §8 Versioning. v=1 implementations MUST reject v>1 envelopes (fail-safe). Version negotiation is out of scope for v1.0 but reserved.

### 6. Conformance Language (LOW — editorial)
**Status:** Uses informal language.
**Gap:** RFC 2119 MUST/SHOULD/MAY keywords referenced but not formally declared.
**Action:** Add RFC 2119 normative reference in §1.

### 7. Test Vector Completeness (MEDIUM)
**Status:** Invite material + derived keys documented. No full encrypt/decrypt vector.
**Gap:** A complete known-answer test vector (plaintext → ciphertext → decrypted) would prove conformance.
**Action:** Add a full roundtrip vector with specific msg_id, plaintext, expected ciphertext, signature.

## Implementation-Spec Divergences

### qntm (Python) — REFERENCE IMPLEMENTATION
- Implements everything in v0.1.1
- Also implements: expiry_ts relay enforcement, DID resolution, entity verification
- Beyond spec: Double Ratchet for conversation key ratcheting (not in QSP-1 spec)

### APS Bridge (TypeScript) — aeoess
- Wraps APS SignedExecutionEnvelope in QSP-1 for relay transport
- Does NOT yet include expiry_ts
- Uses native `@noble/hashes` for crypto
- Bridge is 369 lines, 18 tests

### AgentID Bridge (Python) — haroldmalikfrimpong-ops
- X3DH + Double Ratchet demo (809 lines)
- Uses PyNaCl
- Does NOT yet include expiry_ts

## Recommended v1.0 Path

1. Add expiry_ts (§4.1 field table, §6.2 enforcement) ← from PR #11
2. Write Security Considerations (§7)
3. Add Error Handling (§6)
4. Add full roundtrip test vector (§5)
5. Formalize RFC 2119 language (§1)
6. Add Versioning (§8)
7. Set deprecated alias sunset timeline
8. Circulate draft to all 4 founding members for review
9. Ratify when 3/4 members sign off

**Estimated effort:** 2-3 waves for draft, 1-2 waves for review cycle.
