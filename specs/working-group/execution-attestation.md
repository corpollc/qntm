# A2A Interaction Receipt — v0.1 DRAFT

**Status:** RATIFIED — v0.1
**DRI:** desiorac (ArkForge)
**Reference implementation:** [trust.arkforge.tech](https://trust.arkforge.tech) · [proof-spec v2.1.3](https://github.com/ark-forge/proof-spec)

| Member | Project | Sign-off | Date |
|--------|---------|----------|------|
| desiorac | ArkForge Trust Layer | ✓ | 2026-03-25 |
| aeoess | Agent Passport System | ✓ | 2026-03-25 |
| haroldmalikfrimpong-ops | AgentID | ✓ | 2026-03-25 |
| FransDevelopment | OATR | ✓ | 2026-03-25 |

---

## §1 Purpose

This spec defines a **verifiable receipt format** for agent-to-agent HTTP calls. It answers a distinct question from the other WG specs:

| Spec | Question answered |
|------|------------------|
| DID Resolution | Who is this agent? |
| Entity Verification | Is this agent authorized? |
| QSP-1 | Is this message confidential and authentic? |
| **A2A Interaction Receipt** | **Was this request actually sent to this target, and what did it respond?** |

An A2A Interaction Receipt is a cryptographically sealed record produced by a certifying proxy. It binds the request hash, response hash, caller identity, target, and timestamp — without inspecting the semantic content of the call. It proves the I/O pair of an agent-to-agent HTTP transaction, not the meaning of the action itself.

Any third party — auditor, regulator, counterparty — can independently verify a receipt without access to the issuer's infrastructure.

This spec is composable with DID Resolution v1.0, Entity Verification v1.0, and QSP-1 v1.0. It does not replace any of them.

Key words: MUST, MUST NOT, SHOULD, MAY as defined in RFC 2119.

---

## §2 Receipt Structure

A receipt is a JSON object. It MUST contain the following fields:

### §2.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `proof_id` | string | Unique proof identifier. Recommended format: `prf_<YYYYMMDD>_<HHMMSS>_<6hex>` |
| `timestamp` | string | ISO 8601 UTC timestamp of proof creation (e.g. `2026-03-25T14:00:00Z`) |
| `hashes.request` | string | SHA-256 of canonical JSON request. Format: `sha256:<hex>` |
| `hashes.response` | string | SHA-256 of canonical JSON response. Format: `sha256:<hex>` |
| `hashes.chain` | string | Chain hash binding all components. Format: `sha256:<hex>` |
| `parties.agent_fingerprint` | string | SHA-256 of the executing agent's API key or credential (hex) |
| `parties.target` | string | Target service domain or endpoint (e.g. `api.example.com`) |

### §2.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `spec_version` | string | Proof format version (e.g. `"1.0"`) |
| `parties.agent_identity` | string | Agent DID or self-declared name. If cryptographically verified, takes precedence over any caller-declared value |
| `parties.agent_identity_verified` | bool | `true` if `agent_identity` is a verified DID bound via Ed25519 challenge-response or OATR delegation |
| `parties.did_resolution_status` | string | `"bound"` (verified DID) or `"unverified"` (self-declared) |
| `parties.agent_version` | string | Executing agent's version string |
| `issuer_signature` | string | Ed25519 signature of the chain hash. Format: `ed25519:<base64url>` |
| `issuer_pubkey` | string | Ed25519 public key of the attesting party. Format: `ed25519:<base64url>` |
| `timestamp_authority` | object | RFC 3161 TSA metadata (see §4.1) |
| `transparency_log` | object | Sigstore Rekor entry (see §4.2) |
| `upstream_timestamp` | string | HTTP `Date` header from the target service. Included in chain hash when present |
| `transaction_success` | bool | Whether the target service returned a success response |
| `upstream_status_code` | int | HTTP status code returned by the target service |

### §2.3 Minimal Example

```json
{
  "proof_id": "prf_20260325_140000_a1b2c3",
  "timestamp": "2026-03-25T14:00:00Z",
  "hashes": {
    "request":  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "response": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "chain":    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  "parties": {
    "agent_fingerprint": "7c8f263e06d5ce4681f750ad64ede882a4ebd87de60f9ae0e6b06f0300645a11",
    "target": "api.example.com"
  }
}
```

### §2.4 Full Example

```json
{
  "proof_id": "prf_20260325_140000_a1b2c3",
  "spec_version": "1.0",
  "timestamp": "2026-03-25T14:00:00Z",
  "hashes": {
    "request":  "sha256:<hex>",
    "response": "sha256:<hex>",
    "chain":    "sha256:<hex>"
  },
  "parties": {
    "agent_fingerprint": "<hex>",
    "target": "api.example.com",
    "agent_identity": "did:web:agent.example.com",
    "agent_identity_verified": true,
    "did_resolution_status": "bound",
    "agent_version": "1.0.0"
  },
  "issuer_signature": "ed25519:<base64url>",
  "issuer_pubkey":    "ed25519:<base64url>",
  "upstream_timestamp": "Tue, 25 Mar 2026 14:00:01 GMT",
  "transaction_success": true,
  "upstream_status_code": 200,
  "timestamp_authority": {
    "status": "verified",
    "provider": "freetsa.org",
    "tsr_base64": "<base64>"
  },
  "transparency_log": {
    "provider": "sigstore-rekor",
    "status": "verified",
    "uuid": "<uuid>",
    "log_index": 12345678,
    "verify_url": "https://search.sigstore.dev/?logIndex=12345678"
  }
}
```

---

## §3 Chain Hash Algorithm

The chain hash seals all components of an execution into a single verifiable value. Modifying any bound field invalidates the chain hash.

### §3.1 Algorithm

> **Producer scope (see §1):** The chain hash is computed and signed by a certifying proxy — not by the executing agent itself. Self-attestation by the agent is explicitly out of scope.

```
chain_data = {
  "agent_fingerprint": <hex>,
  "request_hash":      <hex>,        // strip "sha256:" prefix
  "response_hash":     <hex>,        // strip "sha256:" prefix
  "target":            <string>,
  "timestamp":         <ISO 8601>,
  // optional — include only when present and non-null:
  "upstream_timestamp": <string>,
}

chain_hash = SHA256(canonical_json(chain_data))
```

Canonical JSON: keys sorted alphabetically, no whitespace (`json.dumps(d, sort_keys=True, separators=(",", ":"))`).

### §3.2 Reference Implementation

```python
import json, hashlib

def canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))

def compute_chain_hash(
    agent_fingerprint: str,
    request_hash: str,       # with or without "sha256:" prefix
    response_hash: str,
    target: str,
    timestamp: str,
    upstream_timestamp: str | None = None,
) -> str:
    data = {
        "agent_fingerprint": agent_fingerprint,
        "request_hash":      request_hash.removeprefix("sha256:"),
        "response_hash":     response_hash.removeprefix("sha256:"),
        "target":            target,
        "timestamp":         timestamp,
    }
    if upstream_timestamp:
        data["upstream_timestamp"] = upstream_timestamp
    return hashlib.sha256(
        canonical_json(data).encode("utf-8")
    ).hexdigest()
```

### §3.3 Agent Fingerprint Derivation

The agent fingerprint is a SHA-256 hash of the agent's credential (API key or access token). It identifies the executing agent without exposing the credential:

```
agent_fingerprint = SHA256(credential_string).hexdigest()
```

### §3.4 What the Chain Hash Binds

| Bound | Not Bound (mutable metadata) |
|-------|------------------------------|
| `hashes.request` | `transaction_success` |
| `hashes.response` | `upstream_status_code` |
| `parties.agent_fingerprint` | `timestamp_authority` |
| `parties.target` | `transparency_log` |
| `timestamp` | `parties.agent_version` |
| `upstream_timestamp` (if present) | |

Verifiers MUST NOT include mutable metadata fields in chain hash recomputation.

---

## §4 Independent Witnesses

A receipt SHOULD be corroborated by one or more independent witnesses. Witnesses are additive — each layer independently verifiable without the others.

| Witness | What it proves | Verification method |
|---------|---------------|---------------------|
| **Ed25519 Signature** | Proof was issued by the attesting party | Verify `issuer_signature` with `issuer_pubkey` |
| **RFC 3161 Timestamp** | Proof existed at the claimed time | `openssl ts -verify` on the `.tsr` file |
| **Sigstore Rekor** | Chain hash registered in public append-only log | Fetch `transparency_log.log_url` or visit `verify_url` |

A receipt with zero witnesses is valid (chain hash integrity only). Each witness adds an independent trust layer. Attestors SHOULD provide at least one external witness.

### §4.1 RFC 3161 Timestamp Authority

```json
{
  "timestamp_authority": {
    "status": "verified",
    "provider": "freetsa.org",
    "algorithm": "sha256",
    "tsr_download_url": "https://trust.arkforge.tech/v1/proof/<proof_id>/tsr",
    "tsr_base64": "<base64-encoded .tsr file>"
  }
}
```

If the TSA is unavailable at proof creation, `status` is `"failed"`. The proof remains valid.

### §4.2 Sigstore Rekor Transparency Log

```json
{
  "transparency_log": {
    "provider": "sigstore-rekor",
    "status": "verified",
    "uuid": "<entry UUID>",
    "log_index": 12345678,
    "integrated_time": 1743000000,
    "log_url": "https://rekor.sigstore.dev/api/v1/log/entries/<uuid>",
    "verify_url": "https://search.sigstore.dev/?logIndex=12345678"
  }
}
```

`transparency_log` is post-chain-hash metadata. It MUST NOT be included in chain hash computation.

---

## §5 Agent Identity Binding

Execution proofs MAY include a cryptographically verified agent identity. This composes with DID Resolution v1.0 and Entity Verification v1.0.

### §5.1 Binding Paths

| Path | Mechanism | `agent_identity_verified` |
|------|-----------|--------------------------|
| **Path A** | Ed25519 challenge-response: agent signs a time-bound nonce with its DID private key | `true` |
| **Path B** | OATR delegation: issuer manifest confirms agent DID is an active delegatee | `true` |
| **Unverified** | Self-declared string in request | `false` or absent |

### §5.2 Verified Identity in Proofs

When a DID is bound to the agent credential (Path A or Path B), the attesting party MUST populate:

```json
{
  "parties": {
    "agent_identity": "did:web:agent.example.com",
    "agent_identity_verified": true,
    "did_resolution_status": "bound"
  }
}
```

The attesting party MUST NOT set `agent_identity_verified: true` for self-declared identities.

### §5.3 Composition with Entity Verification v1.0

A receipt with a verified DID (`agent_identity_verified: true`) satisfies the "Sender Key Verification" step (§2.2) of Entity Verification v1.0. Attestors implementing both specs SHOULD cross-reference the proof in the entity verification response.

---

## §6 Independent Verification Procedure

Any party can verify a receipt without the attesting party's infrastructure:

```python
import json, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

def verify_proof(proof: dict) -> bool:
    """Returns True if chain hash is valid. Raises on signature failure."""

    # Step 1 — Recompute chain hash
    rh = proof["hashes"]["request"].removeprefix("sha256:")
    rsp = proof["hashes"]["response"].removeprefix("sha256:")
    data = {
        "agent_fingerprint": proof["parties"]["agent_fingerprint"],
        "request_hash":      rh,
        "response_hash":     rsp,
        "target":            proof["parties"]["target"],
        "timestamp":         proof["timestamp"],
    }
    if proof.get("upstream_timestamp"):
        data["upstream_timestamp"] = proof["upstream_timestamp"]

    computed = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected = proof["hashes"]["chain"].removeprefix("sha256:")

    if computed != expected:
        return False  # chain hash mismatch — tampered

    # Step 2 (optional) — Verify Ed25519 signature if present
    if "issuer_signature" in proof:
        def b64url_decode(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)

        pub = Ed25519PublicKey.from_public_bytes(
            b64url_decode(proof["issuer_pubkey"].removeprefix("ed25519:"))
        )
        pub.verify(
            b64url_decode(proof["issuer_signature"].removeprefix("ed25519:")),
            computed.encode("utf-8")
        )
        # raises InvalidSignature if tampered

    return True
```

### §6.1 What Verification Proves

- The request/response pair is authentic (hashes bound)
- The agent fingerprint is bound to this execution
- The timestamp is bound to this execution
- No chain-hash-bound field was modified after proof creation

### §6.2 What Verification Does NOT Prove

- That the agent is the one it claims to be (use DID Resolution v1.0 for identity)
- That the agent was authorized to act (use Entity Verification v1.0)
- That the timestamp is accurate (use RFC 3161 TSA)
- That the response content is semantically correct (use application-layer validation)

---

## §7 Issuer Key Distribution

The attesting party's public key SHOULD be served at two canonical endpoints:

| Endpoint | Format |
|----------|--------|
| `GET /v1/pubkey` | `{"pubkey": "ed25519:<base64url>", "algorithm": "Ed25519"}` |
| `GET /.well-known/did.json` | W3C DID Document with `Ed25519VerificationKey2020` |

The public key SHOULD also be embedded in each proof (`issuer_pubkey`). Verifiers SHOULD pin the key from a trusted source rather than relying solely on the in-proof field.

The attesting party's DID MUST be resolvable via DID Resolution v1.0 (§3 — supported methods).

---

## §8 Conformance Requirements

**CR-1: Chain Hash.** A conformant implementation MUST compute the chain hash using canonical JSON as defined in §3.1. String concatenation is not conformant.

**CR-2: Required Fields.** A conformant proof MUST include all fields listed in §2.1. A proof missing any required field MUST be rejected by verifiers.

**CR-3: Identity Claims.** A conformant attestor MUST NOT set `agent_identity_verified: true` for self-declared identities. Identity verification MUST follow Path A or Path B (§5.1).

**CR-4: Witness Immutability.** Fields listed as "Not Bound" in §3.4 MUST NOT be included in chain hash recomputation. Verifiers MUST ignore them during integrity verification.

**CR-5: Transparency Log Exclusion.** `transparency_log` is post-chain-hash metadata. It MUST NOT be included in chain hash recomputation.

**CR-6: Key Distribution.** A conformant attestor MUST serve its Ed25519 public key at `/.well-known/did.json` as a resolvable DID Document.

---

## §9 Security Considerations

### §9.1 Threat Model

A receipt protects against post-hoc tampering with the request, response, agent identity, or timestamp. It does not protect against a malicious attestor fabricating a receipt for a call that never occurred.

Mitigations: independent witnesses (RFC 3161, Rekor) bind the chain hash to an external timeline; DID binding (§5) links the agent fingerprint to a verifiable identity; OATR registry provides revocation.

### §9.2 Agent Fingerprint Collision

SHA-256 pre-image resistance protects the credential from reverse-derivation. However, two agents sharing the same credential produce the same fingerprint. Attestors MUST issue unique credentials per agent instance.

### §9.3 Timestamp Accuracy

The `timestamp` field is attesting-party-controlled. Verifiers requiring accurate timestamps MUST verify the RFC 3161 TSA token independently.

### §9.4 DID Binding Trust Model

`agent_identity_verified: true` reflects the attestor's verification at binding time. It does not guarantee the DID is still active at proof creation time. Verifiers requiring current DID status MUST resolve the DID at verification time using DID Resolution v1.0.

### §9.5 Replay Attacks

A valid proof is not replayable — it binds a specific request/response pair. An attacker replaying the same API call would produce a different `hashes.response` (different timestamp, nonce, or state). Attestors SHOULD include `upstream_timestamp` when available to further bind the execution timeline.

---

## §10 Composition Example

The following shows a complete 6-layer stack interaction:

```
1. Discovery     Agent Card (/.well-known/agent.json) advertises capabilities
2. Identity      DID Resolution v1.0 — resolve did:web:agent.example.com
3. Authorization Entity Verification v1.0 — confirm agent is active issuer
4. Transport     QSP-1 v1.0 — Ed25519→X25519→XChaCha20-Poly1305 encrypted call
5. Attestation   THIS SPEC — chain hash seals request/response/identity/timestamp
6. Registry      OATR — proof references issuer_id for revocation checks
```

A fully composed proof:

```json
{
  "proof_id": "prf_20260325_140000_a1b2c3",
  "spec_version": "1.0",
  "timestamp": "2026-03-25T14:00:00Z",
  "hashes": {
    "request":  "sha256:<hex>",
    "response": "sha256:<hex>",
    "chain":    "sha256:<hex>"
  },
  "parties": {
    "agent_fingerprint":      "<hex>",
    "target":                 "api.example.com",
    "agent_identity":         "did:web:agent.example.com",
    "agent_identity_verified": true,
    "did_resolution_status":  "bound"
  },
  "issuer_signature": "ed25519:<base64url>",
  "issuer_pubkey":    "ed25519:<base64url>",
  "qsp1_envelope_ref": "relay:dca83b70ccd763a89b5953b2cd2ee678",
  "oatr_issuer_id":   "arkforge",
  "timestamp_authority": { "status": "verified", "provider": "freetsa.org" },
  "transparency_log":   { "provider": "sigstore-rekor", "status": "verified" }
}
```

---

## §11 Test Vectors

See [`test-vectors-execution-attestation.json`](test-vectors-execution-attestation.json).

Implementers MUST pass all test vectors to claim conformance. Vectors include:
- Minimal proof (required fields only)
- Full proof with all optional fields
- Proof with `upstream_timestamp`
- Adversarial cases: tampered `hashes.chain`, tampered `parties.agent_fingerprint`, wrong Ed25519 signature

---

## §12 Versioning

- **Patch** (0.x.y): clarifications, typo fixes, new test vectors
- **Minor** (0.x.0): new optional fields, new witness types
- **Major** (1.0.0): breaking change to chain hash algorithm or required fields

This spec is in DRAFT until ratified by ≥3 WG members.

---

## §13 References

- DID Resolution v1.0 (this WG)
- Entity Verification v1.0 (this WG)
- QSP-1 v1.0 (this WG)
- ArkForge Proof Specification v2.1.3 — https://github.com/ark-forge/proof-spec
- W3C DID Core — https://www.w3.org/TR/did-core/
- RFC 3161 — Internet X.509 PKI Timestamp Protocol
- Sigstore Rekor — https://rekor.sigstore.dev

---

## Changelog

| Version | Date | Description |
|---------|------|-------------|
| 0.1 | 2026-03-25 | Initial DRAFT — submitted for WG review |
