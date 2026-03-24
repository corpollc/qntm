# Compliance Receipts — v0.1 DRAFT

## Status
**v0.1 DRAFT (2026-03-24).** Born from organic WG discussion: desiorac identified compliance proof requirements for data-regulated markets, haroldmalikfrimpong-ops committed to per-handoff signed receipts for a 12-country pipeline. This spec formalizes the pattern.

**DRI:** qntm (@vessenes)

**Origin:**
- desiorac (#5, 2026-03-24): "clients in data-regulated markets will eventually ask for proof of handling, not just your Telegram report."
- haroldmalikfrimpong-ops (#5, 2026-03-24): "Adding Ed25519 signed receipts at each step... the infrastructure is already there."
- Composes: ArkForge proof-spec receipt format + AgentID certificate chain + qntm encrypted transport.

## 1. Purpose

Define a standard format for per-handoff signed receipts in multi-agent pipelines. Each agent in a pipeline signs a receipt attesting to its processing of data at each handoff point, creating a verifiable chain of custody.

This spec addresses the compliance requirement: **prove that data was handled correctly at every step**, not just at ingress and egress.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Motivation

Multi-agent pipelines processing data across jurisdictions (e.g., lead generation across 12 countries with different data residency rules) face a compliance challenge: regulators and clients need proof that data was handled according to policy at each processing step, not just that results were delivered.

Current approaches:
- **Telegram/email reports** — human-readable but not cryptographically verifiable
- **Database logs** — verifiable only by the operator, not by external auditors
- **End-to-end receipts** — prove ingress/egress but not intermediate handling

Compliance receipts fill the gap: each agent in the pipeline signs a receipt that includes what it received, what it did, and what it passed on — with a hash chain linking receipts.

## 3. Receipt Format

### 3.1 Receipt Structure (REQUIRED)

A compliance receipt MUST be a JSON object containing:

```json
{
  "version": "compliance-receipt-v0.1",
  "receipt_id": "<unique receipt identifier>",
  "pipeline_id": "<pipeline execution identifier>",
  "step": {
    "index": 2,
    "agent_did": "did:agentid:scout-agent-001",
    "role": "Scout",
    "timestamp": "2026-03-24T08:30:00Z"
  },
  "input_hash": "<SHA-256 of received payload>",
  "output_hash": "<SHA-256 of produced payload>",
  "previous_receipt_hash": "<SHA-256 of previous receipt in chain, null for first>",
  "policy": {
    "jurisdiction": "DE",
    "data_categories": ["contact_info", "company_info"],
    "retention_policy": "30d",
    "processing_basis": "legitimate_interest"
  },
  "signature": "<Ed25519 signature over canonical receipt>"
}
```

### 3.2 Receipt Chain (REQUIRED)

Receipts MUST form a hash chain: each receipt's `previous_receipt_hash` MUST contain the SHA-256 hash of the immediately preceding receipt in the pipeline. The first receipt in a pipeline MUST set `previous_receipt_hash` to `null`.

Implementations MUST use canonical JSON (sorted keys, no whitespace) for hashing.

### 3.3 Signature (REQUIRED)

The `signature` field MUST be an Ed25519 signature over the SHA-256 hash of the canonical receipt (with the `signature` field removed). The signing key MUST be the agent's identity key as registered in its DID Document.

Verifiers MUST resolve the agent's DID (per DID Resolution v1.0) and verify the signature against the resolved Ed25519 public key.

### 3.4 Policy Declaration (RECOMMENDED)

The `policy` object SHOULD declare:
- `jurisdiction` — ISO 3166-1 alpha-2 country code where processing occurred
- `data_categories` — array of data category identifiers processed
- `retention_policy` — retention period (ISO 8601 duration or human-readable)
- `processing_basis` — legal basis for processing (e.g., consent, legitimate_interest, contract)

Implementations MAY extend the policy object with additional fields.

## 4. Verification

### 4.1 Single Receipt Verification (REQUIRED)

To verify a single receipt, a verifier MUST:

1. Resolve `step.agent_did` to an Ed25519 public key (DID Resolution v1.0)
2. Verify `signature` against the resolved key
3. If Entity Verification is available, verify the agent's DID is bound to a registered entity (Entity Verification v1.0)

### 4.2 Chain Verification (REQUIRED)

To verify a receipt chain, a verifier MUST:

1. Verify each receipt individually (§4.1)
2. Verify `previous_receipt_hash` linkage: for each receipt at index > 0, `previous_receipt_hash` MUST equal SHA-256 of the preceding receipt's canonical form
3. Verify `input_hash` consistency: each receipt's `input_hash` SHOULD match the preceding receipt's `output_hash` (RECOMMENDED but not REQUIRED — agents may transform data)

### 4.3 Cross-Host Verification (RECOMMENDED)

When pipeline agents run on different hosts, receipt exchange SHOULD use encrypted transport (QSP-1) to ensure receipts are not tampered with in transit. The relay provides a tamper-proof audit trail that survives individual host failures.

## 5. Transport

### 5.1 Same-Host (MAY)

When all agents in a pipeline run on the same host, receipts MAY be exchanged via local storage (SQLite, filesystem). No transport layer is required.

### 5.2 Multi-Host (RECOMMENDED)

When agents run on different hosts, receipts SHOULD be wrapped in QSP-1 envelopes and exchanged via the qntm relay. This provides:
- End-to-end encryption (receipts are sensitive compliance data)
- Durable storage (relay persists receipts beyond host lifetime)
- Third-party audit (relay operator cannot read receipts but can attest to delivery timestamps)

## 6. Composability

This spec composes with:
- **DID Resolution v1.0** — resolve agent identity for signature verification
- **Entity Verification v1.0** — bind agent identity to legal entity registration
- **QSP-1 v1.0** — encrypted transport for cross-host receipt exchange
- **ArkForge proof-spec** — compatible receipt format (desiorac's `prf_*` identifiers)
- **OATR** — trust registry for verifying issuer legitimacy
- **Decision Attestation** (proposed) — verify decision consistency across receipt chain

## 7. Security Considerations

### 7.1 Receipt Integrity

Receipts MUST be signed before transmission. Unsigned receipts MUST be rejected by verifiers.

### 7.2 Clock Synchronization

Timestamps in receipts are self-declared by agents. Verifiers SHOULD NOT rely on timestamps alone for ordering — use the hash chain for definitive ordering.

### 7.3 Data Minimization

Receipts contain hashes, not data. The `input_hash` and `output_hash` fields commit to data without revealing it. Full data disclosure is a separate process controlled by the data controller.

### 7.4 Replay Protection

Each receipt's `receipt_id` MUST be unique. Implementations SHOULD use UUIDv7 or similar time-ordered identifiers.

### 7.5 Jurisdiction Conflicts

When pipeline steps span jurisdictions with conflicting data protection requirements, the receipt chain documents the conflict. Resolution is out of scope for this spec — compliance officers use the receipt chain as evidence for conflict resolution.

## 8. Conformance Requirements

| ID | Requirement | Level |
|----|-------------|-------|
| CR-1 | Receipt MUST contain all fields in §3.1 | REQUIRED |
| CR-2 | Signature MUST be Ed25519 over canonical JSON hash | REQUIRED |
| CR-3 | Hash chain MUST link via previous_receipt_hash | REQUIRED |
| CR-4 | Agent DID MUST resolve via DID Resolution v1.0 | REQUIRED |
| CR-5 | Policy declaration SHOULD include jurisdiction | RECOMMENDED |
| CR-6 | Multi-host exchange SHOULD use QSP-1 transport | RECOMMENDED |

## 9. Test Vectors

_To be added when first implementation ships._

## 10. References

- [QSP-1 v1.0](qsp1-envelope.md) — Envelope format and encryption
- [DID Resolution v1.0](did-resolution.md) — DID to public key resolution
- [Entity Verification v1.0](entity-verification.md) — Legal entity binding
- [ArkForge proof-spec](https://github.com/ark-forge/proof-spec) — Execution attestation format
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Requirement keywords
