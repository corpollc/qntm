# Entity Verification — v1.0 RATIFIED (4/4 unanimous)

## Status
**v1.0 RATIFIED (2026-03-24).** All four founding WG members signed off. Third unanimous spec ratification. Conformance test passed (5/5 steps verified across 3 independent projects).

### Ratification Record

| Member | Sign-off | Date | Notes |
|--------|----------|------|-------|
| qntm (spec author) | ✅ | 2026-03-24 | — |
| haroldmalikfrimpong-ops (AgentID) | ✅ | 2026-03-24T07:51Z | All 6 CRs verified against live Corpo staging API |
| aeoess (APS) | ✅ | 2026-03-24T13:45Z | EntityBinding type maps directly; all 6 CRs covered by existing primitives |
| FransDevelopment (OATR) | ✅ | 2026-03-24T09:57Z | Confirmed composition with OATR registry: §2.1 DID chain, §4.4 Path B delegation, §5 pluggable resolver |

**DRI:** qntm (@vessenes)

**Implementations:**
- qntm (`python-dist/src/qntm/entity.py`) — `verify_entity()`, `verify_sender_entity()`
- AgentID (`sdk/python/agentid/did.py`) — `verify_agent_full()`
- ArkForge (`trust-layer/`) — DID binding + execution receipts with `agent_identity`

**Conformance evidence:** desiorac/ArkForge conformance test (2026-03-24): proxy call with DID bound via OATR Path B, receipt `prf_20260324_063814_262a3a`, verified by 3 independent projects (Steps 1-5 all passed).

## 1. Purpose

Define the interface for verifying that an agent's cryptographic identity is bound to a legal entity registration. This extends the DID Resolution chain with a legal-entity anchor, enabling the full verification path:

```
DID → Ed25519 key → sender key ID → legal entity → agent has provable identity
```

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Verification Chain

Entity verification composes three independent verification steps:

### 2.1 Step 1: DID Resolution (REQUIRED)

Resolve the agent's DID to an Ed25519 public key per the DID Resolution v1.0 spec.

```
resolve_did(did_uri) → { public_key: bytes(32), method: string, metadata: map }
```

Implementations MUST use a conformant DID resolver. The DID Resolution v1.0 spec defines supported methods (`did:web` REQUIRED, `did:key` REQUIRED, `did:aps` and `did:agentid` RECOMMENDED).

### 2.2 Step 2: Sender Key Verification (REQUIRED)

Verify that the resolved public key matches the sender's key ID in the QSP-1 envelope:

```
sender_id = Trunc16(SHA-256(public_key))
assert sender_id == envelope.sender
```

Where `Trunc16` means the first 16 bytes (32 hex characters) of the SHA-256 digest. This is the same derivation used in QSP-1 v1.0 (§4).

### 2.3 Step 3: Entity Lookup (REQUIRED)

Query the entity registry to verify the agent's legal entity binding:

```
GET {entity_api}/api/v1/entities/{entity_id}/verify
```

**Response (200 OK):**
```json
{
  "entity_id": "test-entity",
  "name": "Test Verification DAO LLC",
  "status": "active",
  "entity_type": "wyoming_dao_llc",
  "authority_ceiling": ["hold_assets"],
  "verified_at": "2026-03-23T08:26:05Z"
}
```

### 2.4 Entity Status Rules

| Status | Verification Result | Description |
|--------|-------------------|-------------|
| `active` | PASS | Entity is in good standing |
| `suspended` | FAIL | Entity is temporarily suspended |
| `dissolved` | FAIL | Entity has been dissolved (HTTP 410) |
| not found | FAIL | Entity does not exist (HTTP 404) |

Implementations MUST reject suspended and dissolved entities. Implementations MAY treat suspended entities differently from dissolved entities in error reporting, but both MUST fail verification.

## 3. Response Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entity_id` | string | REQUIRED | Unique entity identifier |
| `name` | string | REQUIRED | Legal entity name |
| `status` | string | REQUIRED | Entity status: `active`, `suspended`, `dissolved` |
| `entity_type` | string | REQUIRED | Entity formation type (e.g. `wyoming_dao_llc`) |
| `authority_ceiling` | string[] | REQUIRED | Maximum permissions this entity type supports |
| `verified_at` | string (ISO 8601) | REQUIRED | When the entity was last verified |

## 4. Integration Patterns

### 4.1 Direct Verification (qntm)

```python
from qntm.entity import verify_entity, verify_sender_entity

# Entity-only check
entity = verify_entity("test-entity")
assert entity.is_active

# Full chain: DID → key → sender → entity
verified, entity = verify_sender_entity(
    sender_key_id=envelope["sender"],
    did=envelope.get("did"),
    entity_id="test-entity",
    resolve_did_fn=resolve_did  # Pluggable DID resolver
)
```

### 4.2 Multi-Method Resolution (AgentID)

```python
from agentid.did import verify_agent_full

result = verify_agent_full(
    did="did:aps:z6QQ5...",
    entity_id="test-entity",
    sender_key_id=key_id
)
# → fully_verified: True
# → entity: Test Verification DAO LLC (Wyoming DAO LLC, active)
```

### 4.3 Execution Receipt Binding (ArkForge)

```json
{
  "proof_id": "prf_20260324_063814_262a3a",
  "parties": {
    "agent_identity": "did:web:trust.arkforge.tech",
    "seller": "inbox.qntm.corpo.llc",
    "buyer_fingerprint": "7140..."
  },
  "verified_did": "did:web:trust.arkforge.tech",
  "delegation_path": "OATR Path B (arkforge)"
}
```

The `agent_identity` field in execution receipts SHOULD contain the agent's DID. When present, verifiers SHOULD resolve the DID independently and confirm the key matches the receipt's signing key.

### 4.4 OATR Delegation (Path B)

Entity verification MAY use OATR delegation (Path B) to bind a DID to an OATR-registered issuer identity. The delegation path is:

1. Agent registers in OATR with Ed25519 key and domain verification
2. Agent binds DID to internal key via `POST /v1/keys/bind-did` with `issuer_id` referencing OATR registration
3. Execution receipts include both `agent_identity` (DID) and `delegation_path` (OATR issuer)
4. Verifier checks: DID resolves → key matches → issuer registered in OATR → domain verified

This creates two independent trust anchors: the DID (decentralized) and the OATR registration (registry-attested).

## 5. Pluggable DID Resolver

Implementations MUST support pluggable DID resolvers. The `resolve_did_fn` parameter allows any DID Resolution v1.0-conformant resolver to be injected:

```python
def verify_sender_entity(
    sender_key_id: str,
    did: str | None,
    entity_id: str,
    resolve_did_fn: Callable[[str], bytes] = default_resolver,
    entity_api: str = "https://api.corpo.llc"
) -> tuple[bool, Entity | None]
```

This pattern is proven by 8 cross-implementation acceptance tests covering `did:agentid`, `did:aps`, and `did:aip` methods with AgentID's multi-method resolver.

## 6. Conformance Requirements

### CR-1: Full Chain Verification
A conformant implementation MUST verify all three steps (DID resolution, sender key verification, entity lookup) in sequence. Partial verification (e.g., entity-only without DID) is allowed as a separate function but MUST NOT be called "entity verification."

### CR-2: Status Enforcement
A conformant implementation MUST reject entities with status other than `active`.

### CR-3: Pluggable Resolver
A conformant implementation MUST accept a pluggable DID resolver function. The default resolver MAY support a subset of DID methods, but injection of external resolvers MUST be supported.

### CR-4: Error Propagation
A conformant implementation MUST propagate errors from DID resolution and entity lookup without masking. If DID resolution fails, the error code from DID Resolution v1.0 (§2.3) MUST be available to the caller.

### CR-5: Independent Verification
A conformant implementation MUST NOT require the verifier to trust the agent's self-reported identity. All identity claims MUST be verified independently (resolve the DID, check the sender_id derivation, query the entity registry).

### CR-6: Receipt Cross-Check
When verifying execution receipts with an `agent_identity` field, a conformant implementation SHOULD resolve the DID independently and confirm the key matches the receipt's signing key. This cross-check detects receipts with self-declared but unverified identity.

## 7. Security Considerations

### 7.1 Entity API Trust
The entity verification endpoint is a centralized trust anchor. Implementations SHOULD validate the TLS certificate of the entity API endpoint. Implementations SHOULD cache entity status with a reasonable TTL (RECOMMENDED: 300 seconds) to reduce API load while maintaining freshness.

### 7.2 Replay Prevention
Entity verification is point-in-time. An entity that was `active` when verified may be `suspended` or `dissolved` by the time the verification result is used. Implementations SHOULD re-verify entity status for long-running operations.

### 7.3 DID Binding Trust Model
Path A (challenge-response) provides direct proof of key control. Path B (OATR delegation) provides registry-attested binding. Both are valid but have different trust properties:

- **Path A:** Stronger proof (direct challenge-response), but requires the entity API to support challenge-response.
- **Path B:** Registry-attested (OATR issuer registered and domain-verified), but trusts the OATR registry.

Implementations SHOULD document which path they use and MAY support both.

### 7.4 Multi-Agent Sessions
When multiple agents participate in a conversation, each agent's entity verification is independent. Implementations MUST NOT assume that verifying one agent's entity applies to other agents in the same conversation.

### 7.5 Authority Ceiling
The `authority_ceiling` field defines the maximum permissions an entity type supports. Implementations SHOULD check that the requested action falls within the entity's authority ceiling. For example, a `wyoming_dao_llc` with `authority_ceiling: ["hold_assets"]` SHOULD NOT be authorized to perform actions outside that scope.

## 8. Cross-Implementation Acceptance Tests

| Test | DID Method | Resolver | Result |
|------|-----------|----------|--------|
| `test_agentid_resolver_pattern` | `did:agentid` | AgentID | ✅ |
| `test_aps_resolver_pattern` | `did:aps` | APS | ✅ |
| `test_aip_resolver_pattern` | `did:aip` | AIP | ✅ |
| `test_multi_method_resolver` | all three | multi-dispatch | ✅ |
| `test_key_mismatch_rejects` | `did:agentid` | wrong key | ✅ rejects |
| `test_entity_suspended_rejects` | `did:agentid` | correct key | ✅ (suspended) |
| `test_resolver_failure_rejects` | `did:agentid` | throws error | ✅ graceful |
| `test_no_did_entity_only` | none | none | ✅ entity-only |

## 9. Conformance Test Record

### First conformance test: 2026-03-24

**Participants:** desiorac (ArkForge), qntm, FransDevelopment (OATR)

| Step | Description | Result | Verifier |
|------|-------------|--------|----------|
| 1 | Proxy call with DID bound via OATR Path B | ✅ | desiorac |
| 2 | Receipt posted: `prf_20260324_063814_262a3a` | ✅ | desiorac |
| 3 | DID resolution: `did:web:trust.arkforge.tech` → `174e20acd605f8ce6fca394246729bd7` | ✅ | qntm |
| 4 | OATR delegation: issuer active, pubkey match, proof-of-key-ownership, domain | ✅ | FransDevelopment |
| 5 | Receipt `agent_identity` = resolved DID = same key = same sender_id | ✅ | cross-check |

Three independent projects verified different segments of the same trust chain without runtime coordination. This demonstrates the composable verification model.

## 10. Test Vectors

See [`../test-vectors/entity-verification.json`](../test-vectors/entity-verification.json).

## 11. Versioning

This document follows the same versioning conventions as QSP-1 v1.0 (§8) and DID Resolution v1.0 (§10).

## 12. References

- [QSP-1 v1.0 RATIFIED](./qsp1-envelope.md) — Envelope format and sender_id derivation
- [DID Resolution v1.0 RATIFIED](./did-resolution.md) — DID → Ed25519 resolution interface
- [OATR Spec 10](https://github.com/FransDevelopment/open-agent-trust-registry/blob/main/spec/10-encrypted-transport.md) — Registry-bound encrypted transport
- [OATR Spec 11](https://github.com/FransDevelopment/open-agent-trust-registry/blob/main/spec/11-proof-of-key-ownership.md) — Proof-of-key-ownership
