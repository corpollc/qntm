# Entity Verification Interface — v0.1.1 DRAFT

## Status
Draft. Staging API live at `api.corpo.llc`. Two implementations proven: qntm (`verify_sender_entity`) and AgentID (`verify_agent_full`). Cross-implementation acceptance tests pass (8 tests, 3 DID methods).

## Purpose
Define the interface for verifying that an agent's cryptographic identity is bound to a legal entity. This extends the DID → key → sender chain with a legal-entity anchor.

## Full Verification Chain

```
DID → resolve Ed25519 key → verify qntm sender key ID → verify Corpo entity → agent has provable legal + cryptographic identity
```

## API

### Verify Entity

```
GET https://api.corpo.llc/api/v1/entities/{entity_id}/verify
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

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `entity_id` | string | Unique entity identifier |
| `name` | string | Legal entity name |
| `status` | string | Entity status: `active`, `suspended`, `dissolved` |
| `entity_type` | string | Entity formation type (e.g. `wyoming_dao_llc`) |
| `authority_ceiling` | string[] | Maximum permissions this entity type supports |
| `verified_at` | string (ISO 8601) | When the entity was last verified |

### Status Alias

```
GET https://api.corpo.llc/api/v1/entities/{entity_id}/status
```

Returns the same response as `/verify`. Available as a convenience alias.

### Error Cases

- `404` — Entity not found
- `410` — Entity dissolved
- Entity with `status: "suspended"` — still returns 200, caller decides policy

## Integration Pattern

### From APS (entityBinding)

```python
# In PrincipalIdentity
entity_binding = {
    "entity_id": "test-entity",
    "verified": True,
    "authority_ceiling": ["hold_assets"]
}
```

APS's `ContentHash` commits to identity-defining fields including entity binding.

### From AgentID (PROVEN)

AgentID's `verify_agent_full()` chains DID resolution → CA certificate → Corpo entity in one call. Shipped and tested against staging API by @haroldmalikfrimpong-ops (Wave 29).

```python
from agentid.did import verify_agent_full

result = verify_agent_full(
    did="did:aps:z6QQ5asBUnXiM4JsgfnG36Gu1Y3zBk4busYKwvnDXEn8N",
    entity_id="test-entity",
    sender_key_id=key_id
)
# → fully_verified: True
# → entity: Test Verification DAO LLC (Wyoming DAO LLC, active)
```

**Bridge to qntm:** AgentID's multi-method `resolve_did()` plugs directly into qntm's `resolve_did_fn` parameter:

```python
from agentid.did import resolve_did

verified, entity = verify_sender_entity(
    sender_key_id=envelope["sender"],
    did=envelope.get("did"),
    entity_id="test-entity",
    resolve_did_fn=resolve_did,  # Handles did:agentid + did:aps
)
```

This pattern is proven by 8 cross-implementation acceptance tests covering `did:agentid`, `did:aps`, and `did:aip` methods.

### From qntm Envelope

```python
def verify_sender_entity(envelope: dict, entity_id: str) -> bool:
    """Verify envelope sender has a valid legal entity."""
    # 1. Verify DID matches sender key ID
    did = envelope.get("did")
    if not did:
        return False
    resolved_key = resolve_did(did)
    sender_kid = sha256(resolved_key)[:16]
    if sender_kid != envelope["sender"]:
        return False
    
    # 2. Verify entity
    resp = requests.get(f"https://api.corpo.llc/api/v1/entities/{entity_id}/verify")
    return resp.status_code == 200 and resp.json()["status"] == "active"
```

## CORS

The staging API has CORS enabled — browser and cross-origin requests work.

## Authentication

The `/verify` endpoint requires no authentication. It's a public verification endpoint.

Production endpoints (entity creation, management) will require authentication — not specified here.

## Cross-Implementation Acceptance Tests

The WG maintains acceptance tests at `python-dist/tests/test_entity_interop.py` that prove the `resolve_did_fn` injection pattern works for all three DID methods:

| Test | DID Method | Resolver | Result |
|------|-----------|----------|--------|
| `test_agentid_resolver_pattern` | `did:agentid` | AgentID | ✅ |
| `test_aps_resolver_pattern` | `did:aps` | APS | ✅ |
| `test_aip_resolver_pattern` | `did:aip` | AIP | ✅ |
| `test_multi_method_resolver` | all three | AgentID-style multi-dispatch | ✅ |
| `test_key_mismatch_rejects` | `did:agentid` | returns wrong key | ✅ rejects |
| `test_entity_suspended_rejects` | `did:agentid` | correct key | ✅ rejects (entity suspended) |
| `test_resolver_failure_rejects` | `did:agentid` | throws error | ✅ rejects gracefully |
| `test_no_did_entity_only` | none | none | ✅ entity-only verification |

## Test Vectors

See [`../test-vectors/entity-verification.json`](../test-vectors/entity-verification.json).
