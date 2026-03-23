# Entity Verification Interface — v0.1 DRAFT

## Status
Draft. Staging API live at `api.corpo.llc`. One test entity verified by two implementations.

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

### From AgentID

```python
def verify_agent_full(did: str) -> dict:
    """Full verification: DID → key → entity."""
    key = resolve_did(did)           # DID → Ed25519 public key
    cert = verify_certificate(did)   # AgentID CA certificate
    entity = verify_entity(cert.entity_id)  # Corpo entity
    return {
        "identity": key,
        "certificate": cert,
        "entity": entity,
        "verified": True
    }
```

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

## Test Vectors

See [`../test-vectors/entity-verification.json`](../test-vectors/entity-verification.json).
