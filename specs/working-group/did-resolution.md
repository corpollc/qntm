# DID Resolution Interface — v0.1 DRAFT

## Status
Draft. Two DID methods implemented and cross-verified (did:agentid, did:aps). DID key method (did:key) supported as generic fallback. did:web documented (already implemented in qntm/did.py).

## Purpose
Define the interface for resolving a DID URI to an Ed25519 public key, enabling qntm envelope sender verification across identity systems.

## Supported DID Methods

### `did:aps:<multibase-encoded-ed25519-public-key>`
- **Owner:** Agent Passport System (@aeoess)
- **Key encoding:** Multibase (z-base58btc prefix)
- **Resolution:** Decode multibase → extract Ed25519 public key
- **Features:** Self-sovereign identity, delegation chains, cascade revocation, signed execution envelopes
- **Reference:** `aeoess/agent-passport-system` Module 9

### `did:agentid:<agent-identifier>`
- **Owner:** AgentID (@haroldmalikfrimpong-ops)
- **Key encoding:** Agent identifier → CA lookup → Ed25519 public key
- **Resolution:** Query AgentID CA → extract certificate → extract Ed25519 public key
- **Features:** CA-issued identity, trust scoring (8-factor), framework integrations (CrewAI, LangChain, MCP)
- **Reference:** `haroldmalikfrimpong-ops/getagentid`

### `did:web:<domain>[:<path>]`
- **Owner:** W3C Credentials Community Group
- **Key encoding:** Three formats supported (in priority order): `publicKeyMultibase` (Ed25519VerificationKey2020, base58btc with 0xed01 multicodec prefix), `publicKeyBase58` (Ed25519VerificationKey2018, legacy), `publicKeyJwk` (OKP/Ed25519, base64url `x` field)
- **Resolution:** `did:web:example.com` fetches `https://example.com/.well-known/did.json`; `did:web:example.com:path:to` fetches `https://example.com/path/to/did.json`. Extracts first Ed25519 key from `verificationMethod` array.
- **Features:** Server-hosted DID document, no blockchain dependency, path-based sub-identities, standard HTTPS transport. Already implemented in `qntm/did.py` (`resolve_did_web`), covered by existing test suite.
- **Reference:** [W3C DID Web Method](https://w3c-ccg.github.io/did-method-web/) / `corpollc/qntm` `python-dist/src/qntm/did.py`

### `did:key:<multibase-encoded-key>`
- **Owner:** W3C DID Key method (generic)
- **Key encoding:** Multicodec prefix (0xed01 for Ed25519) + raw key, multibase encoded
- **Resolution:** Decode multibase → strip multicodec prefix → Ed25519 public key
- **Reference:** [W3C DID Key Method](https://w3c-ccg.github.io/did-method-key/)

## Resolution Interface

All DID methods MUST implement this interface:

```
resolve_did(did_uri: string) → { public_key: bytes(32), method: string, metadata: map }
```

### Return Fields
- `public_key` — 32-byte Ed25519 public key
- `method` — DID method name (e.g. "aps", "agentid", "key")
- `metadata` — Method-specific metadata (trust score, delegation chain, entity binding, etc.)

### Error Cases
- `did_not_found` — DID cannot be resolved
- `key_mismatch` — Resolved key does not match envelope sender
- `method_unsupported` — DID method not recognized

## Verification Rule

When a QSP-1 envelope contains a `did` field, receivers MUST:

1. Resolve the DID to an Ed25519 public key via the appropriate method
2. Compute `Trunc16(SHA-256(resolved_public_key))`
3. Compare with the envelope's `sender` field (16-byte key ID)
4. **REJECT** the message if they don't match

This ensures the DID holder controls the same key that signed the envelope.

## Cross-Verification (Proven)

AgentID and APS have proven mutual DID verification:
- `did:agentid` → resolve → Ed25519 key → derive X25519 → match qntm sender
- `did:aps` → resolve → Ed25519 key → derive X25519 → match qntm sender
- 10/10 cross-checks pass (haroldmalikfrimpong-ops, Wave 27)

## Entity Binding (Extension)

A DID can optionally bind to a legal entity via the Corpo API:

```
DID → resolve key → verify qntm sender → verify Corpo entity → agent has provable legal + cryptographic identity
```

See [`entity-verification.md`](./entity-verification.md) for the entity API interface.
