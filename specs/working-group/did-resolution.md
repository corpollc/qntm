# DID Resolution — v1.0 RATIFIED (UNANIMOUS)

## Status
**v1.0 RATIFIED — UNANIMOUS (2026-03-24).** All 4 founding members signed off.

**Ratification date:** 2026-03-24T05:04:08Z
**Ratification record:** §11

**Changes in rev 2:** Fixed §3.3 (`did:aps`) to include multicodec prefix per WG consensus (aeoess, FransDevelopment, haroldmalikfrimpong-ops). Added local/remote resolution paths for §3.4 (`did:agentid`). Fixed test vector expected values per haroldmalikfrimpong-ops conformance report. Added `Aligning` implementation table.

**DRI:** qntm (@vessenes), with Python reference implementation contributions from @haroldmalikfrimpong-ops.

**Implementations:**
- qntm (`python-dist/src/qntm/did.py`) — `did:web`, `did:key`
- AgentID (`sdk/python/agentid/did.py`) — `did:agentid`, `did:aps`, `did:web`, `did:key`
- APS (`src/identity/`) — `did:aps` (native), `did:web` (via qntm bridge)
- ArkForge (`trust-layer/`) — `did:web` (native)

## 1. Purpose

Define the interface for resolving a DID URI to an Ed25519 public key, enabling QSP-1 envelope sender verification across identity systems.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Resolution Interface

All conformant implementations MUST implement this interface:

```
resolve_did(did_uri: string) → { public_key: bytes(32), method: string, metadata: map }
```

### 2.1 Parameters
- `did_uri` — A DID URI string (e.g. `did:web:example.com`, `did:key:z6Mk...`)

### 2.2 Return Fields
- `public_key` — 32-byte Ed25519 public key. MUST be exactly 32 bytes.
- `method` — DID method name string (e.g. `"web"`, `"key"`, `"aps"`, `"agentid"`)
- `metadata` — Method-specific metadata map. MAY be empty. SHOULD include trust-relevant fields when available (trust score, delegation chain depth, entity binding, verification timestamp).

### 2.3 Error Conditions
Implementations MUST signal errors using one of these error codes:
- `did_not_found` — DID cannot be resolved (network error, 404, DNS failure)
- `key_type_unsupported` — Resolved key is not Ed25519
- `key_extraction_failed` — DID Document exists but key extraction failed (malformed verificationMethod)
- `method_unsupported` — DID method not recognized by this resolver

## 3. Supported DID Methods

### 3.1 `did:web` (REQUIRED)

Conformant implementations MUST support `did:web`.

**Resolution algorithm:**
1. Parse the DID: `did:web:<domain>[:<path>...]`
2. URL-decode the domain component
3. If path components exist: fetch `https://<domain>/<path>/did.json`
4. If no path components: fetch `https://<domain>/.well-known/did.json`
5. Parse the JSON response as a DID Document
6. Extract the Ed25519 public key from `verificationMethod` (see §3.1.1)

**3.1.1 Key extraction priority:**

Implementations MUST check `verificationMethod` entries in this order and use the first Ed25519 key found:

1. `publicKeyMultibase` with type `Ed25519VerificationKey2020` — decode base58btc (strip `z` prefix), strip 2-byte multicodec prefix (`0xed01`). The remaining 32 bytes are the public key.
2. `publicKeyBase58` with type `Ed25519VerificationKey2018` — decode base58. The resulting 32 bytes are the public key.
3. `publicKeyJwk` with `kty: "OKP"`, `crv: "Ed25519"` — base64url-decode the `x` field. The resulting 32 bytes are the public key.

If no Ed25519 key is found, return `key_type_unsupported`.

**3.1.2 HTTP requirements:**

- Implementations MUST use HTTPS (not HTTP)
- Implementations MUST set a descriptive `User-Agent` header (some CDNs block default library agents)
- Implementations SHOULD follow redirects (up to 3 hops)
- Implementations SHOULD timeout after 10 seconds

**Reference:** [W3C DID Web Method](https://w3c-ccg.github.io/did-method-web/)

### 3.2 `did:key` (REQUIRED)

Conformant implementations MUST support `did:key`.

**Resolution algorithm:**
1. Parse the DID: `did:key:<multibase-encoded-key>`
2. Decode the multibase value (z-prefix = base58btc)
3. Check multicodec prefix: `0xed01` for Ed25519
4. Strip the 2-byte prefix. The remaining 32 bytes are the public key.
5. If prefix is not `0xed01`, return `key_type_unsupported`

**Reference:** [W3C DID Key Method](https://w3c-ccg.github.io/did-method-key/)

### 3.3 `did:aps` (RECOMMENDED)

**Resolution algorithm:**
1. Parse the DID: `did:aps:<multibase-encoded-key>`
2. Decode multibase (z-prefix = base58btc)
3. Check multicodec prefix: `0xed01` for Ed25519 (same byte layout as `did:key`)
4. Strip the 2-byte prefix. The remaining 32 bytes are the public key.

The multicodec prefix makes the encoding self-describing — resolvers can verify "this is an Ed25519 key" from the bytes alone, and implementations that already handle `did:key` get `did:aps` with minimal adaptation.

**Legacy alias:** `did:aps:<raw_hex>` (64-character hex, no multibase, no multicodec) is accepted by existing resolvers for backward compatibility. Implementations SHOULD support both formats during the transition period.

**Metadata:** Implementations SHOULD populate `metadata` with delegation chain information when available.

**Reference:** Agent Passport System Module 9 (@aeoess)

### 3.4 `did:agentid` (RECOMMENDED)

**Resolution algorithm:**
1. Parse the DID: `did:agentid:<agent-identifier>`
2. Resolve via one of two paths:
   - **Local resolution:** The agent has the key binding cached from registration (mapping `agent_id` → Ed25519 key). This is the fast path for agents in the same trust domain.
   - **Remote resolution:** Query the AgentID API at `https://getagentid.dev/api/v1/agents/<identifier>/certificate`. Extract the Ed25519 public key from the certificate response.
3. Validate certificate chain (if verification is enabled)

Implementations SHOULD prefer local resolution when available and fall back to remote resolution.

**Metadata:** Implementations SHOULD populate `metadata` with trust score and certificate expiry.

**Reference:** AgentID (@haroldmalikfrimpong-ops)

### 3.5 Additional Methods (OPTIONAL)

Implementations MAY support additional DID methods via a pluggable resolver interface:

```
register_did_method(method_name: string, resolver_fn: function) → void
```

Known methods in the ecosystem:
- `did:agip` — AIP identity protocol (@The-Nexus-Guard). Note: renamed from `did:aip` to avoid W3C Aries collision.

## 4. Sender ID Derivation

Implementations MUST derive the sender ID from the resolved public key using this algorithm:

```
sender_id = SHA-256(public_key)[0:16]
```

This produces a 16-byte (128-bit) identifier that MUST match the QSP-1 envelope `sender` field.

### 4.1 Hex encoding

When displayed or stored as text, the sender_id MUST be encoded as lowercase hexadecimal (32 characters).

## 5. QSP-1 Envelope Verification

When a QSP-1 envelope contains a `did` field, receivers MUST:

1. Resolve the DID to an Ed25519 public key via §3
2. Compute `sender_id` per §4
3. Compare with the envelope's `sender` field
4. **REJECT** the message if they do not match

This ensures the DID holder controls the same key that signed the envelope.

When the `did` field is absent, the envelope is still valid — the receiver verifies via the shared conversation key material instead. The `did` field provides additional identity binding, not replacement of existing verification.

## 6. Cross-Verification

The following cross-project DID resolution paths have been verified with live infrastructure:

| Source | Target | Status |
|--------|--------|--------|
| qntm → `did:web:trust.arkforge.tech` | ArkForge | ✅ Verified (Wave 38) |
| ArkForge → `did:web:inbox.qntm.corpo.llc` | qntm | ✅ Verified (Wave 40) |
| AgentID → `did:aps:z6QQ5...` | APS | ✅ Verified (Wave 27, 10/10) |
| APS → `did:agentid:...` | AgentID | ✅ Verified (Wave 27, 10/10) |
| qntm → `did:web:the-agora.dev` | Agent Agora | ✅ Verified (Wave 43) |

## 7. Security Considerations

### 7.1 DNS and TLS Trust
`did:web` resolution depends on DNS and TLS. Compromised DNS or TLS certificates can redirect resolution to attacker-controlled servers. Implementations SHOULD cache resolved keys and alert on key changes.

### 7.2 Key Rotation
DID Documents MAY change over time (key rotation). Implementations SHOULD NOT cache resolved keys indefinitely. A RECOMMENDED cache TTL is 3600 seconds (1 hour).

### 7.3 Network Partitions
If a DID cannot be resolved (network error), the implementation MUST NOT fall back to an unverified key. The message SHOULD be queued for re-verification when connectivity is restored.

### 7.4 Multicodec Prefix Validation
When decoding `did:key` URIs, implementations MUST verify the multicodec prefix is `0xed01` before treating the remaining bytes as an Ed25519 key. Incorrect prefix handling can lead to key confusion attacks.

### 7.5 User-Agent Filtering
Some CDN providers (including Cloudflare) block requests with default library User-Agent strings. Implementations MUST set a descriptive User-Agent (see §3.1.2).

## 8. Conformance Requirements

A conformant DID Resolution v1.0 implementation:

1. MUST implement `resolve_did()` per §2
2. MUST support `did:web` per §3.1
3. MUST support `did:key` per §3.2
4. MUST derive sender_id per §4
5. MUST verify QSP-1 envelopes with `did` field per §5
6. MUST pass all test vectors in `test-vectors/did-resolution.json`

## 9. Test Vectors

See [`../test-vectors/did-resolution.json`](../test-vectors/did-resolution.json) for conformance test vectors covering:
- `did:key` resolution (Ed25519, multibase z-prefix)
- `did:web` resolution (mock DID Document with Ed25519VerificationKey2020)
- Sender ID derivation from resolved keys
- Error cases (unsupported key type, malformed DID, missing verificationMethod)

## 10. Versioning

This is DID Resolution v1.0. Future versions will:
- Add `did:agip` as RECOMMENDED (pending The-Nexus-Guard name migration)
- Add resolution caching requirements
- Add DID Document signature verification

Changes to REQUIRED methods or the resolution interface require a new major version.

## 11. Ratification

### Founding Members

| Member | Status | Date | Notes |
|--------|--------|------|-------|
| qntm (@vessenes) | ✅ SIGNED OFF | 2026-03-24 | Author |
| OATR (@FransDevelopment) | ✅ SIGNED OFF | 2026-03-24T04:30:00Z | "Sign-off confirmed — 3 blocking items resolved" |
| APS (@aeoess) | ✅ SIGNED OFF | 2026-03-24T05:02:51Z | "rev 2 resolves all three blocking items" + 3 did:aps ↔ did:key equivalence test vectors contributed |
| AgentID (@haroldmalikfrimpong-ops) | ✅ SIGNED OFF | 2026-03-24T05:04:08Z | 8/8 rev 2 vectors pass, resolver updated (4 methods: did:agentid, did:aps, did:key, did:web), 82 tests |

### Aligning Implementations

| Project | Contact | Status | Notes |
|---------|---------|--------|-------|
| Agent Agora | @archedark-ada | Aligning | 8/8 conformance + standalone tool (`tools/did_resolution_conformance.py`), `did:web` resolution live |

### Implementation References

| Project | Resolver | Methods | Tests |
|---------|----------|---------|-------|
| qntm | `python-dist/src/qntm/did.py` | did:web, did:key | 13 |
| AgentID | `sdk/python/agentid/did.py` | did:agentid, did:aps, did:key, did:web | 82 |
| APS | `src/identity/` + `src/core/did.ts` | did:aps (native), did:key, did:web | 23 conformance |
| Agent Agora | `tools/did_resolution_conformance.py` | did:web, did:key | 8 conformance |
