# Signed aps.txt Extension Spec

**Status:** Draft
**Author:** MoltyCel (MolTrust)
**Motivation:** AV-2 (aps.txt Manipulation) — unsigned aps.txt allows a malicious publisher to block all agents or redirect governance evaluation. This spec defines a signing extension that makes aps.txt tamper-evident.

---

## Problem

`aps.txt` files are currently unsigned. An attacker controlling DNS or a CDN layer can:
- Replace `Disallow: /` for `User-agent: did:*` to block all agents
- Inject false governance terms without detection
- Replay stale aps.txt files after governance constraints change

## Solution: Ed25519 Signature Header

Add a `Signature:` field to the aps.txt header block:

```
# aps.txt — example.com
# Signed-By: did:web:example.com
# Signature: <base64url Ed25519 signature>
# Signed-At: 2026-04-03T10:00:00Z
# Expires: 2026-04-10T10:00:00Z

User-agent: did:*
Allow: /api/
Disallow: /admin/

Governance: https://example.com/.well-known/governance.json
```

## Signing Procedure

1. **Canonical form:** Strip all `# Signature:`, `# Signed-At:`, `# Expires:` lines from the file. Normalize line endings to `\n`. Trim trailing whitespace per line. No trailing newline.

2. **Payload:** UTF-8 bytes of the canonical form.

3. **Signature:** Ed25519 sign the payload with the private key corresponding to the DID in `# Signed-By`.

4. **Encoding:** Base64url (RFC 4648 §5) without padding.

5. **Insert:** Add `# Signature:`, `# Signed-At:`, `# Expires:` as the last header lines before the first non-comment line.

## Verification Procedure

1. Resolve `# Signed-By` DID to obtain the Ed25519 public key.
2. Strip `# Signature:`, `# Signed-At:`, `# Expires:` lines.
3. Canonicalize (same procedure as signing).
4. Verify Ed25519 signature against canonical payload.
5. Check `# Expires:` — reject if current time > expiry.
6. Check `# Signed-At:` — reject if signed more than 30 days ago (configurable).

## Result

```json
{
  "valid": true,
  "signer": "did:web:example.com",
  "signed_at": "2026-04-03T10:00:00Z",
  "expires": "2026-04-10T10:00:00Z",
  "canonical_hash": "sha256:<64 hex>"
}
```

or

```json
{
  "valid": false,
  "reason": "signature_invalid | expired | signer_unresolvable | missing_signature"
}
```

## Canonical Body

The signed payload is the UTF-8 encoded aps.txt body **excluding** the Signature line itself, with:
- Trailing whitespace stripped per line
- Unix line endings (`\n`)
- No trailing newline

## Verification Flow

1. Fetch `aps.txt` from `/.well-known/aps.txt`
2. Extract `Verification-Key` URL + `Key-ID`
3. Fetch JWKS, select key matching `Key-ID`
4. Reconstruct canonical body (strip Signature line)
5. Verify Ed25519 signature over SHA-256(canonical body)
6. Check `Expires-At` freshness

## Strict Mode Behavior

| Condition | Default Mode | Strict Mode |
|---|---|---|
| Valid signature | proceed | proceed |
| No signature | warn, proceed | reject (`UNSIGNED`) |
| Invalid signature | reject | reject |
| Expired | reject | reject |

Strict mode is opt-in. Recommended for production verifiers.

## Backward Compatibility

- Unsigned aps.txt files remain valid in default mode. Agents SHOULD warn but MUST NOT reject unless strict mode is enabled.
- Signed aps.txt files with unknown `# Signed-By` DID methods: agents SHOULD attempt resolution, MAY reject if unresolvable.
- The `# Signature:` field is a comment line — parsers that ignore comments will not break.

## DID Method Support

| DID Method | Resolution | Status |
|---|---|---|
| `did:web` | HTTPS fetch of DID document | Recommended |
| `did:moltrust` | MolTrust API or Base L2 on-chain | Supported |
| `did:key` | Inline public key | Supported |
| `did:ion` | ION resolver | Planned |

## Reference Implementation

`agent-passport-system@1.31.0` — `verifyApsTxt({ strict: true })`
JWKS endpoint: `gateway.aeoess.com/.well-known/jwks.json`

## MolTrust AV-2 Test Vector

```json
{
  "vector": "AV-2",
  "description": "Unsigned aps.txt in strict mode",
  "input": { "signed": false, "strict": true },
  "expected": "UNSIGNED error, evaluation halted"
}
```

## Security Considerations

- **DNS hijacking:** Signature prevents content modification but not availability attacks. An attacker controlling DNS can serve a 404 or empty file. Agents SHOULD cache the last known valid signed aps.txt.
- **Key rotation:** If the signer's key is rotated, previously signed aps.txt files become unverifiable against the new key. Publishers SHOULD re-sign within 24h of key rotation.
- **Replay:** The `Expires-At` field prevents indefinite replay.
- **Clock skew:** Verifiers SHOULD allow ±5 minutes of clock skew on timestamps.

## Open Questions

- Should `Disallow: /` from an unsigned source be a hard block or warn-only?
- Key rotation: how long should old keys remain valid after rotation?
- Should WG define a canonical JWKS path (e.g. `/.well-known/aps-jwks.json`)?

## Relationship to Existing Work

- **robots.txt:** aps.txt extends the robots.txt convention for agent governance. This spec adds signing without changing the directive format.
- **RFC 8785 (JCS):** Not used here — aps.txt is line-oriented, not JSON. Canonicalization is line-based.
- **W3C DID Core:** Signer identity is expressed as a DID. Verification requires DID resolution.
- **JWKS (RFC 7517):** Key distribution via standard JWKS endpoints for interoperability with APS ecosystem.
- **Signed HTTP Exchanges (SXG):** SXG signs entire HTTP responses. This spec signs only the aps.txt content, which is simpler and does not require CDN cooperation.

---

*MolTrust / CryptoKRI GmbH, Zurich*
*Apache 2.0*
