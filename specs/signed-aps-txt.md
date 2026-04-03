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

## Backward Compatibility

- Unsigned aps.txt files remain valid. Agents SHOULD warn but MUST NOT reject.
- Signed aps.txt files with unknown `# Signed-By` DID methods: agents SHOULD attempt resolution, MAY reject if unresolvable.
- The `# Signature:` field is a comment line — parsers that ignore comments will not break.

## DID Method Support

| DID Method | Resolution | Status |
|---|---|---|
| `did:web` | HTTPS fetch of DID document | Recommended |
| `did:moltrust` | MolTrust API or Base L2 on-chain | Supported |
| `did:key` | Inline public key | Supported |
| `did:ion` | ION resolver | Planned |

## Security Considerations

- **DNS hijacking:** Signature prevents content modification but not availability attacks. An attacker controlling DNS can serve a 404 or empty file. Agents SHOULD cache the last known valid signed aps.txt.
- **Key rotation:** If the signer's key is rotated, previously signed aps.txt files become unverifiable against the new key. Publishers SHOULD re-sign within 24h of key rotation.
- **Replay:** The `# Expires:` field prevents indefinite replay. The 30-day `# Signed-At:` staleness check provides a secondary bound.
- **Clock skew:** Verifiers SHOULD allow ±5 minutes of clock skew on `# Signed-At:` and `# Expires:`.

## Reference Implementation

```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonicalize(aps_txt: str) -> bytes:
    lines = aps_txt.split("\n")
    filtered = [
        line.rstrip()
        for line in lines
        if not line.startswith("# Signature:")
        and not line.startswith("# Signed-At:")
        and not line.startswith("# Expires:")
    ]
    # Remove trailing empty lines
    while filtered and filtered[-1] == "":
        filtered.pop()
    return "\n".join(filtered).encode("utf-8")

def sign_aps_txt(aps_txt: str, private_key: Ed25519PrivateKey) -> str:
    payload = canonicalize(aps_txt)
    signature = private_key.sign(payload)
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

def verify_aps_txt(aps_txt: str, public_key: Ed25519PublicKey, signature_b64: str) -> bool:
    payload = canonicalize(aps_txt)
    # Re-pad base64url
    padding = 4 - len(signature_b64) % 4
    if padding != 4:
        signature_b64 += "=" * padding
    signature = base64.urlsafe_b64decode(signature_b64)
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
```

## Relationship to Existing Work

- **robots.txt:** aps.txt extends the robots.txt convention for agent governance. This spec adds signing without changing the directive format.
- **RFC 8785 (JCS):** Not used here — aps.txt is line-oriented, not JSON. Canonicalization is line-based.
- **W3C DID Core:** Signer identity is expressed as a DID. Verification requires DID resolution.
- **Signed HTTP Exchanges (SXG):** SXG signs entire HTTP responses. This spec signs only the aps.txt content, which is simpler and does not require CDN cooperation.

---

*MolTrust / CryptoKRI GmbH, Zurich*
*Apache 2.0*
