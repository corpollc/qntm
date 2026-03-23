"""DID resolution for the Agent Identity Working Group.

Supports did:web (W3C standard) and did:key (Ed25519 only).
Used by verify_sender_entity() to resolve DID URIs to Ed25519 public keys.

References:
- did:web spec: https://w3c-ccg.github.io/did-method-web/
- did:key spec: https://w3c-ccg.github.io/did-method-key/
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DIDDocument:
    """Parsed DID Document."""

    id: str
    verification_methods: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def ed25519_public_key(self) -> Optional[bytes]:
        """Extract the first Ed25519 public key from verificationMethod.

        Looks for Ed25519VerificationKey2020 or Ed25519VerificationKey2018
        with publicKeyMultibase or publicKeyBase58.
        """
        import base64

        for vm in self.verification_methods:
            vm_type = vm.get("type", "")
            if "Ed25519" not in vm_type:
                continue

            # publicKeyMultibase (preferred, multicodec-prefixed)
            if "publicKeyMultibase" in vm:
                mb = vm["publicKeyMultibase"]
                if mb.startswith("z"):
                    # base58btc encoded
                    raw = _base58_decode(mb[1:])
                    # Ed25519 multicodec prefix is 0xed01 (2 bytes)
                    if len(raw) == 34 and raw[0] == 0xED and raw[1] == 0x01:
                        return raw[2:]
                    if len(raw) == 32:
                        return raw

            # publicKeyBase58 (legacy)
            if "publicKeyBase58" in vm:
                return _base58_decode(vm["publicKeyBase58"])

            # publicKeyJwk
            if "publicKeyJwk" in vm:
                jwk = vm["publicKeyJwk"]
                if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                    x = jwk["x"]
                    # base64url decode
                    padding = 4 - len(x) % 4
                    if padding != 4:
                        x += "=" * padding
                    return base64.urlsafe_b64decode(x)

        return None

    def service_endpoint(self, service_type: str) -> Optional[str]:
        """Find a service endpoint by type."""
        for svc in self.services:
            if svc.get("type") == service_type:
                ep = svc.get("serviceEndpoint")
                if isinstance(ep, str):
                    return ep
        return None


class DIDResolutionError(Exception):
    """Raised when DID resolution fails."""
    pass


def resolve_did_web(did_uri: str, *, timeout: float = 10.0) -> DIDDocument:
    """Resolve a did:web URI to a DID Document.

    did:web:example.com → https://example.com/.well-known/did.json
    did:web:example.com:path:to → https://example.com/path/to/did.json

    Args:
        did_uri: The did:web URI to resolve.
        timeout: HTTP request timeout in seconds.

    Returns:
        DIDDocument with parsed verification methods and services.

    Raises:
        DIDResolutionError: If resolution fails.
    """
    if not did_uri.startswith("did:web:"):
        raise DIDResolutionError(f"Not a did:web URI: {did_uri}")

    # Parse the domain and path
    parts = did_uri[8:].split(":")
    domain = parts[0].replace("%3A", ":")  # percent-decode port
    path_parts = parts[1:] if len(parts) > 1 else []

    if path_parts:
        url = f"https://{domain}/{'/'.join(path_parts)}/did.json"
    else:
        url = f"https://{domain}/.well-known/did.json"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/did+json, application/json")
        req.add_header("User-Agent", "qntm-did-resolver/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise DIDResolutionError(
            f"HTTP {e.code} resolving {did_uri} at {url}"
        ) from e
    except urllib.error.URLError as e:
        raise DIDResolutionError(
            f"Cannot reach {url}: {e.reason}"
        ) from e

    return _parse_did_document(data)


def resolve_did_key(did_uri: str) -> DIDDocument:
    """Resolve a did:key URI (Ed25519 only).

    did:key:z6Mk... → extracts Ed25519 public key from multibase-encoded key.

    Args:
        did_uri: The did:key URI to resolve.

    Returns:
        DIDDocument with a synthetic verification method.

    Raises:
        DIDResolutionError: If the key type is not Ed25519.
    """
    if not did_uri.startswith("did:key:z"):
        raise DIDResolutionError(
            f"Not a did:key URI or unsupported encoding: {did_uri}"
        )

    # Decode multibase (z = base58btc)
    multibase_value = did_uri[9:]  # after "did:key:z"
    raw = _base58_decode(multibase_value)

    # Ed25519 multicodec prefix: 0xed 0x01
    if len(raw) != 34 or raw[0] != 0xED or raw[1] != 0x01:
        raise DIDResolutionError(
            f"Unsupported key type in {did_uri} (only Ed25519 supported)"
        )

    pub_key = raw[2:]

    return DIDDocument(
        id=did_uri,
        verification_methods=[
            {
                "id": f"{did_uri}#{did_uri[8:]}",
                "type": "Ed25519VerificationKey2020",
                "controller": did_uri,
                "publicKeyMultibase": f"z{multibase_value}",
                "_raw_public_key": pub_key,
            }
        ],
        raw={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did_uri,
        },
    )


def resolve_did(did_uri: str, *, timeout: float = 10.0) -> DIDDocument:
    """Resolve any supported DID URI.

    Currently supports: did:web, did:key.
    Extensible — add new methods here.

    Returns:
        DIDDocument.

    Raises:
        DIDResolutionError: If the DID method is unsupported or resolution fails.
    """
    if did_uri.startswith("did:web:"):
        return resolve_did_web(did_uri, timeout=timeout)
    elif did_uri.startswith("did:key:"):
        return resolve_did_key(did_uri)
    else:
        method = did_uri.split(":")[1] if ":" in did_uri else "unknown"
        raise DIDResolutionError(f"Unsupported DID method: {method}")


def resolve_did_to_ed25519(did_uri: str, *, timeout: float = 10.0) -> bytes:
    """Convenience: resolve a DID URI to a 32-byte Ed25519 public key.

    This is the function signature expected by verify_sender_entity(resolve_did_fn=...).

    Returns:
        32-byte Ed25519 public key.

    Raises:
        DIDResolutionError: If resolution fails or no Ed25519 key is found.
    """
    doc = resolve_did(did_uri, timeout=timeout)

    # Check for raw key in did:key synthetic documents
    for vm in doc.verification_methods:
        if "_raw_public_key" in vm:
            return vm["_raw_public_key"]

    key = doc.ed25519_public_key()
    if key is None:
        raise DIDResolutionError(
            f"No Ed25519 public key found in DID Document for {did_uri}"
        )
    return key


def _parse_did_document(data: dict) -> DIDDocument:
    """Parse a raw DID Document JSON into a DIDDocument."""
    return DIDDocument(
        id=data.get("id", ""),
        verification_methods=data.get("verificationMethod", []),
        services=data.get("service", []),
        raw=data,
    )


# --- Base58 ---

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes:
    """Decode a base58btc string to bytes."""
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHABET.index(c.encode())

    # Convert to bytes
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    result.reverse()

    # Preserve leading zeros
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break

    return b"\x00" * pad + bytes(result)
