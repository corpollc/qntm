"""DID resolution for the Agent Identity Working Group.

Supports did:web (W3C standard) and did:key (Ed25519 only).
Used by verify_sender_entity() to resolve DID URIs to Ed25519 public keys.

References:
- did:web spec: https://w3c-ccg.github.io/did-method-web/
- did:key spec: https://w3c-ccg.github.io/did-method-key/
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import re
import urllib.request
import urllib.error
from urllib.parse import unquote, urlsplit
from ._identity_http import read_identity_json
from .ed25519 import is_valid_ed25519_public_key
from dataclasses import dataclass, field
from typing import Optional


def _valid_ed25519_key(raw: object) -> Optional[bytes]:
    if isinstance(raw, bytes) and len(raw) == 32 and is_valid_ed25519_public_key(raw):
        return raw
    return None


def _is_disallowed_did_web_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_disallowed_did_web_ip(ip.ipv4_mapped)
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or not ip.is_global
    )


@dataclass
class DIDDocument:
    """Parsed DID Document."""

    id: str
    verification_methods: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def ed25519_public_key(self) -> Optional[bytes]:
        """Extract the first valid prime-order Ed25519 public key from verificationMethod.

        Looks for Ed25519VerificationKey2020 or Ed25519VerificationKey2018
        with publicKeyMultibase, publicKeyBase58, or publicKeyJwk.
        """
        if not isinstance(self.verification_methods, list):
            return None

        for vm in self.verification_methods:
            if not isinstance(vm, dict):
                continue
            vm_type = vm.get("type", "")
            if not isinstance(vm_type, str) or "Ed25519" not in vm_type:
                continue

            # publicKeyMultibase (preferred, multicodec-prefixed)
            mb = vm.get("publicKeyMultibase")
            if isinstance(mb, str) and mb.startswith("z"):
                try:
                    raw = _base58_decode(mb[1:])
                    if len(raw) == 34 and raw[0] == 0xED and raw[1] == 0x01:
                        valid = _valid_ed25519_key(raw[2:])
                        if valid is not None:
                            return valid
                    elif len(raw) == 32:
                        valid = _valid_ed25519_key(raw)
                        if valid is not None:
                            return valid
                except ValueError:
                    pass

            # publicKeyBase58 (legacy)
            b58 = vm.get("publicKeyBase58")
            if isinstance(b58, str):
                try:
                    valid = _valid_ed25519_key(_base58_decode(b58))
                    if valid is not None:
                        return valid
                except ValueError:
                    pass

            # publicKeyJwk
            jwk = vm.get("publicKeyJwk")
            if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                x = jwk.get("x")
                if isinstance(x, str) and 1 <= len(x) <= 64 and re.fullmatch(r"[A-Za-z0-9_-]+=*", x):
                    try:
                        padded = x + "=" * ((4 - len(x) % 4) % 4)
                        valid = _valid_ed25519_key(base64.urlsafe_b64decode(padded))
                        if valid is not None:
                            return valid
                    except Exception:
                        pass

        return None

    def service_endpoint(self, service_type: str) -> Optional[str]:
        """Find a service endpoint by type."""
        if not isinstance(self.services, list):
            return None
        for svc in self.services:
            if isinstance(svc, dict) and svc.get("type") == service_type:
                ep = svc.get("serviceEndpoint")
                if isinstance(ep, str):
                    return ep
        return None


class DIDResolutionError(Exception):
    """Raised when DID resolution fails."""
    pass


def _validate_did_web_authority(raw_authority: str) -> str:
    domain = unquote(raw_authority)
    if (
        not domain
        or "%" in domain
        or any(c in domain for c in "/\\@?#")
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F for c in domain)
    ):
        raise DIDResolutionError("Invalid did:web authority")
    try:
        parsed = urlsplit(f"https://{domain}")
        port = parsed.port
    except ValueError as exc:
        raise DIDResolutionError("Invalid did:web authority") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc != domain
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or domain.endswith(":")
        or (port is not None and not (1 <= port <= 65535))
    ):
        raise DIDResolutionError("Invalid did:web authority")

    hostname = unquote(parsed.hostname or "").lower()
    if (
        not hostname
        or "%" in hostname
        or hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or ".." in hostname
        or hostname.startswith(".")
        or hostname.endswith(".")
    ):
        raise DIDResolutionError("Disallowed or invalid did:web host")

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        if all(lbl.isdigit() or lbl.lower().startswith("0x") for lbl in labels if lbl):
            raise DIDResolutionError("Invalid numeric IP authority in did:web")
        if ":" in hostname:
            raise DIDResolutionError("Invalid did:web authority")
    else:
        if _is_disallowed_did_web_ip(ip_obj):
            raise DIDResolutionError(f"Disallowed non-public host in did:web: {hostname}")

    return domain


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
    if not isinstance(did_uri, str) or not did_uri.startswith("did:web:"):
        raise DIDResolutionError(f"Not a did:web URI: {did_uri}")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F for c in did_uri):
        raise DIDResolutionError("Invalid control or whitespace characters in did:web URI")

    parts = did_uri[8:].split(":")
    domain = _validate_did_web_authority(parts[0])
    path_parts = parts[1:] if len(parts) > 1 else []
    for p in path_parts:
        decoded_p = unquote(p)
        if (
            not p
            or not decoded_p
            or "%" in decoded_p
            or decoded_p in (".", "..")
            or any(c in decoded_p for c in "/\\?#")
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F for c in decoded_p)
        ):
            raise DIDResolutionError("Invalid did:web path")

    if path_parts:
        url = f"https://{domain}/{'/'.join(path_parts)}/did.json"
    else:
        url = f"https://{domain}/.well-known/did.json"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/did+json, application/json")
        req.add_header("User-Agent", "qntm-did-resolver/1.0")
        data = read_identity_json(req, timeout=timeout)
        if not isinstance(data, dict) or data.get("id") != did_uri:
            raise ValueError("DID document identifier mismatch")
        return _parse_did_document(data)
    except DIDResolutionError:
        raise
    except urllib.error.HTTPError as e:
        raise DIDResolutionError(
            f"HTTP {e.code} resolving {did_uri} at {url}"
        ) from e
    except urllib.error.URLError as e:
        raise DIDResolutionError(
            f"Cannot reach {url}: {e.reason}"
        ) from e
    except (http.client.InvalidURL, ValueError, TypeError, KeyError, AttributeError, OSError) as e:
        raise DIDResolutionError(f"Invalid DID document: {e}") from e


def resolve_did_key(did_uri: str) -> DIDDocument:
    """Resolve a did:key URI (Ed25519 only).

    did:key:z6Mk... → extracts Ed25519 public key from multibase-encoded key.

    Args:
        did_uri: The did:key URI to resolve.

    Returns:
        DIDDocument with a synthetic verification method.

    Raises:
        DIDResolutionError: If the key type is not a valid 32-byte Ed25519 public key.
    """
    if not isinstance(did_uri, str) or not did_uri.startswith("did:key:z"):
        raise DIDResolutionError(
            f"Not a did:key URI or unsupported encoding: {did_uri}"
        )

    # Decode multibase (z = base58btc)
    multibase_value = did_uri[9:]  # after "did:key:z"
    try:
        raw = _base58_decode(multibase_value)
    except ValueError as e:
        raise DIDResolutionError(f"Invalid base58 encoding in {did_uri}: {e}") from e

    # Ed25519 multicodec prefix: 0xed 0x01
    if len(raw) != 34 or raw[0] != 0xED or raw[1] != 0x01:
        raise DIDResolutionError(
            f"Unsupported key type in {did_uri} (only Ed25519 supported)"
        )

    pub_key = _valid_ed25519_key(raw[2:])
    if pub_key is None:
        raise DIDResolutionError(f"Invalid Ed25519 public key in {did_uri}")

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
    if not isinstance(did_uri, str):
        raise DIDResolutionError("DID URI must be a string")
    if did_uri.startswith("did:web:"):
        return resolve_did_web(did_uri, timeout=timeout)
    elif did_uri.startswith("did:key:"):
        return resolve_did_key(did_uri)
    else:
        method = did_uri.split(":")[1] if ":" in did_uri else "unknown"
        raise DIDResolutionError(f"Unsupported DID method: {method}")


def resolve_did_to_ed25519(did_uri: str, *, timeout: float = 10.0) -> bytes:
    """Convenience: resolve a DID URI to a validated 32-byte Ed25519 public key.

    This is the function signature expected by verify_sender_entity(resolve_did_fn=...).

    Returns:
        32-byte Ed25519 public key.

    Raises:
        DIDResolutionError: If resolution fails or no valid Ed25519 key is found.
    """
    doc = resolve_did(did_uri, timeout=timeout)

    if isinstance(doc.verification_methods, list):
        for vm in doc.verification_methods:
            if isinstance(vm, dict) and "_raw_public_key" in vm:
                valid = _valid_ed25519_key(vm["_raw_public_key"])
                if valid is not None:
                    return valid

    key = doc.ed25519_public_key()
    if key is None:
        raise DIDResolutionError(
            f"No Ed25519 public key found in DID Document for {did_uri}"
        )
    return key


def _parse_did_document(data: dict) -> DIDDocument:
    """Parse a raw DID Document JSON into a DIDDocument."""
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        raise DIDResolutionError("Invalid DID Document object")
    vms = data.get("verificationMethod", [])
    svcs = data.get("service", [])
    if not isinstance(vms, list):
        raise DIDResolutionError("Invalid verificationMethod in DID Document")
    if not isinstance(svcs, list):
        raise DIDResolutionError("Invalid service in DID Document")
    return DIDDocument(
        id=data["id"],
        verification_methods=vms,
        services=svcs,
        raw=data,
    )


# --- Base58 ---

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MAX_BASE58_KEY_LEN = 64


def _base58_decode(s: str) -> bytes:
    """Decode a bounded base58btc string (1..64 chars) to bytes."""
    if not isinstance(s, str) or not (1 <= len(s) <= _MAX_BASE58_KEY_LEN):
        raise ValueError("Invalid base58 length")
    try:
        encoded = s.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Invalid non-ASCII base58 character") from exc

    n = 0
    for b in encoded:
        idx = _B58_ALPHABET.find(b)
        if idx < 0:
            raise ValueError("Invalid base58 character")
        n = n * 58 + idx

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
