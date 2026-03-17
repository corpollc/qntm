"""Canonical gateway wire encoding helpers.

Repo rule: all active gateway wire fields that represent raw bytes use
RFC 4648 base64url without padding. This module centralizes the
conversions so command paths cannot drift between hex and base64url.

These helpers are the ONLY allowed path for gateway wire serialization.
Active gateway command paths must not hand-write .hex() or bytes.fromhex()
for wire-bound KID, signature, public key, or ciphertext fields.
"""

from .identity import base64url_encode, base64url_decode, key_id_from_public_key


def kid_to_wire(kid_bytes: bytes) -> str:
    """Encode a KID (key ID) for the gateway wire format."""
    return base64url_encode(kid_bytes)


def kid_from_wire(kid_wire: str) -> bytes:
    """Decode a KID from the gateway wire format."""
    return base64url_decode(kid_wire)


def pubkey_to_wire(pk_bytes: bytes) -> str:
    """Encode a public key for the gateway wire format."""
    return base64url_encode(pk_bytes)


def pubkey_from_wire(pk_wire: str) -> bytes:
    """Decode a public key from the gateway wire format."""
    return base64url_decode(pk_wire)


def sig_to_wire(sig_bytes: bytes) -> str:
    """Encode a signature for the gateway wire format."""
    return base64url_encode(sig_bytes)


def sig_from_wire(sig_wire: str) -> bytes:
    """Decode a signature from the gateway wire format."""
    return base64url_decode(sig_wire)


def blob_to_wire(blob_bytes: bytes) -> str:
    """Encode a ciphertext blob for the gateway wire format."""
    return base64url_encode(blob_bytes)


def blob_from_wire(blob_wire: str) -> bytes:
    """Decode a ciphertext blob from the gateway wire format."""
    return base64url_decode(blob_wire)


def kid_from_pubkey(pk_bytes: bytes) -> str:
    """Derive a wire-format KID from a public key."""
    return base64url_encode(key_id_from_public_key(pk_bytes))
