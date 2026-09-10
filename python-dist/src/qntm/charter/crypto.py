"""The charter's strict prime-order Ed25519 profile, shared with QSP."""

from ..ed25519 import is_valid_ed25519_public_key, verify_ed25519_signature
from .json import CharterError


def validate_charter_public_key(public_key: bytes) -> None:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise CharterError("Expected 32-byte Ed25519 charter key")
    if not is_valid_ed25519_public_key(public_key):
        raise CharterError("Invalid prime-order Ed25519 charter key")


def verify_charter_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    validate_charter_public_key(public_key)
    if type(signature) is not bytes:
        return False
    return verify_ed25519_signature(public_key, message, signature)
