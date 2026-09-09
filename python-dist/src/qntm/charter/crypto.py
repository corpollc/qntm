"""The charter's strict prime-order Ed25519 profile, using library operations."""

import nacl.bindings as sodium
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .json import CharterError

_IDENTITY = b"\x01" + bytes(31)
_ORDER = 2**252 + 27742317777372353535851937790883648493
_ORDER_MINUS_ONE = (_ORDER - 1).to_bytes(32, "little")


def validate_charter_public_key(public_key: bytes) -> None:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise CharterError("Expected 32-byte Ed25519 charter key")
    try:
        if not sodium.crypto_core_ed25519_is_valid_point(public_key):
            raise CharterError("Invalid prime-order Ed25519 charter key")
        # Libsodium <=1.0.20 can accept some mixed-order points. Its documented
        # workaround checks [L-1]P + P = identity using library group operations:
        # https://doc.libsodium.org/advanced/point-arithmetic#point-validation
        multiple = sodium.crypto_scalarmult_ed25519_noclamp(_ORDER_MINUS_ONE, public_key)
        if sodium.crypto_core_ed25519_add(multiple, public_key) != _IDENTITY:
            raise CharterError("Invalid prime-order Ed25519 charter key")
    except (ValueError, RuntimeError) as exc:
        raise CharterError("Invalid prime-order Ed25519 charter key") from exc


def verify_charter_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    validate_charter_public_key(public_key)
    if type(signature) is not bytes or len(signature) != 64:
        return False
    try:
        # R may be the canonical identity, unlike an authority public key.
        if signature[:32] != _IDENTITY:
            validate_charter_public_key(signature[:32])
        if int.from_bytes(signature[32:], "little") >= _ORDER:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (ValueError, InvalidSignature):
        return False
