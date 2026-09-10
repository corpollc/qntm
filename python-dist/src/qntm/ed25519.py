"""Strict Ed25519 profile shared by QSP messaging and charter verification."""

import nacl.bindings as sodium
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_IDENTITY = b"\x01" + bytes(31)
_ORDER = 2**252 + 27742317777372353535851937790883648493
_ORDER_MINUS_ONE = (_ORDER - 1).to_bytes(32, "little")
_BYTES = (bytes, bytearray, memoryview)


def is_valid_ed25519_public_key(public_key: bytes) -> bool:
    """Require canonical nonidentity public keys in the prime-order subgroup."""
    if not isinstance(public_key, _BYTES) or len(public_key) != 32:
        return False
    public_key = bytes(public_key)
    try:
        if not sodium.crypto_core_ed25519_is_valid_point(public_key):
            return False
        # Documented workaround for permissive subgroup checks in libsodium
        # <=1.0.20: https://doc.libsodium.org/advanced/point-arithmetic
        multiple = sodium.crypto_scalarmult_ed25519_noclamp(_ORDER_MINUS_ONE, public_key)
        return sodium.crypto_core_ed25519_add(multiple, public_key) == _IDENTITY
    except (ValueError, RuntimeError):
        return False


def verify_ed25519_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Use canonical R/S and the uncofactored equation; identity R is allowed."""
    if not is_valid_ed25519_public_key(public_key) or not isinstance(signature, _BYTES) or len(signature) != 64:
        return False
    signature = bytes(signature)
    try:
        if signature[:32] != _IDENTITY and not is_valid_ed25519_public_key(signature[:32]):
            return False
        if int.from_bytes(signature[32:], "little") >= _ORDER:
            return False
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(signature, message)
        return True
    except (TypeError, ValueError, InvalidSignature):
        return False
