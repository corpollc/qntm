"""Identity management for QSP."""

import base64
import os

from .crypto import QSP1Suite

_suite = QSP1Suite()


def generate_identity() -> dict:
    """Generate a new identity. Returns dict with privateKey, publicKey, keyID."""
    private_key, public_key = _suite.generate_identity_key()
    key_id = _suite.compute_key_id(public_key)
    return {
        "privateKey": private_key,
        "publicKey": public_key,
        "keyID": key_id,
    }


def key_id_from_public_key(public_key: bytes) -> bytes:
    return _suite.compute_key_id(public_key)


def verify_key_id(public_key: bytes, key_id: bytes) -> bool:
    computed = _suite.compute_key_id(public_key)
    return computed == key_id


def validate_identity(identity: dict) -> None:
    if len(identity["privateKey"]) != 64:
        raise ValueError(
            f"invalid private key length: {len(identity['privateKey'])}"
        )
    if len(identity["publicKey"]) != 32:
        raise ValueError(
            f"invalid public key length: {len(identity['publicKey'])}"
        )
    if not verify_key_id(identity["publicKey"], identity["keyID"]):
        raise ValueError("key ID does not match public key")

    # Test that the key pair works
    test_msg = b"validation test"
    sig = _suite.sign(identity["privateKey"], test_msg)
    if not _suite.verify(identity["publicKey"], test_msg, sig):
        raise ValueError("public key cannot verify signature from private key")


def generate_conversation_id() -> bytes:
    return os.urandom(16)


def generate_message_id() -> bytes:
    return os.urandom(16)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def public_key_to_string(public_key: bytes) -> str:
    return base64url_encode(public_key)


def key_id_to_string(key_id: bytes) -> str:
    return base64url_encode(key_id)
