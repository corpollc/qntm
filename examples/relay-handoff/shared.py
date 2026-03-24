"""Shared utilities for relay-handoff example.

Key derivation, CBOR encoding, envelope construction, and crypto helpers
used by both sender and receiver agents.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import time
from typing import Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from nacl.signing import SigningKey, VerifyKey

# ── Configuration ─────────────────────────────────────────────────────────────

RELAY_URL = os.environ.get("QNTM_RELAY_URL", "https://inbox.qntm.corpo.llc")
SEND_ENDPOINT = f"{RELAY_URL}/v1/send"
SUBSCRIBE_ENDPOINT = f"{RELAY_URL}/v1/subscribe"


# ── CBOR Encoder/Decoder (minimal) ───────────────────────────────────────────

def _cbor_uint(major: int, value: int) -> bytes:
    mt = major << 5
    if value < 24:
        return struct.pack("B", mt | value)
    elif value < 0x100:
        return struct.pack("BB", mt | 24, value)
    elif value < 0x10000:
        return struct.pack("!BH", mt | 25, value)
    elif value < 0x100000000:
        return struct.pack("!BI", mt | 26, value)
    else:
        return struct.pack("!BQ", mt | 27, value)


def cbor_encode(obj: Any) -> bytes:
    """Encode a Python object to CBOR (supports int, bytes, str, dict, list)."""
    if isinstance(obj, int) and obj >= 0:
        return _cbor_uint(0, obj)
    elif isinstance(obj, bytes):
        return _cbor_uint(2, len(obj)) + obj
    elif isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_uint(3, len(encoded)) + encoded
    elif isinstance(obj, list):
        result = _cbor_uint(4, len(obj))
        for item in obj:
            result += cbor_encode(item)
        return result
    elif isinstance(obj, dict):
        items = list(obj.items())
        result = _cbor_uint(5, len(items))
        for k, v in items:
            result += cbor_encode(k)
            result += cbor_encode(v)
        return result
    else:
        raise TypeError(f"cbor_encode: unsupported type {type(obj)}")


# ── Key Derivation (QSP-1 v1.0) ─────────────────────────────────────────────

def derive_conversation_keys(
    invite_secret: bytes, invite_salt: bytes, conv_id: bytes
) -> tuple[bytes, bytes, bytes]:
    """Derive (root_key, aead_key, nonce_key) from invite material per QSP-1 v1.0.

    Args:
        invite_secret: 32-byte shared secret from conversation invite
        invite_salt: 32-byte salt from conversation invite
        conv_id: 16-byte conversation identifier

    Returns:
        Tuple of (root_key, aead_key, nonce_key), each 32 bytes.
    """
    root_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=invite_salt,
        info=b"qntm/qsp/v1/root" + conv_id,
    ).derive(invite_secret)

    aead_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"qntm/qsp/v1/aead" + conv_id,
    ).derive(root_key)

    nonce_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"qntm/qsp/v1/nonce" + conv_id,
    ).derive(root_key)

    return root_key, aead_key, nonce_key


# ── Crypto Helpers ───────────────────────────────────────────────────────────

def compute_sender_id(ed25519_public_key: bytes) -> bytes:
    """Compute sender_id = Trunc16(SHA-256(ed25519_public_key))."""
    return hashlib.sha256(ed25519_public_key).digest()[:16]


def encrypt_message(
    plaintext: bytes,
    aead_key: bytes,
    nonce_key: bytes,
    conv_id: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with XChaCha20-Poly1305 per QSP-1 v1.0.

    Returns:
        Tuple of (msg_id, nonce, ciphertext).
    """
    msg_id = os.urandom(16)
    nonce = hmac.new(nonce_key, msg_id, hashlib.sha256).digest()[:24]
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad=conv_id, nonce=nonce, key=aead_key
    )
    return msg_id, nonce, ciphertext


def decrypt_message(
    ciphertext: bytes,
    nonce: bytes,
    aead_key: bytes,
    conv_id: bytes,
) -> bytes:
    """Decrypt ciphertext with XChaCha20-Poly1305 per QSP-1 v1.0."""
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, aad=conv_id, nonce=nonce, key=aead_key
    )


# ── Envelope Construction ────────────────────────────────────────────────────

def build_envelope(
    signing_key: SigningKey,
    conv_id: bytes,
    msg_id: bytes,
    nonce: bytes,
    ciphertext: bytes,
    seq: int = 1,
    expiry_ts: int | None = None,
) -> bytes:
    """Build a signed QSP-1 v1.0 CBOR envelope.

    Args:
        signing_key: Ed25519 signing key
        conv_id: 16-byte conversation ID
        msg_id: 16-byte message ID
        nonce: 24-byte nonce
        ciphertext: encrypted payload
        seq: sequence number (monotonically increasing per sender)
        expiry_ts: optional expiry timestamp (unix ms)

    Returns:
        CBOR-encoded envelope bytes.
    """
    sender_id = compute_sender_id(bytes(signing_key.verify_key))
    signature = signing_key.sign(ciphertext).signature

    envelope = {
        "v": 1,
        "conv": conv_id,
        "sender": sender_id,
        "seq": seq,
        "ts": int(time.time() * 1000),
        "msg_id": msg_id,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "sig": signature,
        "aad_hash": hashlib.sha256(conv_id).digest(),
    }
    if expiry_ts is not None:
        envelope["expiry_ts"] = expiry_ts

    return cbor_encode(envelope)


def verify_sender(
    ciphertext: bytes,
    signature: bytes,
    sender_public_key: bytes,
) -> bool:
    """Verify an Ed25519 signature on ciphertext.

    Args:
        ciphertext: the signed payload
        signature: 64-byte Ed25519 signature
        sender_public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        vk = VerifyKey(sender_public_key)
        vk.verify(ciphertext, signature)
        return True
    except Exception:
        return False


# ── Work Artifact ────────────────────────────────────────────────────────────

def create_work_artifact(
    artifact_type: str,
    source_agent: str,
    target_agent: str,
    payload: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Create a JSON work artifact for pipeline handoff.

    This is the structure that flows between pipeline stages. Customize
    the payload for your use case.

    Args:
        artifact_type: e.g. "copywriter_output", "analyst_report"
        source_agent: name/ID of the sending agent
        target_agent: name/ID of the intended recipient
        payload: the actual work product
        metadata: optional metadata (timestamps, versions, etc.)

    Returns:
        UTF-8 encoded JSON bytes.
    """
    artifact = {
        "artifact_type": artifact_type,
        "source_agent": source_agent,
        "target_agent": target_agent,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload": payload,
    }
    if metadata:
        artifact["metadata"] = metadata

    return json.dumps(artifact, separators=(",", ":")).encode("utf-8")
