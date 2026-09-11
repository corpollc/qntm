"""Message creation, encryption, decryption, and verification."""

import time

from .cbor import marshal_canonical, unmarshal
from .constants import (
    DEFAULT_HANDSHAKE_TTL_SECONDS,
    DEFAULT_SUITE,
    DEFAULT_TTL_SECONDS,
    PROTO_PREFIX,
    PROTOCOL_VERSION,
)
from .crypto import QSP1Suite
from .identity import generate_message_id, key_id_from_public_key, validate_identity

_suite = QSP1Suite()


def create_message(
    sender_identity: dict,
    conversation: dict,
    body_type: str,
    body: bytes,
    refs: list | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    did: str | None = None,
) -> dict:
    """Create and encrypt a message, returning an outer envelope dict."""
    validate_identity(sender_identity)

    msg_id = generate_message_id()
    now = int(time.time())
    if not _safe_timestamp(ttl_seconds) or ttl_seconds <= 0 or not _safe_timestamp(now + ttl_seconds):
        raise ValueError("message TTL must be a positive safe integer within the timestamp range")
    expiry_ts = now + ttl_seconds

    # QSP v1.2 binds membership controls to their signed source epoch.
    if conversation.get('type') == 'group' and body_type in ('group_genesis','group_add','group_remove','group_rekey'):
        control = unmarshal(body)
        body = marshal_canonical({**control, 'group_epoch': conversation['currentEpoch']})

    # Build body structure for hashing
    body_struct = {"body": body, "body_type": body_type}
    if refs:
        body_struct["refs"] = refs

    body_struct_bytes = marshal_canonical(body_struct)
    body_hash = _suite.hash(body_struct_bytes)

    # Build signable
    signable = {
        "body_hash": body_hash,
        "conv_id": conversation["id"],
        "created_ts": now,
        "expiry_ts": expiry_ts,
        "msg_id": msg_id,
        "proto": PROTO_PREFIX,
        "sender_kid": sender_identity["keyID"],
        "suite": DEFAULT_SUITE,
    }

    signable_bytes = marshal_canonical(signable)
    signature = _suite.sign(sender_identity["privateKey"], signable_bytes)

    # Build inner payload
    inner_payload = {
        "body": body,
        "body_type": body_type,
        "sender_ik_pk": sender_identity["publicKey"],
        "sender_kid": sender_identity["keyID"],
        "sig_alg": "Ed25519",
        "signature": signature,
    }
    if refs:
        inner_payload["refs"] = refs

    inner_payload_bytes = marshal_canonical(inner_payload)

    # Build AAD
    aad_struct = {
        "conv_epoch": conversation["currentEpoch"],
        "conv_id": conversation["id"],
        "created_ts": now,
        "expiry_ts": expiry_ts,
        "msg_id": msg_id,
        "suite": DEFAULT_SUITE,
        "v": PROTOCOL_VERSION,
    }

    aad_bytes = marshal_canonical(aad_struct)

    # Encrypt
    nonce = _suite.derive_nonce(conversation["keys"]["nonceKey"], msg_id)
    ciphertext = _suite.encrypt(
        conversation["keys"]["aeadKey"], nonce, inner_payload_bytes, aad_bytes
    )
    aad_hash = _suite.hash(aad_bytes)

    envelope = {
        "aad_hash": aad_hash,
        "ciphertext": ciphertext,
        "conv_epoch": conversation["currentEpoch"],
        "conv_id": conversation["id"],
        "created_ts": now,
        "expiry_ts": expiry_ts,
        "msg_id": msg_id,
        "suite": DEFAULT_SUITE,
        "v": PROTOCOL_VERSION,
    }

    # Optional DID field — identity-layer metadata for DID resolution.
    # Backwards compatible: receivers that don't understand DIDs ignore it.
    if did is not None:
        envelope["did"] = did

    return envelope


def decrypt_message(envelope: dict, conversation: dict, *, allow_expired: bool = False) -> dict:
    """Decrypt and authenticate an envelope, rejecting expired messages by default.

    ``allow_expired=True`` is for verifying saved history only, never live receive
    or action authorization. Encryption, signature and timestamp validation remain
    mandatory in either mode.
    """
    validate_envelope(envelope)
    if allow_expired is not True and check_expiry(envelope):
        raise ValueError("message has expired")

    conv_id = bytes(envelope["conv_id"])
    expected_conv_id = bytes(conversation["id"])
    if conv_id != expected_conv_id:
        raise ValueError("conversation ID mismatch")

    # Reconstruct AAD
    aad_struct = {
        "conv_epoch": envelope.get("conv_epoch", 0),
        "conv_id": envelope["conv_id"],
        "created_ts": envelope["created_ts"],
        "expiry_ts": envelope["expiry_ts"],
        "msg_id": envelope["msg_id"],
        "suite": envelope["suite"],
        "v": envelope["v"],
    }

    aad_bytes = marshal_canonical(aad_struct)

    # Verify AAD hash if present
    if envelope.get("aad_hash") and len(bytes(envelope["aad_hash"])) > 0:
        computed_aad_hash = _suite.hash(aad_bytes)
        if bytes(envelope["aad_hash"]) != computed_aad_hash:
            raise ValueError("AAD hash mismatch")

    # Decrypt
    msg_id = bytes(envelope["msg_id"])
    nonce = _suite.derive_nonce(conversation["keys"]["nonceKey"], msg_id)
    inner_bytes = _suite.decrypt(
        conversation["keys"]["aeadKey"], nonce, bytes(envelope["ciphertext"]), aad_bytes
    )

    inner = unmarshal(inner_bytes)
    validate_inner_payload(inner)

    # Verify signature
    verified = verify_message_signature(envelope, inner)
    if not verified:
        raise ValueError("invalid message signature")

    # Verify sender key ID
    sender_pk = bytes(inner["sender_ik_pk"])
    sender_kid = bytes(inner["sender_kid"])
    computed_kid = key_id_from_public_key(sender_pk)
    if sender_kid != computed_kid:
        raise ValueError("sender key ID does not match public key")

    return {
        "envelope": envelope,
        "inner": inner,
        "verified": verified,
    }


def verify_message_signature(envelope: dict, inner_payload: dict) -> bool:
    """Verify the inner signature against the envelope."""
    body_struct = {
        "body": inner_payload["body"],
        "body_type": inner_payload["body_type"],
    }
    if inner_payload.get("refs") and len(inner_payload["refs"]) > 0:
        body_struct["refs"] = inner_payload["refs"]

    body_struct_bytes = marshal_canonical(body_struct)
    body_hash = _suite.hash(body_struct_bytes)

    signable = {
        "body_hash": body_hash,
        "conv_id": envelope["conv_id"],
        "created_ts": envelope["created_ts"],
        "expiry_ts": envelope["expiry_ts"],
        "msg_id": envelope["msg_id"],
        "proto": PROTO_PREFIX,
        "sender_kid": inner_payload["sender_kid"],
        "suite": envelope["suite"],
    }

    signable_bytes = marshal_canonical(signable)
    return _suite.verify(
        bytes(inner_payload["sender_ik_pk"]),
        signable_bytes,
        bytes(inner_payload["signature"]),
    )


def validate_envelope(envelope: dict) -> None:
    if envelope["v"] != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version: {envelope['v']}")
    if envelope["suite"] != DEFAULT_SUITE:
        raise ValueError(f"unsupported crypto suite: {envelope['suite']}")
    if not _safe_timestamp(envelope["created_ts"]) or envelope["created_ts"] <= 0:
        raise ValueError(f"invalid created timestamp: {envelope['created_ts']}")
    if not _safe_timestamp(envelope["expiry_ts"]) or envelope["expiry_ts"] <= envelope["created_ts"]:
        raise ValueError("expiry timestamp must be after created timestamp")
    ct = envelope["ciphertext"]
    if isinstance(ct, memoryview):
        ct = bytes(ct)
    if len(ct) == 0:
        raise ValueError("ciphertext is empty")
    if envelope["created_ts"] > int(time.time()) + 600:
        raise ValueError("message created timestamp is too far in the future")


def _safe_timestamp(value: object) -> bool:
    # Match JavaScript's exact integer domain; bool is not a wire timestamp.
    return type(value) is int and abs(value) <= 2**53 - 1


def check_expiry(envelope: dict) -> bool:
    """True once the current Unix second exceeds the signed expiry timestamp."""
    return int(time.time()) > envelope["expiry_ts"]


def validate_inner_payload(inner: dict) -> None:
    pk = inner["sender_ik_pk"]
    if isinstance(pk, memoryview):
        pk = bytes(pk)
    if len(pk) != 32:
        raise ValueError(f"invalid sender public key length: {len(pk)}")
    if inner["sig_alg"] != "Ed25519":
        raise ValueError(f"unsupported signature algorithm: {inner['sig_alg']}")
    sig = inner["signature"]
    if isinstance(sig, memoryview):
        sig = bytes(sig)
    if len(sig) != 64:
        raise ValueError(f"invalid signature length: {len(sig)}")
    if not inner.get("body_type"):
        raise ValueError("body type is empty")


def extract_did(envelope: dict) -> str | None:
    """Extract the optional DID URI from an envelope, if present."""
    return envelope.get("did")


def serialize_envelope(envelope: dict) -> bytes:
    return marshal_canonical(envelope)


def deserialize_envelope(data: bytes) -> dict:
    envelope = unmarshal(data)
    validate_envelope(envelope)
    return envelope


def default_ttl() -> int:
    return DEFAULT_TTL_SECONDS


def default_handshake_ttl() -> int:
    return DEFAULT_HANDSHAKE_TTL_SECONDS
