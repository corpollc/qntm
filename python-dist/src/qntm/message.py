"""Message creation, encryption, decryption, and verification."""

import time

import cbor2

from .cbor import marshal_canonical, unmarshal
from .charter_info import with_local_charter_info
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
    if conversation.get("controlsBlocked") or (conversation.get("sendBlocked") and body_type not in ("group_genesis", "group_add", "group_remove", "group_rekey")):
        raise ValueError("Complete the pending group update or restore authorized access before sending")

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

    conv_id = _require_bytes(envelope["conv_id"], "conv_id", exact_len=16)
    expected_conv_id = _require_bytes(conversation["id"], "conversation id", exact_len=16)
    if conv_id != expected_conv_id:
        raise ValueError("conversation ID mismatch")

    # Reconstruct AAD
    aad_struct = {
        "conv_epoch": envelope.get("conv_epoch", 0),
        "conv_id": conv_id,
        "created_ts": envelope["created_ts"],
        "expiry_ts": envelope["expiry_ts"],
        "msg_id": _require_bytes(envelope["msg_id"], "msg_id", exact_len=16),
        "suite": envelope["suite"],
        "v": envelope["v"],
    }

    aad_bytes = marshal_canonical(aad_struct)

    # Verify AAD hash if present (validate_envelope already enforced 32-byte bytes)
    aad_hash = envelope.get("aad_hash")
    if aad_hash is not None:
        computed_aad_hash = _suite.hash(aad_bytes)
        if _require_bytes(aad_hash, "aad_hash", exact_len=32) != computed_aad_hash:
            raise ValueError("AAD hash mismatch")

    # Decrypt
    msg_id = _require_bytes(envelope["msg_id"], "msg_id", exact_len=16)
    ciphertext = _require_bytes(envelope["ciphertext"], "ciphertext", min_len=1, max_len=65536)
    nonce = _suite.derive_nonce(conversation["keys"]["nonceKey"], msg_id)
    inner_bytes = _suite.decrypt(
        conversation["keys"]["aeadKey"], nonce, ciphertext, aad_bytes
    )

    try:
        inner = unmarshal(inner_bytes)
    except cbor2.CBORDecodeError as exc:
        raise ValueError("invalid inner CBOR payload") from exc
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

    return with_local_charter_info({
        "envelope": envelope,
        "inner": inner,
        "verified": verified,
    })


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


def _require_bytes(
    value: object,
    field_name: str,
    *,
    exact_len: int | None = None,
    min_len: int | None = None,
    max_len: int | None = None,
) -> bytes:
    if isinstance(value, memoryview):
        raw = bytes(value)
    elif isinstance(value, bytes):
        raw = value
    else:
        raise ValueError(f"{field_name} must be bytes")
    if exact_len is not None and len(raw) != exact_len:
        raise ValueError(f"invalid {field_name} length: {len(raw)}")
    if min_len is not None and len(raw) < min_len:
        if min_len == 1 and len(raw) == 0:
            raise ValueError(f"{field_name} is empty")
        raise ValueError(f"invalid {field_name} length: {len(raw)}")
    if max_len is not None and len(raw) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length ({max_len}): {len(raw)}")
    return raw


def validate_envelope(envelope: dict) -> None:
    if not isinstance(envelope, dict) or not all(isinstance(k, str) for k in envelope.keys()):
        raise ValueError("envelope must be a string-keyed map")
    v = envelope.get("v")
    if type(v) is not int or v != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version: {v}")
    suite = envelope.get("suite")
    if not isinstance(suite, str) or suite != DEFAULT_SUITE:
        raise ValueError(f"unsupported crypto suite: {suite}")
    created_ts = envelope.get("created_ts")
    if not _safe_timestamp(created_ts) or created_ts <= 0:
        raise ValueError(f"invalid created timestamp: {created_ts}")
    expiry_ts = envelope.get("expiry_ts")
    if not _safe_timestamp(expiry_ts) or expiry_ts <= created_ts:
        raise ValueError("expiry timestamp must be after created timestamp")
    conv_epoch = envelope.get("conv_epoch", 0)
    if type(conv_epoch) is not int or conv_epoch < 0 or conv_epoch > 2**53 - 1:
        raise ValueError(f"invalid conversation epoch: {conv_epoch}")
    _require_bytes(envelope.get("conv_id"), "conv_id", exact_len=16)
    _require_bytes(envelope.get("msg_id"), "msg_id", exact_len=16)
    _require_bytes(envelope.get("ciphertext"), "ciphertext", min_len=1, max_len=65536)
    if "aad_hash" in envelope and envelope["aad_hash"] is not None:
        _require_bytes(envelope["aad_hash"], "aad_hash", exact_len=32)
    if "did" in envelope and envelope["did"] is not None and not isinstance(envelope["did"], str):
        raise ValueError("did must be a string")
    if created_ts > int(time.time()) + 600:
        raise ValueError("message created timestamp is too far in the future")


def _safe_timestamp(value: object) -> bool:
    # Match JavaScript's exact integer domain; bool is not a wire timestamp.
    return type(value) is int and abs(value) <= 2**53 - 1


def check_expiry(envelope: dict) -> bool:
    """True once the current Unix second exceeds the signed expiry timestamp."""
    if not isinstance(envelope, dict) or not _safe_timestamp(envelope.get("expiry_ts")):
        raise ValueError("invalid expiry timestamp")
    return int(time.time()) > envelope["expiry_ts"]


def validate_inner_payload(inner: dict) -> None:
    if not isinstance(inner, dict) or not all(isinstance(k, str) for k in inner.keys()):
        raise ValueError("inner payload must be a string-keyed map")
    if "msg_id" in inner and inner["msg_id"] is not None:
        _require_bytes(inner["msg_id"], "msg_id", exact_len=16)
    _require_bytes(inner.get("sender_ik_pk"), "sender public key", exact_len=32)
    _require_bytes(inner.get("sender_kid"), "sender key ID", exact_len=16)
    sig_alg = inner.get("sig_alg")
    if not isinstance(sig_alg, str) or sig_alg != "Ed25519":
        raise ValueError(f"unsupported signature algorithm: {sig_alg}")
    _require_bytes(inner.get("signature"), "signature", exact_len=64)
    _require_bytes(inner.get("body"), "body")
    body_type = inner.get("body_type")
    if not isinstance(body_type, str) or not body_type:
        raise ValueError("body type is empty")
    if "refs" in inner and inner["refs"] is not None:
        if not isinstance(inner["refs"], list):
            raise ValueError("refs must be a list")
        for ref in inner["refs"]:
            _require_bytes(ref, "ref", exact_len=16)


def extract_did(envelope: dict) -> str | None:
    """Extract the optional DID URI from an envelope, if present."""
    if not isinstance(envelope, dict):
        return None
    did = envelope.get("did")
    return did if isinstance(did, str) else None


def serialize_envelope(envelope: dict) -> bytes:
    return marshal_canonical(envelope)


def deserialize_envelope(data: bytes) -> dict:
    raw = _require_bytes(data, "envelope", min_len=1)
    try:
        envelope = unmarshal(raw)
    except cbor2.CBORDecodeError as exc:
        raise ValueError("invalid CBOR envelope") from exc
    validate_envelope(envelope)
    return envelope


def default_ttl() -> int:
    return DEFAULT_TTL_SECONDS


def default_handshake_ttl() -> int:
    return DEFAULT_HANDSHAKE_TTL_SECONDS
