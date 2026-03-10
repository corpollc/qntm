"""Invite creation, parsing, and conversation bootstrapping."""

import os

from .cbor import marshal_canonical, unmarshal
from .constants import DEFAULT_SUITE, PROTOCOL_VERSION
from .crypto import QSP1Suite
from .identity import (
    base64url_decode,
    base64url_encode,
    generate_conversation_id,
    key_id_from_public_key,
    validate_identity,
)

_suite = QSP1Suite()


def create_invite(inviter_identity: dict, conv_type: str = "direct") -> dict:
    """Create a new invite payload."""
    validate_identity(inviter_identity)

    conv_id = generate_conversation_id()
    invite_secret = os.urandom(32)
    invite_salt = os.urandom(32)

    return {
        "v": PROTOCOL_VERSION,
        "suite": DEFAULT_SUITE,
        "type": conv_type,
        "conv_id": conv_id,
        "inviter_ik_pk": inviter_identity["publicKey"],
        "invite_salt": invite_salt,
        "invite_secret": invite_secret,
    }


def serialize_invite(invite: dict) -> bytes:
    return marshal_canonical(invite)


def deserialize_invite(data: bytes) -> dict:
    invite = unmarshal(data)
    validate_invite(invite)
    return invite


def validate_invite(invite: dict) -> None:
    if invite["v"] != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version: {invite['v']}")
    if invite["suite"] != DEFAULT_SUITE:
        raise ValueError(f"unsupported crypto suite: {invite['suite']}")
    if invite["type"] not in ("direct", "group"):
        raise ValueError(f"invalid conversation type: {invite['type']}")
    inviter_pk = invite["inviter_ik_pk"]
    if isinstance(inviter_pk, memoryview):
        inviter_pk = bytes(inviter_pk)
    if len(inviter_pk) != 32:
        raise ValueError(f"invalid inviter public key length: {len(inviter_pk)}")
    invite_salt = invite["invite_salt"]
    if isinstance(invite_salt, memoryview):
        invite_salt = bytes(invite_salt)
    salt_len = len(invite_salt)
    if salt_len < 16 or salt_len > 32:
        raise ValueError(f"invalid invite salt length: {salt_len}")
    invite_secret = invite["invite_secret"]
    if isinstance(invite_secret, memoryview):
        invite_secret = bytes(invite_secret)
    if len(invite_secret) != 32:
        raise ValueError(f"invalid invite secret length: {len(invite_secret)}")


def invite_to_token(invite: dict) -> str:
    data = serialize_invite(invite)
    return base64url_encode(data)


def invite_from_url(invite_url: str) -> dict:
    """Parse an invite from a URL fragment or bare token."""
    fragment = invite_url
    if "://" in invite_url:
        # Extract fragment from URL
        parts = invite_url.split("#", 1)
        if len(parts) < 2 or not parts[1]:
            raise ValueError("no invite data in URL fragment")
        fragment = parts[1]

    data = base64url_decode(fragment)
    return deserialize_invite(data)


def derive_conversation_keys(invite: dict) -> dict:
    """Derive root, AEAD, and nonce keys from invite."""
    validate_invite(invite)

    invite_secret = bytes(invite["invite_secret"])
    invite_salt = bytes(invite["invite_salt"])
    conv_id = bytes(invite["conv_id"])

    root_key = _suite.derive_root_key(invite_secret, invite_salt, conv_id)
    aead_key, nonce_key = _suite.derive_conversation_keys(root_key, conv_id)

    return {
        "root": root_key,
        "aeadKey": aead_key,
        "nonceKey": nonce_key,
    }


def create_conversation(invite: dict, keys: dict) -> dict:
    """Create a conversation object from invite + derived keys."""
    validate_invite(invite)

    inviter_key_id = key_id_from_public_key(bytes(invite["inviter_ik_pk"]))

    return {
        "id": bytes(invite["conv_id"]),
        "type": invite["type"],
        "keys": keys,
        "participants": [inviter_key_id],
        "currentEpoch": 0,
    }


def add_participant(conv: dict, public_key: bytes) -> None:
    """Add a participant to a conversation."""
    key_id = key_id_from_public_key(public_key)
    for existing in conv["participants"]:
        if existing == key_id:
            return
    conv["participants"].append(key_id)
