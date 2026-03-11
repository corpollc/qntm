"""Announce channel management - broadcast/one-to-many channels.

An announce channel has:
- A master keypair (Ed25519) for channel ownership operations (register, delete)
- A posting keypair (Ed25519) for signing posted messages
- A conversation ID and derived conversation keys for encryption
- An invite secret that subscribers use to derive the same conversation keys
"""

import json
import os

from .crypto import QSP1Suite
from .identity import base64url_encode, generate_conversation_id

_suite = QSP1Suite()


def generate_channel_keys() -> dict:
    """Generate master + posting keypairs for an announce channel.

    Returns dict with master_private, master_public, posting_private, posting_public.
    """
    master_private, master_public = _suite.generate_identity_key()
    posting_private, posting_public = _suite.generate_identity_key()
    return {
        "master_private": master_private,
        "master_public": master_public,
        "posting_private": posting_private,
        "posting_public": posting_public,
    }


def derive_announce_keys(invite_secret: bytes, conv_id: bytes) -> dict:
    """Derive conversation keys from an invite secret and conv_id.

    Uses the same HKDF derivation as regular conversations but with
    conv_id as both the salt and part of the info.
    """
    root_key = _suite.derive_root_key(invite_secret, conv_id, conv_id)
    aead_key, nonce_key = _suite.derive_conversation_keys(root_key, conv_id)
    return {
        "root": root_key,
        "aeadKey": aead_key,
        "nonceKey": nonce_key,
    }


def create_channel(name: str) -> dict:
    """Create a new announce channel with all keys and conversation.

    Returns a dict with channel metadata, keys, invite secret, and conversation.
    """
    keys = generate_channel_keys()
    conv_id = generate_conversation_id()
    invite_secret = os.urandom(32)

    conv_keys = derive_announce_keys(invite_secret, conv_id)
    conversation = {
        "id": conv_id,
        "type": "announce",
        "keys": conv_keys,
        "participants": [],
        "currentEpoch": 0,
    }

    return {
        "name": name,
        "conv_id": conv_id.hex(),
        "master_private": keys["master_private"].hex(),
        "master_public": keys["master_public"].hex(),
        "posting_private": keys["posting_private"].hex(),
        "posting_public": keys["posting_public"].hex(),
        "invite_secret": invite_secret.hex(),
        "is_owner": True,
        "conversation": conversation,
    }


def sign_register(
    master_private: bytes, name: str, conv_id_hex: str, posting_pk_b64: str
) -> str:
    """Sign a channel registration payload with the master key.

    Returns hex-encoded Ed25519 signature.
    """
    message = f"register:{name}:{conv_id_hex}:{posting_pk_b64}".encode()
    sig = _suite.sign(master_private, message)
    return sig.hex()


def verify_register_signature(
    master_public: bytes, name: str, conv_id_hex: str, posting_pk_b64: str, sig_hex: str
) -> bool:
    """Verify a channel registration signature."""
    message = f"register:{name}:{conv_id_hex}:{posting_pk_b64}".encode()
    sig = bytes.fromhex(sig_hex)
    return _suite.verify(master_public, message, sig)


def sign_delete(master_private: bytes, conv_id_hex: str) -> str:
    """Sign a channel deletion request with the master key.

    Returns hex-encoded Ed25519 signature.
    """
    message = f"delete:{conv_id_hex}".encode()
    sig = _suite.sign(master_private, message)
    return sig.hex()


def sign_envelope(posting_private: bytes, envelope_b64: str) -> str:
    """Sign an envelope for announce delivery with the posting key.

    Returns hex-encoded Ed25519 signature.
    """
    sig = _suite.sign(posting_private, envelope_b64.encode())
    return sig.hex()


# --- Persistence ---


def _announce_store_path(config_dir: str) -> str:
    return os.path.join(config_dir, "announce_channels.json")


def load_announce_store(config_dir: str) -> dict:
    """Load the announce channel store from disk."""
    path = _announce_store_path(config_dir)
    if not os.path.isfile(path):
        return {"channels": {}}
    try:
        with open(path) as f:
            store = json.load(f)
        if not isinstance(store.get("channels"), dict):
            store["channels"] = {}
        return store
    except (json.JSONDecodeError, OSError):
        return {"channels": {}}


def save_announce_store(config_dir: str, store: dict) -> None:
    """Save the announce channel store to disk."""
    os.makedirs(config_dir, exist_ok=True)
    path = _announce_store_path(config_dir)
    with open(path, "w") as f:
        json.dump(store, f, indent=2)
        f.write("\n")


def resolve_channel(store: dict, name_or_id: str) -> dict:
    """Resolve a channel by conv_id or name.

    Raises ValueError if not found.
    """
    # Direct lookup by conv_id
    if name_or_id in store["channels"]:
        return store["channels"][name_or_id]
    # Search by name
    for entry in store["channels"].values():
        if entry.get("name") == name_or_id:
            return entry
    raise ValueError(f"announce channel {name_or_id!r} not found")
