"""Tests for announce channel creation, posting, subscribing, and persistence."""

import json
import os
import tempfile

from qntm import (
    QSP1Suite,
    create_message,
    decrypt_message,
    default_ttl,
    generate_identity,
    serialize_envelope,
)
from qntm.announce import (
    create_channel,
    derive_announce_keys,
    generate_channel_keys,
    load_announce_store,
    resolve_channel,
    save_announce_store,
    sign_envelope,
    sign_register,
    verify_register_signature,
)


# --- Channel key generation ---


def test_generate_channel_keys():
    """Generate master + posting keypairs for an announce channel."""
    keys = generate_channel_keys()
    assert len(keys["master_private"]) == 64  # Ed25519 seed+pub
    assert len(keys["master_public"]) == 32
    assert len(keys["posting_private"]) == 64
    assert len(keys["posting_public"]) == 32
    # Master and posting are distinct keypairs
    assert keys["master_public"] != keys["posting_public"]


def test_channel_keys_can_sign():
    """Both master and posting keys produce valid signatures."""
    suite = QSP1Suite()
    keys = generate_channel_keys()
    msg = b"test message"

    sig_m = suite.sign(keys["master_private"], msg)
    assert suite.verify(keys["master_public"], msg, sig_m)

    sig_p = suite.sign(keys["posting_private"], msg)
    assert suite.verify(keys["posting_public"], msg, sig_p)


# --- Channel creation ---


def test_create_channel():
    """create_channel returns a channel dict with all required fields."""
    channel = create_channel("my-news")
    assert channel["name"] == "my-news"
    assert channel["is_owner"] is True
    assert len(channel["conv_id"]) == 32  # hex string, 16 bytes
    assert channel["master_private"]
    assert channel["master_public"]
    assert channel["posting_private"]
    assert channel["posting_public"]
    assert channel["invite_secret"]
    assert channel["conversation"]  # stored conversation dict


def test_create_channel_has_conversation_keys():
    """The embedded conversation has usable crypto keys."""
    channel = create_channel("test-chan")
    conv = channel["conversation"]
    assert "keys" in conv
    assert "root" in conv["keys"]
    assert "aeadKey" in conv["keys"]
    assert "nonceKey" in conv["keys"]


# --- Post message construction ---


def test_post_message_roundtrip():
    """Owner can create and decrypt a message through the announce channel."""
    channel = create_channel("roundtrip")
    conv = channel["conversation"]
    identity = generate_identity()

    envelope = create_message(identity, conv, "text", b"Hello subscribers!", None, default_ttl())
    msg = decrypt_message(envelope, conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Hello subscribers!"


def test_sign_envelope():
    """Posting key signs an envelope for announce delivery."""
    suite = QSP1Suite()
    keys = generate_channel_keys()
    envelope_b64 = "dGVzdCBlbnZlbG9wZQ"

    sig = sign_envelope(keys["posting_private"], envelope_b64)
    assert isinstance(sig, str)  # hex-encoded
    sig_bytes = bytes.fromhex(sig)
    assert len(sig_bytes) == 64

    # Verify the signature
    assert suite.verify(keys["posting_public"], envelope_b64.encode(), sig_bytes)


# --- Register signature ---


def test_sign_register():
    """Sign a channel registration request."""
    keys = generate_channel_keys()
    conv_id_hex = os.urandom(16).hex()
    posting_pk_b64 = "dGVzdHBvc3Rpbmc"

    sig = sign_register(keys["master_private"], "test-channel", conv_id_hex, posting_pk_b64)
    assert isinstance(sig, str)
    assert len(bytes.fromhex(sig)) == 64


def test_verify_register_signature():
    """Register signature can be verified with master public key."""
    keys = generate_channel_keys()
    conv_id_hex = os.urandom(16).hex()
    posting_pk_b64 = "dGVzdHBvc3Rpbmc"

    sig = sign_register(keys["master_private"], "test-channel", conv_id_hex, posting_pk_b64)
    assert verify_register_signature(
        keys["master_public"], "test-channel", conv_id_hex, posting_pk_b64, sig
    )


# --- Subscribe / key derivation ---


def test_derive_announce_keys():
    """Derive conversation keys from invite secret + conv_id."""
    invite_secret = os.urandom(32)
    conv_id = os.urandom(16)

    keys = derive_announce_keys(invite_secret, conv_id)
    assert "root" in keys
    assert "aeadKey" in keys
    assert "nonceKey" in keys
    assert len(keys["root"]) == 32
    assert len(keys["aeadKey"]) == 32
    assert len(keys["nonceKey"]) == 32


def test_derive_announce_keys_deterministic():
    """Same inputs produce same keys."""
    invite_secret = os.urandom(32)
    conv_id = os.urandom(16)

    keys1 = derive_announce_keys(invite_secret, conv_id)
    keys2 = derive_announce_keys(invite_secret, conv_id)

    assert keys1["root"] == keys2["root"]
    assert keys1["aeadKey"] == keys2["aeadKey"]
    assert keys1["nonceKey"] == keys2["nonceKey"]


def test_subscriber_can_decrypt():
    """A subscriber with the invite secret can decrypt messages."""
    channel = create_channel("pubsub")
    conv = channel["conversation"]
    identity = generate_identity()

    # Owner posts a message
    envelope = create_message(identity, conv, "text", b"Broadcast!", None, default_ttl())

    # Subscriber derives keys from invite secret + conv_id
    invite_secret = bytes.fromhex(channel["invite_secret"])
    conv_id = bytes.fromhex(channel["conv_id"])
    sub_keys = derive_announce_keys(invite_secret, conv_id)
    sub_conv = {
        "id": conv_id,
        "type": "announce",
        "keys": sub_keys,
        "participants": [],
        "currentEpoch": 0,
    }

    msg = decrypt_message(envelope, sub_conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Broadcast!"


# --- Channel persistence (store) ---


def test_store_roundtrip():
    """Save and load announce store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = {"channels": {}}
        entry = {
            "name": "test-channel",
            "conv_id": "abcd1234" * 4,
            "is_owner": True,
            "master_private": "aa" * 32,
            "master_public": "bb" * 32,
            "posting_private": "cc" * 32,
            "posting_public": "dd" * 32,
        }
        store["channels"][entry["conv_id"]] = entry
        save_announce_store(tmpdir, store)

        loaded = load_announce_store(tmpdir)
        assert len(loaded["channels"]) == 1
        ch = loaded["channels"][entry["conv_id"]]
        assert ch["name"] == "test-channel"
        assert ch["is_owner"] is True
        assert ch["master_private"] == "aa" * 32


def test_store_empty_on_missing_file():
    """Loading from nonexistent dir returns empty store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = load_announce_store(tmpdir)
        assert store["channels"] == {}


def test_store_subscriber_entry():
    """Subscriber entries don't have master/posting private keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = {"channels": {}}
        entry = {
            "name": "sub-channel",
            "conv_id": "1234abcd" * 4,
            "is_owner": False,
        }
        store["channels"][entry["conv_id"]] = entry
        save_announce_store(tmpdir, store)

        loaded = load_announce_store(tmpdir)
        ch = loaded["channels"][entry["conv_id"]]
        assert ch["is_owner"] is False
        assert ch.get("master_private") is None


# --- Channel resolution ---


def test_resolve_by_conv_id():
    """Resolve channel by conv_id hex."""
    store = {"channels": {}}
    cid = "abcdef0123456789" * 2
    store["channels"][cid] = {"name": "test", "conv_id": cid, "is_owner": True}

    entry = resolve_channel(store, cid)
    assert entry["name"] == "test"


def test_resolve_by_name():
    """Resolve channel by name."""
    store = {"channels": {}}
    cid = "abcdef0123456789" * 2
    store["channels"][cid] = {"name": "news", "conv_id": cid, "is_owner": True}

    entry = resolve_channel(store, "news")
    assert entry["conv_id"] == cid


def test_resolve_not_found():
    """Resolve raises for unknown channel."""
    store = {"channels": {}}
    try:
        resolve_channel(store, "nonexistent")
        assert False, "Should have raised"
    except ValueError:
        pass


# --- Channel listing ---


def test_list_channels():
    """List returns all channels with role info."""
    store = {"channels": {}}
    store["channels"]["aaa"] = {"name": "owned", "conv_id": "aaa", "is_owner": True}
    store["channels"]["bbb"] = {"name": "subbed", "conv_id": "bbb", "is_owner": False}

    channels = list(store["channels"].values())
    assert len(channels) == 2
    owners = [c for c in channels if c["is_owner"]]
    subs = [c for c in channels if not c["is_owner"]]
    assert len(owners) == 1
    assert len(subs) == 1


# --- Delete ---


def test_delete_channel_from_store():
    """Delete removes channel from store."""
    store = {"channels": {}}
    cid = "deadbeef01234567" * 2
    store["channels"][cid] = {"name": "doomed", "conv_id": cid, "is_owner": True}

    del store["channels"][cid]
    assert cid not in store["channels"]
