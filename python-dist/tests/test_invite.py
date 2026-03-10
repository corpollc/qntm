"""Tests for invite creation, serialization, and token roundtrip."""

from qntm import (
    generate_identity,
    create_invite,
    invite_to_token,
    invite_from_url,
    derive_conversation_keys,
    create_conversation,
    add_participant,
)


def test_invite_roundtrip():
    """Create invite, convert to token, parse back."""
    identity = generate_identity()
    invite = create_invite(identity, "direct")

    token = invite_to_token(invite)
    assert isinstance(token, str)
    assert len(token) > 0

    restored = invite_from_url(token)
    assert bytes(restored["conv_id"]) == invite["conv_id"]
    assert bytes(restored["invite_secret"]) == invite["invite_secret"]
    assert bytes(restored["invite_salt"]) == invite["invite_salt"]
    assert bytes(restored["inviter_ik_pk"]) == invite["inviter_ik_pk"]
    assert restored["type"] == "direct"
    assert restored["v"] == 1
    assert restored["suite"] == "QSP-1"


def test_invite_url_fragment():
    """Parse invite from a URL with fragment."""
    identity = generate_identity()
    invite = create_invite(identity, "direct")
    token = invite_to_token(invite)

    url = f"https://qntm.corpo.llc/invite#{token}"
    restored = invite_from_url(url)
    assert bytes(restored["conv_id"]) == invite["conv_id"]


def test_group_invite():
    """Create and parse a group invite."""
    identity = generate_identity()
    invite = create_invite(identity, "group")
    assert invite["type"] == "group"

    token = invite_to_token(invite)
    restored = invite_from_url(token)
    assert restored["type"] == "group"


def test_conversation_creation():
    """Create conversation from invite and add participants."""
    alice = generate_identity()
    bob = generate_identity()

    invite = create_invite(alice, "direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)

    assert len(conv["participants"]) == 1
    add_participant(conv, bob["publicKey"])
    assert len(conv["participants"]) == 2

    # Adding same participant again is a no-op
    add_participant(conv, bob["publicKey"])
    assert len(conv["participants"]) == 2


def test_key_derivation_deterministic():
    """Same invite produces same keys."""
    identity = generate_identity()
    invite = create_invite(identity, "direct")

    keys1 = derive_conversation_keys(invite)
    keys2 = derive_conversation_keys(invite)

    assert keys1["root"] == keys2["root"]
    assert keys1["aeadKey"] == keys2["aeadKey"]
    assert keys1["nonceKey"] == keys2["nonceKey"]
