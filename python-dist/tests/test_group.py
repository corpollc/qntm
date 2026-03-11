"""Tests for group conversation management."""

import time

import pytest

from qntm import (
    generate_identity,
    create_invite,
    invite_to_token,
    invite_from_url,
    derive_conversation_keys,
    create_conversation,
    add_participant,
    create_message,
    decrypt_message,
    serialize_envelope,
    deserialize_envelope,
    default_ttl,
)
from qntm.cbor import marshal_canonical, unmarshal
from qntm.crypto import QSP1Suite
from qntm.identity import base64url_encode, base64url_decode, key_id_from_public_key
from qntm.group import (
    create_group_genesis_body,
    create_group_add_body,
    create_group_remove_body,
    create_group_rekey_body,
    parse_group_genesis_body,
    parse_group_add_body,
    parse_group_remove_body,
    parse_group_rekey_body,
    GroupState,
    process_group_message,
    create_rekey,
    apply_rekey,
)


_suite = QSP1Suite()


def _make_group_conversation():
    """Helper: create identity, group invite, and group conversation."""
    identity = generate_identity()
    invite = create_invite(identity, "group")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, identity["publicKey"])
    return identity, conv, invite


# --- Group invite/conversation type tests ---


def test_group_invite_has_group_type():
    identity = generate_identity()
    invite = create_invite(identity, "group")
    assert invite["type"] == "group"

    token = invite_to_token(invite)
    restored = invite_from_url(token)
    assert restored["type"] == "group"


def test_group_conversation_has_group_type():
    identity, conv, _ = _make_group_conversation()
    assert conv["type"] == "group"


# --- Genesis body construction ---


def test_create_genesis_body():
    creator = generate_identity()
    body_bytes = create_group_genesis_body(
        group_name="Test Group",
        description="A test group",
        creator_identity=creator,
        founding_member_keys=[],
    )
    assert isinstance(body_bytes, bytes)
    assert len(body_bytes) > 0

    parsed = parse_group_genesis_body(body_bytes)
    assert parsed["group_name"] == "Test Group"
    assert parsed["description"] == "A test group"
    assert len(parsed["founding_members"]) == 1  # creator
    assert parsed["founding_members"][0]["role"] == "admin"


def test_genesis_body_with_founding_members():
    creator = generate_identity()
    member1 = generate_identity()
    member2 = generate_identity()

    body_bytes = create_group_genesis_body(
        group_name="Team",
        description="",
        creator_identity=creator,
        founding_member_keys=[member1["publicKey"], member2["publicKey"]],
    )
    parsed = parse_group_genesis_body(body_bytes)
    assert len(parsed["founding_members"]) == 3  # creator + 2 members
    roles = [m["role"] for m in parsed["founding_members"]]
    assert roles.count("admin") == 1
    assert roles.count("member") == 2


def test_genesis_body_deduplicates_creator():
    creator = generate_identity()
    body_bytes = create_group_genesis_body(
        group_name="Solo",
        description="",
        creator_identity=creator,
        founding_member_keys=[creator["publicKey"]],  # creator passed again
    )
    parsed = parse_group_genesis_body(body_bytes)
    assert len(parsed["founding_members"]) == 1  # no duplicate


# --- Add body construction ---


def test_create_add_body():
    adder = generate_identity()
    new_member = generate_identity()

    body_bytes = create_group_add_body(
        adder_identity=adder,
        new_member_keys=[new_member["publicKey"]],
    )
    assert isinstance(body_bytes, bytes)

    parsed = parse_group_add_body(body_bytes)
    assert len(parsed["new_members"]) == 1
    assert parsed["new_members"][0]["role"] == "member"
    assert parsed["added_at"] > 0


# --- Remove body construction ---


def test_create_remove_body():
    member_kid = key_id_from_public_key(generate_identity()["publicKey"])

    body_bytes = create_group_remove_body(
        removed_member_kids=[member_kid],
        reason="left the project",
    )
    assert isinstance(body_bytes, bytes)

    parsed = parse_group_remove_body(body_bytes)
    assert len(parsed["removed_members"]) == 1
    assert bytes(parsed["removed_members"][0]) == member_kid
    assert parsed["reason"] == "left the project"


# --- Rekey body construction ---


def test_create_rekey_body():
    alice = generate_identity()
    bob = generate_identity()

    new_group_key = _suite.generate_group_key()
    alice_kid = key_id_from_public_key(alice["publicKey"])
    bob_kid = key_id_from_public_key(bob["publicKey"])
    conv_id = b"\x00" * 16

    members = [
        {"kid": alice_kid, "public_key": alice["publicKey"]},
        {"kid": bob_kid, "public_key": bob["publicKey"]},
    ]

    body_bytes = create_group_rekey_body(
        new_group_key=new_group_key,
        new_epoch=1,
        members=members,
        conv_id=conv_id,
    )
    assert isinstance(body_bytes, bytes)

    parsed = parse_group_rekey_body(body_bytes)
    assert parsed["new_conv_epoch"] == 1
    assert len(parsed["wrapped_keys"]) == 2

    # Verify Alice can unwrap
    alice_kid_str = base64url_encode(alice_kid)
    wrapped_blob = bytes(parsed["wrapped_keys"][alice_kid_str])
    unwrapped = _suite.unwrap_key_for_recipient(
        wrapped_blob, alice["privateKey"], alice_kid, conv_id
    )
    assert unwrapped == new_group_key


# --- GroupState tests ---


def test_group_state_from_genesis():
    creator = generate_identity()
    member = generate_identity()

    body_bytes = create_group_genesis_body(
        group_name="State Test",
        description="testing state",
        creator_identity=creator,
        founding_member_keys=[member["publicKey"]],
    )

    state = GroupState()
    state.apply_genesis(parse_group_genesis_body(body_bytes))

    assert state.group_name == "State Test"
    assert state.description == "testing state"
    assert state.member_count() == 2
    assert state.is_member(key_id_from_public_key(creator["publicKey"]))
    assert state.is_member(key_id_from_public_key(member["publicKey"]))
    assert state.is_admin(key_id_from_public_key(creator["publicKey"]))
    assert not state.is_admin(key_id_from_public_key(member["publicKey"]))


def test_group_state_add_member():
    creator = generate_identity()
    state = GroupState()

    genesis_bytes = create_group_genesis_body(
        group_name="Add Test",
        description="",
        creator_identity=creator,
        founding_member_keys=[],
    )
    state.apply_genesis(parse_group_genesis_body(genesis_bytes))
    assert state.member_count() == 1

    new_member = generate_identity()
    add_bytes = create_group_add_body(
        adder_identity=creator,
        new_member_keys=[new_member["publicKey"]],
    )
    state.apply_add(parse_group_add_body(add_bytes))
    assert state.member_count() == 2
    assert state.is_member(key_id_from_public_key(new_member["publicKey"]))


def test_group_state_remove_member():
    creator = generate_identity()
    member = generate_identity()
    member_kid = key_id_from_public_key(member["publicKey"])

    state = GroupState()
    genesis_bytes = create_group_genesis_body(
        group_name="Remove Test",
        description="",
        creator_identity=creator,
        founding_member_keys=[member["publicKey"]],
    )
    state.apply_genesis(parse_group_genesis_body(genesis_bytes))
    assert state.member_count() == 2

    remove_bytes = create_group_remove_body(
        removed_member_kids=[member_kid],
        reason="bye",
    )
    state.apply_remove(parse_group_remove_body(remove_bytes))
    assert state.member_count() == 1
    assert not state.is_member(member_kid)


def test_group_state_cannot_remove_creator():
    creator = generate_identity()
    member = generate_identity()
    creator_kid = key_id_from_public_key(creator["publicKey"])

    state = GroupState()
    genesis_bytes = create_group_genesis_body(
        group_name="Creator Test",
        description="",
        creator_identity=creator,
        founding_member_keys=[member["publicKey"]],
    )
    state.apply_genesis(parse_group_genesis_body(genesis_bytes))

    remove_bytes = create_group_remove_body(
        removed_member_kids=[creator_kid],
        reason="nope",
    )
    state.apply_remove(parse_group_remove_body(remove_bytes))
    # Creator should still be there
    assert state.is_member(creator_kid)


# --- Encrypted group message roundtrip ---


def test_group_genesis_message_roundtrip():
    """Create a genesis message, encrypt, serialize, deserialize, decrypt."""
    creator, conv, _ = _make_group_conversation()

    body_bytes = create_group_genesis_body(
        group_name="Roundtrip",
        description="test",
        creator_identity=creator,
        founding_member_keys=[],
    )

    envelope = create_message(
        creator, conv, "group_genesis", body_bytes, None, default_ttl()
    )
    data = serialize_envelope(envelope)
    restored = deserialize_envelope(data)
    msg = decrypt_message(restored, conv)

    assert msg["verified"]
    assert msg["inner"]["body_type"] == "group_genesis"

    parsed = parse_group_genesis_body(bytes(msg["inner"]["body"]))
    assert parsed["group_name"] == "Roundtrip"


def test_group_add_message_roundtrip():
    creator, conv, _ = _make_group_conversation()
    new_member = generate_identity()

    body_bytes = create_group_add_body(
        adder_identity=creator,
        new_member_keys=[new_member["publicKey"]],
    )
    envelope = create_message(
        creator, conv, "group_add", body_bytes, None, default_ttl()
    )
    data = serialize_envelope(envelope)
    restored = deserialize_envelope(data)
    msg = decrypt_message(restored, conv)

    assert msg["verified"]
    assert msg["inner"]["body_type"] == "group_add"
    parsed = parse_group_add_body(bytes(msg["inner"]["body"]))
    assert len(parsed["new_members"]) == 1


def test_group_remove_message_roundtrip():
    creator, conv, _ = _make_group_conversation()
    member = generate_identity()
    member_kid = key_id_from_public_key(member["publicKey"])

    body_bytes = create_group_remove_body(
        removed_member_kids=[member_kid],
        reason="test removal",
    )
    envelope = create_message(
        creator, conv, "group_remove", body_bytes, None, default_ttl()
    )
    data = serialize_envelope(envelope)
    restored = deserialize_envelope(data)
    msg = decrypt_message(restored, conv)

    assert msg["verified"]
    assert msg["inner"]["body_type"] == "group_remove"


# --- Rekey full flow ---


def test_rekey_wrap_unwrap():
    """Create rekey, verify each member can unwrap."""
    alice = generate_identity()
    bob = generate_identity()
    alice_kid = key_id_from_public_key(alice["publicKey"])
    bob_kid = key_id_from_public_key(bob["publicKey"])

    _, conv, _ = _make_group_conversation()
    conv_id = conv["id"]

    new_group_key = _suite.generate_group_key()
    members = [
        {"kid": alice_kid, "public_key": alice["publicKey"]},
        {"kid": bob_kid, "public_key": bob["publicKey"]},
    ]
    body_bytes = create_group_rekey_body(
        new_group_key=new_group_key,
        new_epoch=1,
        members=members,
        conv_id=conv_id,
    )
    parsed = parse_group_rekey_body(body_bytes)

    # Alice unwraps
    alice_wrapped = bytes(parsed["wrapped_keys"][base64url_encode(alice_kid)])
    alice_unwrapped = _suite.unwrap_key_for_recipient(
        alice_wrapped, alice["privateKey"], alice_kid, conv_id
    )
    assert alice_unwrapped == new_group_key

    # Bob unwraps
    bob_wrapped = bytes(parsed["wrapped_keys"][base64url_encode(bob_kid)])
    bob_unwrapped = _suite.unwrap_key_for_recipient(
        bob_wrapped, bob["privateKey"], bob_kid, conv_id
    )
    assert bob_unwrapped == new_group_key


def test_apply_rekey_updates_conversation():
    """apply_rekey should update conversation keys and epoch."""
    _, conv, _ = _make_group_conversation()
    old_aead = conv["keys"]["aeadKey"]
    old_nonce = conv["keys"]["nonceKey"]
    old_epoch = conv["currentEpoch"]

    new_group_key = _suite.generate_group_key()
    apply_rekey(conv, new_group_key, old_epoch + 1)

    assert conv["currentEpoch"] == old_epoch + 1
    assert conv["keys"]["aeadKey"] != old_aead
    assert conv["keys"]["nonceKey"] != old_nonce
    assert conv["keys"]["root"] == new_group_key


def test_messaging_after_rekey():
    """After rekey, messages should encrypt/decrypt with new keys."""
    creator, conv, _ = _make_group_conversation()

    # Rekey
    new_group_key = _suite.generate_group_key()
    apply_rekey(conv, new_group_key, 1)

    # Send message on new epoch
    envelope = create_message(
        creator, conv, "text", b"Post-rekey message", None, default_ttl()
    )
    msg = decrypt_message(envelope, conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Post-rekey message"


# --- process_group_message integration ---


def test_process_group_message_genesis():
    creator = generate_identity()
    body_bytes = create_group_genesis_body(
        group_name="Process Test",
        description="",
        creator_identity=creator,
        founding_member_keys=[],
    )
    state = GroupState()
    process_group_message("group_genesis", body_bytes, state)
    assert state.group_name == "Process Test"
    assert state.member_count() == 1


def test_process_group_message_add():
    creator = generate_identity()
    state = GroupState()

    genesis_bytes = create_group_genesis_body(
        group_name="Add Process",
        description="",
        creator_identity=creator,
        founding_member_keys=[],
    )
    process_group_message("group_genesis", genesis_bytes, state)

    new_member = generate_identity()
    add_bytes = create_group_add_body(
        adder_identity=creator,
        new_member_keys=[new_member["publicKey"]],
    )
    process_group_message("group_add", add_bytes, state)
    assert state.member_count() == 2


def test_process_group_message_remove():
    creator = generate_identity()
    member = generate_identity()
    member_kid = key_id_from_public_key(member["publicKey"])

    state = GroupState()
    genesis_bytes = create_group_genesis_body(
        group_name="Remove Process",
        description="",
        creator_identity=creator,
        founding_member_keys=[member["publicKey"]],
    )
    process_group_message("group_genesis", genesis_bytes, state)
    assert state.member_count() == 2

    remove_bytes = create_group_remove_body(
        removed_member_kids=[member_kid],
        reason="bye",
    )
    process_group_message("group_remove", remove_bytes, state)
    assert state.member_count() == 1


def test_process_ignores_non_group_messages():
    state = GroupState()
    # Should not raise
    process_group_message("text", b"hello", state)
    assert state.member_count() == 0
