"""Tests for message creation, encryption, decryption."""

from qntm import (
    generate_identity,
    create_invite,
    derive_conversation_keys,
    create_conversation,
    add_participant,
    create_message,
    decrypt_message,
    serialize_envelope,
    deserialize_envelope,
    default_ttl,
)


def _make_conversation():
    """Helper: create identity, invite, and conversation."""
    identity = generate_identity()
    invite = create_invite(identity, "direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, identity["publicKey"])
    return identity, conv


def test_create_and_decrypt():
    identity, conv = _make_conversation()

    envelope = create_message(identity, conv, "text", b"Hello!", None, default_ttl())
    msg = decrypt_message(envelope, conv)

    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Hello!"
    assert msg["inner"]["body_type"] == "text"


def test_serialize_deserialize():
    identity, conv = _make_conversation()
    envelope = create_message(identity, conv, "text", b"Test", None, default_ttl())

    data = serialize_envelope(envelope)
    assert isinstance(data, bytes)
    assert len(data) > 0

    restored = deserialize_envelope(data)
    msg = decrypt_message(restored, conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Test"


def test_different_body_types():
    identity, conv = _make_conversation()

    for body_type in ["text", "text/plain", "json", "event"]:
        envelope = create_message(
            identity, conv, body_type, b"content", None, default_ttl()
        )
        msg = decrypt_message(envelope, conv)
        assert msg["inner"]["body_type"] == body_type


def test_tampered_ciphertext_fails():
    identity, conv = _make_conversation()
    envelope = create_message(identity, conv, "text", b"Secret", None, default_ttl())

    # Tamper with ciphertext
    ct = bytearray(envelope["ciphertext"])
    ct[0] ^= 0xFF
    envelope["ciphertext"] = bytes(ct)

    try:
        decrypt_message(envelope, conv)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_keys_fail():
    identity, conv1 = _make_conversation()
    _, conv2 = _make_conversation()

    envelope = create_message(identity, conv1, "text", b"Wrong keys", None, default_ttl())

    try:
        decrypt_message(envelope, conv2)
        assert False, "Should have raised"
    except Exception:
        pass


def test_two_party_messaging():
    """Alice and Bob exchange messages."""
    alice = generate_identity()
    bob = generate_identity()

    invite = create_invite(alice, "direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, alice["publicKey"])
    add_participant(conv, bob["publicKey"])

    # Alice sends
    env1 = create_message(alice, conv, "text", b"Hi Bob!", None, default_ttl())
    msg1 = decrypt_message(env1, conv)
    assert bytes(msg1["inner"]["body"]) == b"Hi Bob!"

    # Bob sends
    env2 = create_message(bob, conv, "text", b"Hi Alice!", None, default_ttl())
    msg2 = decrypt_message(env2, conv)
    assert bytes(msg2["inner"]["body"]) == b"Hi Alice!"
