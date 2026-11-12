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
from qntm.message import extract_did


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


def test_did_field_optional():
    """DID field is optional — absent by default, present when provided."""
    identity, conv = _make_conversation()

    # Without DID
    env_no_did = create_message(identity, conv, "text", b"No DID", None, default_ttl())
    assert "did" not in env_no_did
    assert extract_did(env_no_did) is None

    # With DID
    test_did = "did:aps:z3Bmy2y8WtbRXNBYayR64kYqXN1XRi6Hqch6FwKFxmSWH"
    env_with_did = create_message(
        identity, conv, "text", b"With DID", None, default_ttl(), did=test_did
    )
    assert env_with_did["did"] == test_did
    assert extract_did(env_with_did) == test_did

    # DID field survives serialize/deserialize round-trip
    data = serialize_envelope(env_with_did)
    restored = deserialize_envelope(data)
    assert extract_did(restored) == test_did

    # Message still decrypts correctly with DID field present
    msg = decrypt_message(env_with_did, conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"With DID"


def test_did_field_multiple_methods():
    """Different DID methods all work as optional metadata."""
    identity, conv = _make_conversation()

    dids = [
        "did:aps:z3Bmy2y8WtbRXNBYayR64kYqXN1XRi6Hqch6FwKFxmSWH",
        "did:agentid:agent_tv-agent-001",
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ]

    for did_uri in dids:
        env = create_message(
            identity, conv, "text", b"DID test", None, default_ttl(), did=did_uri
        )
        assert extract_did(env) == did_uri
        msg = decrypt_message(env, conv)
        assert msg["verified"]


def test_p0_1_wire_envelope_type_and_byte_length_validation():
    import cbor2
    import pytest
    from qntm.message import validate_envelope

    identity, conv = _make_conversation()
    valid = create_message(identity, conv, "text", b"ok", None, default_ttl())

    for non_dict in ([1, 2, 3], 42, "str", {1: b"bad"}):
        with pytest.raises(ValueError):
            validate_envelope(non_dict)
        with pytest.raises(ValueError):
            deserialize_envelope(cbor2.dumps(non_dict))

    poison_envelopes = [
        {**valid, "msg_id": 10_000_000_000},
        {**valid, "msg_id": "x"},
        {**valid, "msg_id": b"short"},
        {**valid, "conv_id": 10_000_000_000},
        {**valid, "conv_id": b"short"},
        {**valid, "aad_hash": 10_000_000_000},
        {**valid, "aad_hash": "x"},
        {**valid, "aad_hash": b"short"},
        {**valid, "ciphertext": b""},
        {**valid, "ciphertext": b"x" * 65537},
        {**valid, "ciphertext": 10_000_000_000},
        {**valid, "v": True},
        {**valid, "conv_epoch": True},
        {**valid, "conv_epoch": -1},
        {**valid, "created_ts": True},
        {**valid, "expiry_ts": False},
        {**valid, "suite": 123},
        {**valid, "did": 123},
    ]
    for bad in poison_envelopes:
        with pytest.raises(ValueError):
            validate_envelope(bad)
        with pytest.raises(ValueError):
            decrypt_message(bad, conv)
        with pytest.raises(ValueError):
            deserialize_envelope(cbor2.dumps(bad))


def test_p0_1_inner_payload_type_and_byte_length_validation():
    import pytest
    from qntm.cbor import marshal_canonical
    from qntm.crypto import QSP1Suite
    from qntm.message import validate_inner_payload

    identity, conv = _make_conversation()
    valid = create_message(identity, conv, "text", b"ok", None, default_ttl())
    suite = QSP1Suite()

    base_inner = {
        "body": b"ok",
        "body_type": "text",
        "sender_ik_pk": identity["publicKey"],
        "sender_kid": identity["keyID"],
        "sig_alg": "Ed25519",
        "signature": b"\x00" * 64,
    }
    validate_inner_payload(base_inner)

    for bad_inner in (
        [1, 2],
        {1: b"bad"},
        {**base_inner, "body": 1_000_000_000},
        {**base_inner, "body": "not-bytes"},
        {**base_inner, "body_type": b"bytes"},
        {**base_inner, "body_type": ""},
        {**base_inner, "msg_id": 10_000_000_000},
        {**base_inner, "msg_id": b"short"},
        {**base_inner, "sender_ik_pk": 10_000_000_000},
        {**base_inner, "sender_ik_pk": b"short"},
        {**base_inner, "sender_kid": "not-bytes"},
        {**base_inner, "sender_kid": b"short"},
        {**base_inner, "signature": 10_000_000_000},
        {**base_inner, "signature": b"short"},
        {**base_inner, "refs": [123]},
        {**base_inner, "refs": [b"short"]},
    ):
        with pytest.raises(ValueError):
            validate_inner_payload(bad_inner)

    # Encrypt inner.body = 1_000_000_000 under real AEAD keys and verify decrypt_message
    # rejects cleanly with ValueError instead of allocating 1 GB in bytes(inner["body"]).
    aad_struct = {
        k: valid[k]
        for k in ("conv_epoch", "conv_id", "created_ts", "expiry_ts", "msg_id", "suite", "v")
    }
    aad_bytes = marshal_canonical(aad_struct)
    nonce = suite.derive_nonce(conv["keys"]["nonceKey"], valid["msg_id"])
    poison_ct = suite.encrypt(
        conv["keys"]["aeadKey"],
        nonce,
        marshal_canonical({**base_inner, "body": 1_000_000_000}),
        aad_bytes,
    )
    poison_env = {**valid, "ciphertext": poison_ct, "aad_hash": suite.hash(aad_bytes)}
    with pytest.raises(ValueError, match="body"):
        decrypt_message(poison_env, conv)


def test_p0_1_recv_advances_cursor_past_poison_wire_frames(tmp_path):
    import base64
    import cbor2
    from qntm import cli
    from qntm.cbor import marshal_canonical
    from qntm.crypto import QSP1Suite

    sender, conv = _make_conversation()
    receiver = generate_identity()
    add_participant(conv, receiver["publicKey"])
    conv_id_hex = conv["id"].hex()
    record = {
        "id": conv_id_hex,
        "name": "Poison test",
        "type": "direct",
        "keys": {
            "root": conv["keys"]["root"].hex(),
            "aead_key": conv["keys"]["aeadKey"].hex(),
            "nonce_key": conv["keys"]["nonceKey"].hex(),
        },
        "participants": [sender["keyID"].hex(), receiver["keyID"].hex()],
        "current_epoch": 0,
    }
    cli._save_identity(str(tmp_path), receiver)
    cli._save_conversations(str(tmp_path), [record])

    good_env = create_message(sender, conv, "text", b"clean delivery", None, default_ttl())
    poison_msg_id = bytes([b ^ 0xFF for b in good_env["msg_id"]])
    suite = QSP1Suite()
    poison_env_base = {**good_env, "msg_id": poison_msg_id}
    aad_bytes = marshal_canonical(
        {k: poison_env_base[k] for k in ("conv_epoch", "conv_id", "created_ts", "expiry_ts", "msg_id", "suite", "v")}
    )
    poison_inner_ct = suite.encrypt(
        conv["keys"]["aeadKey"],
        suite.derive_nonce(conv["keys"]["nonceKey"], poison_msg_id),
        marshal_canonical({
            "body": 1_000_000_000,
            "body_type": "text",
            "sender_ik_pk": sender["publicKey"],
            "sender_kid": sender["keyID"],
            "sig_alg": "Ed25519",
            "signature": b"\x00" * 64,
        }),
        aad_bytes,
    )

    frames = [
        {"seq": 1, "envelope_b64": base64.b64encode(cbor2.dumps({**good_env, "msg_id": 10_000_000_000})).decode()},
        {"seq": 2, "envelope_b64": base64.b64encode(cbor2.dumps({**good_env, "msg_id": "x"})).decode()},
        {"seq": 3, "envelope_b64": base64.b64encode(cbor2.dumps({**poison_env_base, "aad_hash": 10_000_000_000})).decode()},
        {"seq": 4, "envelope_b64": base64.b64encode(cbor2.dumps({**poison_env_base, "aad_hash": suite.hash(aad_bytes), "ciphertext": poison_inner_ct})).decode()},
        {"seq": 5, "envelope_b64": base64.b64encode(serialize_envelope(good_env)).decode()},
    ]
    out = cli._process_received_messages(str(tmp_path), receiver, [record], record, frames, 5)
    assert len(out) == 1
    assert out[0]["unsafe_body"] == "clean delivery"
    assert cli._load_cursors(str(tmp_path))[conv_id_hex] == 5
