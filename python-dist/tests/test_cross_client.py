"""Cross-client compatibility tests using shared spec vectors."""

import json
import os

import pytest

# Load vectors from the shared file. Regenerate after spec-affecting changes:
#   go run ./crosstest/generate_vectors.go > client/tests/vectors.json
VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "client", "tests", "vectors.json"
)

with open(VECTORS_PATH) as f:
    VECTORS = json.load(f)


def test_identity_vectors():
    """Key ID derivation from a fixed seed must match Go/TS."""
    from qntm.crypto import QSP1Suite
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    suite = QSP1Suite()
    seed = bytes.fromhex(VECTORS["seed"])

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw()

    assert pub.hex() == VECTORS["identity_vectors"]["public_key"]

    key_id = suite.compute_key_id(pub)
    assert key_id.hex() == VECTORS["identity_vectors"]["key_id"]


def test_cbor_vectors():
    """Canonical CBOR encoding must match Go/TS output."""
    from qntm.cbor import marshal_canonical

    for vec in VECTORS["cbor_vectors"]:
        obj = vec["input"]
        # The "with_bytes" vector has base64-encoded bytes in JSON
        if vec["name"] == "with_bytes":
            import base64
            obj = {"data": base64.b64decode(obj["data"])}

        encoded = marshal_canonical(obj)
        assert encoded.hex() == vec["encoded"], f"CBOR mismatch for {vec['name']}"


def test_key_derivation():
    """Key derivation must match Go/TS vectors."""
    from qntm.crypto import QSP1Suite

    suite = QSP1Suite()
    kd = VECTORS["key_derivation"]

    invite_secret = bytes.fromhex(kd["invite_secret"])
    invite_salt = bytes.fromhex(kd["invite_salt"])
    conv_id = bytes.fromhex(kd["conv_id"])

    root_key = suite.derive_root_key(invite_secret, invite_salt, conv_id)
    assert root_key.hex() == kd["root_key"]

    aead_key, nonce_key = suite.derive_conversation_keys(root_key, conv_id)
    assert aead_key.hex() == kd["aead_key"]
    assert nonce_key.hex() == kd["nonce_key"]


def test_signing_vector():
    """Ed25519 signatures must match Go/TS."""
    from qntm.crypto import QSP1Suite
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    suite = QSP1Suite()
    sv = VECTORS["signing_vector"]

    seed = bytes.fromhex(sv["seed"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw()
    private_key = seed + pub  # 64-byte Go-compatible format

    message = bytes.fromhex(sv["message"])
    signature = suite.sign(private_key, message)
    assert signature.hex() == sv["signature"]

    assert suite.verify(pub, message, signature)


def test_hash_vector():
    """SHA-256 must match."""
    from qntm.crypto import QSP1Suite

    suite = QSP1Suite()
    hv = VECTORS["hash_vector"]

    result = suite.hash(bytes.fromhex(hv["input"]))
    assert result.hex() == hv["output"]


def test_nonce_vector():
    """Nonce derivation must match Go/TS."""
    from qntm.crypto import QSP1Suite

    suite = QSP1Suite()
    nv = VECTORS["nonce_vector"]

    nonce_key = bytes.fromhex(nv["nonce_key"])
    msg_id = bytes.fromhex(nv["msg_id"])
    nonce = suite.derive_nonce(nonce_key, msg_id)
    assert nonce.hex() == nv["nonce"]


def test_aead_vector():
    """XChaCha20-Poly1305 encrypt/decrypt must match Go/TS."""
    from qntm.crypto import QSP1Suite

    suite = QSP1Suite()
    av = VECTORS["aead_vector"]

    key = bytes.fromhex(av["key"])
    nonce = bytes.fromhex(av["nonce"])
    plaintext = bytes.fromhex(av["plaintext"])
    aad = bytes.fromhex(av["aad"])

    ct = suite.encrypt(key, nonce, plaintext, aad)
    assert ct.hex() == av["ciphertext"]

    pt = suite.decrypt(key, nonce, ct, aad)
    assert pt == plaintext


def test_x25519_vector():
    """Ed25519 -> X25519 conversion must match Go/TS."""
    from qntm.crypto import ed25519_public_key_to_x25519, ed25519_private_key_to_x25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    xv = VECTORS["x25519_vector"]
    seed = bytes.fromhex(xv["ed25519_seed"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw()
    private_key_64 = seed + pub

    x25519_pk = ed25519_public_key_to_x25519(pub)
    assert x25519_pk.hex() == xv["x25519_public_key"]

    x25519_sk = ed25519_private_key_to_x25519(private_key_64)
    assert x25519_sk.hex() == xv["x25519_private_key"]


def test_epoch_vectors():
    """Epoch key derivation must match Go/TS."""
    from qntm.crypto import QSP1Suite

    suite = QSP1Suite()
    ev = VECTORS["epoch_vectors"]

    group_key = bytes.fromhex(ev["group_key"])
    conv_id = bytes.fromhex(ev["conv_id"])

    for epoch_vec in ev["epochs"]:
        epoch = epoch_vec["epoch"]
        aead_key, nonce_key = suite.derive_epoch_keys(group_key, conv_id, epoch)
        assert aead_key.hex() == epoch_vec["aead_key"], f"AEAD key mismatch at epoch {epoch}"
        assert nonce_key.hex() == epoch_vec["nonce_key"], f"Nonce key mismatch at epoch {epoch}"


def test_e2e_decrypt():
    """Decrypt the E2E vector envelope produced by Go."""
    from qntm.message import decrypt_message
    from qntm.cbor import unmarshal

    e2e = VECTORS["e2e_vector"]

    # Reconstruct conversation keys
    keys = {
        "root": bytes.fromhex(e2e["root_key"]),
        "aeadKey": bytes.fromhex(e2e["aead_key"]),
        "nonceKey": bytes.fromhex(e2e["nonce_key"]),
    }
    conversation = {
        "id": bytes.fromhex(e2e["conv_id"]),
        "type": "direct",
        "keys": keys,
        "participants": [],
        "currentEpoch": 0,
    }

    # Deserialize envelope
    envelope_bytes = bytes.fromhex(e2e["envelope_cbor"])
    envelope = unmarshal(envelope_bytes)

    # Decrypt - need to skip expiry check for test vectors
    msg = decrypt_message(envelope, conversation)

    assert msg["verified"]
    inner = msg["inner"]
    assert bytes(inner["body"]) == bytes.fromhex(e2e["body"])
    assert inner["body_type"] == e2e["body_type"]
    assert bytes(inner["sender_ik_pk"]).hex() == e2e["sender_pub_key"]
    assert bytes(inner["sender_kid"]).hex() == e2e["sender_key_id"]


def test_roundtrip():
    """Create a message, serialize, deserialize, and decrypt."""
    from qntm import (
        create_invite,
        create_message,
        decrypt_message,
        derive_conversation_keys,
        create_conversation,
        add_participant,
        generate_identity,
        serialize_envelope,
        deserialize_envelope,
        default_ttl,
    )

    identity = generate_identity()
    invite = create_invite(identity, "direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, identity["publicKey"])

    envelope = create_message(identity, conv, "text", b"Hello from Python!", None, default_ttl())

    # Serialize and deserialize
    data = serialize_envelope(envelope)
    restored = deserialize_envelope(data)

    # Decrypt
    msg = decrypt_message(restored, conv)
    assert msg["verified"]
    assert bytes(msg["inner"]["body"]) == b"Hello from Python!"
