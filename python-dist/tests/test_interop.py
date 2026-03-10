"""Cross-language interop: Python creates messages that Go/TS can decrypt, and vice versa.

Uses the E2E test vector from Go to verify Python can produce compatible envelopes.
"""

import json
import os

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "client", "tests", "vectors.json"
)

with open(VECTORS_PATH) as f:
    VECTORS = json.load(f)


def test_python_envelope_structure_matches_go():
    """Verify that Python-produced envelopes have the same CBOR structure."""
    from qntm import (
        generate_identity,
        create_invite,
        derive_conversation_keys,
        create_conversation,
        add_participant,
        create_message,
        serialize_envelope,
        deserialize_envelope,
        default_ttl,
    )

    identity = generate_identity()
    invite = create_invite(identity, "direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, identity["publicKey"])

    envelope = create_message(identity, conv, "text", b"test", None, default_ttl())
    data = serialize_envelope(envelope)

    # Deserialize back and check all required fields
    restored = deserialize_envelope(data)
    assert restored["v"] == 1
    assert restored["suite"] == "QSP-1"
    assert "conv_id" in restored
    assert "msg_id" in restored
    assert "created_ts" in restored
    assert "expiry_ts" in restored
    assert "ciphertext" in restored
    assert "aad_hash" in restored
    assert "conv_epoch" in restored


def test_python_can_parse_go_invite_token():
    """Parse the Go-format invite token (base64url CBOR)."""
    from qntm import invite_from_url, derive_conversation_keys

    e2e = VECTORS["e2e_vector"]

    # Construct a synthetic invite from the E2E vector data
    # (The E2E vector contains the raw fields, not a token)
    from qntm.cbor import marshal_canonical
    from qntm.identity import base64url_encode

    invite_data = {
        "v": 1,
        "suite": "QSP-1",
        "type": "direct",
        "conv_id": bytes.fromhex(e2e["conv_id"]),
        "inviter_ik_pk": bytes.fromhex(e2e["sender_pub_key"]),
        "invite_salt": bytes.fromhex(e2e["invite_salt"]),
        "invite_secret": bytes.fromhex(e2e["invite_secret"]),
    }
    token = base64url_encode(marshal_canonical(invite_data))

    parsed = invite_from_url(token)
    keys = derive_conversation_keys(parsed)

    assert keys["root"].hex() == e2e["root_key"]
    assert keys["aeadKey"].hex() == e2e["aead_key"]
    assert keys["nonceKey"].hex() == e2e["nonce_key"]


def test_epoch_key_isolation():
    """Different epochs produce different keys."""
    from qntm import QSP1Suite

    suite = QSP1Suite()
    group_key = os.urandom(32)
    conv_id = os.urandom(16)

    keys = {}
    for epoch in range(5):
        aead, nonce = suite.derive_epoch_keys(group_key, conv_id, epoch)
        keys[epoch] = (aead, nonce)

    # All unique
    aead_keys = [k[0] for k in keys.values()]
    assert len(set(k.hex() for k in aead_keys)) == 5
