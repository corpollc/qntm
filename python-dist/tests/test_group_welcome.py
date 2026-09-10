"""Real encrypted contact-add boundaries; all identities are synthetic."""
import copy

import pytest

from qntm import (
    QSP1Suite, generate_identity, create_invite, create_conversation, derive_conversation_keys,
    create_message, decrypt_message, marshal_canonical, unmarshal, GroupState,
    create_group_genesis_body, parse_group_genesis_body, parse_group_rekey_body, apply_rekey, create_rekey,
    base64url_encode, prepare_group_addition, open_group_welcome, is_group_welcome_envelope,
    GROUP_WELCOME_TTL, MAX_GROUP_WELCOME_BYTES,
)
from qntm.gate import seal_secret, open_secret

suite = QSP1Suite()


def setup(epoch=0):
    owner, peer, late = generate_identity(), generate_identity(), generate_identity()
    invite = create_invite(owner, "group")
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    state = GroupState()
    state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("Colleagues", "private roster", owner, [peer["publicKey"]])))
    conversation["participants"] = state.list_members()
    if epoch:
        apply_rekey(conversation, suite.generate_group_key(), epoch)
    return owner, peer, late, conversation, state


@pytest.mark.parametrize("epoch", [0, 7])
def test_add_has_fresh_keys_without_old_history(epoch):
    owner, peer, late, conversation, state = setup(epoch)
    before, roster = copy.deepcopy(conversation), state.snapshot()
    earlier = create_message(owner, conversation, "text", b"before addition")
    added = prepare_group_addition(owner, conversation, state, [late["publicKey"]])
    assert conversation == before and state.snapshot() == roster
    assert added["conversation"]["currentEpoch"] == epoch + 1
    assert added["conversation"]["keys"]["root"] != before["keys"]["root"]
    assert unmarshal(decrypt_message(added["addition"], before)["inner"]["body"])["group_epoch"] == epoch
    rekey = parse_group_rekey_body(decrypt_message(added["rekey"], before)["inner"]["body"])
    peer_key = suite.unwrap_key_for_recipient(rekey["wrapped_keys"][base64url_encode(peer["keyID"])],
                                              peer["privateKey"], peer["keyID"], before["id"])
    assert peer_key == added["conversation"]["keys"]["root"]
    envelope = added["welcomes"][0]
    joined = open_group_welcome(late, marshal_canonical(envelope), conversation_id=conversation["id"], inviter_public_key=owner["publicKey"])
    assert joined["rekey_id"] == added["rekey"]["msg_id"]
    assert joined["addition_id"] == added["addition"]["msg_id"]
    assert joined["conversation"]["keys"] == added["conversation"]["keys"]
    assert "inviteToken" not in joined["conversation"] and "epochKeys" not in joined["conversation"]
    with pytest.raises(Exception):
        decrypt_message(earlier, joined["conversation"])
    after = create_message(late, joined["conversation"], "text", b"hello group")
    assert decrypt_message(after, added["conversation"])["inner"]["body"] == b"hello group"
    with pytest.raises(Exception):
        decrypt_message(after, before)
    assert is_group_welcome_envelope(envelope)
    assert set(envelope) == set("v,suite,kind,conv_id,msg_id,conv_epoch,created_ts,expiry_ts,ciphertext".split(","))
    with pytest.raises(Exception):
        decrypt_message(envelope, before)


def test_member_initiated_addition_and_recipient_encryption():
    owner, peer, late, conversation, state = setup()
    second = generate_identity()
    snapshot = state.snapshot()
    state = GroupState()
    state.apply_genesis(snapshot)
    added = prepare_group_addition(peer, conversation, state, [late["publicKey"], second["publicKey"]])
    expected = {"conversation_id": conversation["id"], "inviter_public_key": peer["publicKey"]}
    first = open_group_welcome(late, marshal_canonical(added["welcomes"][0]), **expected)
    next_member = open_group_welcome(second, marshal_canonical(added["welcomes"][1]), **expected)
    assert first["state"].creator == owner["keyID"]
    assert first["conversation"]["keys"] == next_member["conversation"]["keys"]
    with pytest.raises(Exception):
        open_group_welcome(second, marshal_canonical(added["welcomes"][0]), **expected)
    with pytest.raises(Exception):
        open_group_welcome(late, marshal_canonical(added["welcomes"][0]), conversation_id=conversation["id"], inviter_public_key=owner["publicKey"])


def test_invalid_additions_do_not_mutate_state():
    owner, peer, late, conversation, state = setup()
    before = state.snapshot()
    with pytest.raises(ValueError, match="current group member"):
        prepare_group_addition(generate_identity(), conversation, state, [late["publicKey"]])
    for recipients in [[owner["publicKey"]], [late["publicKey"], late["publicKey"]], [bytes(32)], []]:
        with pytest.raises(ValueError):
            prepare_group_addition(owner, conversation, state, recipients)
    with pytest.raises(ValueError, match="roster"):
        prepare_group_addition(owner, {**conversation, "participants": []}, state, [late["publicKey"]])
    for ttl in [0, -1, 1.5, True, GROUP_WELCOME_TTL + 1]:
        with pytest.raises(ValueError, match="lifetime"):
            prepare_group_addition(owner, conversation, state, [late["publicKey"]], ttl)
    assert before == state.snapshot()


def test_outer_context_expiry_size_and_group_binding():
    owner, _, late, conversation, state = setup()
    envelope = prepare_group_addition(owner, conversation, state, [late["publicKey"]])["welcomes"][0]
    expected = {"conversation_id": conversation["id"], "inviter_public_key": owner["publicKey"]}
    for field, value in {"v": 2, "suite": "other", "kind": "text", "conv_id": bytes(16), "msg_id": bytes(16),
                         "conv_epoch": 2, "created_ts": envelope["created_ts"] - 1,
                         "expiry_ts": envelope["expiry_ts"] - 1, "ciphertext": bytes(40)}.items():
        with pytest.raises(Exception):
            open_group_welcome(late, marshal_canonical({**envelope, field: value}), **expected)
    wire = marshal_canonical(envelope)
    with pytest.raises(ValueError, match="different group"):
        open_group_welcome(late, wire, conversation_id=bytes(16), inviter_public_key=owner["publicKey"])
    for at in [envelope["expiry_ts"] + 1, envelope["created_ts"] - 601]:
        with pytest.raises(ValueError):
            open_group_welcome(late, wire, **expected, at=at)
    assert open_group_welcome(late, wire, **expected, at=envelope["expiry_ts"])["conversation"]["currentEpoch"] == 1
    with pytest.raises(ValueError, match="size"):
        open_group_welcome(late, bytes(MAX_GROUP_WELCOME_BYTES + 1), **expected)
    with pytest.raises(ValueError):
        open_group_welcome(late, marshal_canonical({**envelope, "extra": True}), **expected)


def test_recipient_cannot_forge_inviter_signature_with_shared_box_key():
    owner, _, late, conversation, state = setup()
    envelope = prepare_group_addition(owner, conversation, state, [late["publicKey"]])["welcomes"][0]
    opened = unmarshal(open_secret(late["privateKey"], owner["publicKey"], envelope["ciphertext"]))
    opened["payload"]["group_key"] = suite.generate_group_key()
    forged = {**envelope, "ciphertext": seal_secret(late["privateKey"], owner["publicKey"], marshal_canonical(opened))}
    with pytest.raises(ValueError, match="signature"):
        open_group_welcome(late, marshal_canonical(forged), conversation_id=conversation["id"], inviter_public_key=owner["publicKey"])


@pytest.mark.parametrize("mutation", ["missing_recipient", "duplicate", "creator_role", "recipient", "weak_key", "oversized", "role_type"])
def test_full_signed_roster_validation(mutation):
    owner, peer, late, conversation, state = setup()
    envelope = prepare_group_addition(owner, conversation, state, [late["publicKey"]])["welcomes"][0]
    payload = unmarshal(open_secret(late["privateKey"], owner["publicKey"], envelope["ciphertext"]))["payload"]
    members = payload["group_state"]["founding_members"]
    if mutation == "missing_recipient":
        payload["group_state"]["founding_members"] = [m for m in members if m["key_id"] != late["keyID"]]
    elif mutation == "duplicate":
        members.append(members[0])
    elif mutation == "creator_role":
        members[0]["role"] = "member"
    elif mutation == "recipient":
        payload["recipient_ik_pk"] = peer["publicKey"]
    elif mutation == "weak_key":
        members[1]["public_key"] = bytes(32)
    elif mutation == "oversized":
        payload["group_state"]["description"] = "x" * 4097
    elif mutation == "role_type":
        members[1]["role"] = ["admin"]
    signature = suite.sign(owner["privateKey"], marshal_canonical(payload))
    ciphertext = seal_secret(owner["privateKey"], late["publicKey"], marshal_canonical({"payload": payload, "signature": signature}))
    with pytest.raises(ValueError):
        open_group_welcome(late, marshal_canonical({**envelope, "ciphertext": ciphertext}),
                           conversation_id=conversation["id"], inviter_public_key=owner["publicKey"])


def test_snapshot_is_detached():
    owner, _, _, _, state = setup()
    snapshot = state.snapshot()
    snapshot["founding_members"][0]["role"] = "member"
    assert state.is_admin(owner["keyID"])
    assert state.snapshot()["founding_members"][0]["role"] == "admin"


def test_removal_and_readmission_preserve_key_boundaries():
    owner, _, late, conversation, state = setup()
    expected = {"conversation_id": conversation["id"], "inviter_public_key": owner["publicKey"]}
    added = prepare_group_addition(owner, conversation, state, [late["publicKey"]])
    original_welcome = marshal_canonical(added["welcomes"][0])
    joined = open_group_welcome(late, original_welcome, **expected)
    remaining = GroupState()
    remaining.apply_genesis(added["state"].snapshot())
    remaining.apply_remove({"removed_members": [late["keyID"]]})
    body, root = create_rekey(owner, added["conversation"], remaining, conversation["id"])
    assert base64url_encode(late["keyID"]) not in parse_group_rekey_body(body)["wrapped_keys"]
    after_removal = copy.deepcopy(added["conversation"])
    after_removal["participants"] = remaining.list_members()
    apply_rekey(after_removal, root, 2)
    private_message = create_message(owner, after_removal, "text", b"after removal")
    for old in [joined, open_group_welcome(late, original_welcome, **expected)]:
        with pytest.raises(Exception):
            decrypt_message(private_message, old["conversation"])
    readmitted = prepare_group_addition(owner, after_removal, remaining, [late["publicKey"]])
    rejoined = open_group_welcome(late, marshal_canonical(readmitted["welcomes"][0]), **expected)
    assert rejoined["conversation"]["currentEpoch"] == 3
    with pytest.raises(Exception):
        decrypt_message(private_message, rejoined["conversation"])
    latest = create_message(owner, readmitted["conversation"], "text", b"welcome back")
    assert decrypt_message(latest, rejoined["conversation"])["inner"]["body"] == b"welcome back"
