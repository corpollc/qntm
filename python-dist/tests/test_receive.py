"""CLI/MCP receive parity with real signed, encrypted membership and rekey events."""
import base64
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from qntm import cli, mcp_server as mcp
from qntm.crypto import QSP1Suite
from qntm.group import GroupState, parse_group_genesis_body
from qntm.group import (create_group_genesis_body, create_group_add_body,
                        create_group_remove_body, create_group_rekey_body)
from qntm.guidance import pin_contact, prepare_request
from qntm.identity import generate_identity
from qntm.invite import create_invite, derive_conversation_keys
from qntm.message import create_message, serialize_envelope, default_ttl


@pytest.fixture
def conversation(tmp_path, monkeypatch):
    alice, bob, charlie = (generate_identity() for _ in range(3))
    invite = create_invite(alice)
    keys = derive_conversation_keys(invite)
    record = {"id": invite["conv_id"].hex(), "name": "Receive test", "type": "group",
              "participants": [alice["keyID"].hex(), bob["keyID"].hex()], "current_epoch": 0,
              "keys": {"root": keys["root"].hex(), "aead_key": keys["aeadKey"].hex(), "nonce_key": keys["nonceKey"].hex()}}
    state=GroupState();state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("test","",alice,[bob["publicKey"]])))
    record["group_state"]=state.to_dict()
    record["participant_public_keys"]=[alice["publicKey"].hex(),bob["publicKey"].hex()]
    path = str(tmp_path)
    cli._save_identity(path, alice)
    cli._save_conversations(path, [record])
    monkeypatch.setenv("QNTM_CONFIG_DIR", path)
    monkeypatch.setenv("QNTM_RELAY_URL", "http://localhost:9999")
    return path, record, alice, bob, charlie


def wire(identity, record, body_type, body):
    envelope = create_message(identity, cli._conv_to_crypto(record), body_type, body, None, default_ttl())
    return {"envelope_b64": base64.b64encode(serialize_envelope(envelope)).decode()}


def rotated(record, identity, epoch=1):
    suite = QSP1Suite()
    key = suite.generate_group_key()
    conv_id = bytes.fromhex(record["id"])
    body = create_group_rekey_body(key, epoch, [{"kid":bytes.fromhex(row["key_id"]),"public_key":bytes.fromhex(row["public_key"])} for row in record["group_state"]["members"]], conv_id)
    updated = deepcopy(record)
    aead, nonce = suite.derive_epoch_keys(key, conv_id, epoch)
    updated.update(current_epoch=epoch, keys={"root": key.hex(), "aead_key": aead.hex(), "nonce_key": nonce.hex()})
    return body, updated


@pytest.mark.parametrize("surface", ["cli", "mcp"])
def test_membership_rekey_and_nontext_survive_restart(conversation, monkeypatch, capsys, surface):
    path, record, alice, bob, charlie = conversation
    record.pop("group_state")
    cli._save_conversations(path,[record])
    state=GroupState();state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("test","",alice,[charlie["publicKey"]])))
    rekey, updated = rotated({**record,"group_state":state.to_dict()}, alice)
    batch = [
        wire(alice, record, "group_genesis", create_group_genesis_body("test", "", alice, [bob["publicKey"]])),
        wire(alice, record, "group_add", create_group_add_body(alice, [charlie["publicKey"]])),
        wire(alice, record, "group_remove", create_group_remove_body([bob["keyID"]], "left")),
        wire(alice, record, "group_rekey", rekey),
        wire(alice, updated, "text", b"after rekey in the same batch"),
        wire(alice, updated, "gate.result", b'{"status":200,"body":"untrusted"}'),
        wire(alice, updated, "attachment", b"\xff\x00\xfe"),
    ]
    def poll(*args):
        assert args[-1] == 0
        return batch, 7
    monkeypatch.setattr(mcp, "_recv_once", poll)
    monkeypatch.setattr(cli, "_http_poll", poll)
    if surface == "mcp":
        result = mcp.receive_messages(record["id"])
        assert result["count"] == 7
        messages = result["messages"]
        assert all(entry["verified"] for entry in messages)
    else:
        cli.cmd_recv(SimpleNamespace(config_dir=path, dropbox_url="http://localhost:9999", conversation=record["id"]))
        result = json.loads(capsys.readouterr().out)
        assert result["data"]["received"] == 7
        messages = result["data"]["messages"]
    assert json.loads(messages[0]["unsafe_body"])["group_name"] == "test"
    assert messages[4]["unsafe_body"] == "after rekey in the same batch"
    assert json.loads(messages[5]["unsafe_body"])["status"] == 200
    assert base64.b64decode(messages[6]["unsafe_body_b64"]) == b"\xff\x00\xfe"
    stored = cli._load_conversations(path)[0]
    assert stored["keys"] == updated["keys"]
    assert stored["current_epoch"] == 1
    assert set(stored["participants"]) == {alice["keyID"].hex(), charlie["keyID"].hex()}
    # A fresh tool invocation loads persisted keys and does not replay history.
    def after_restart(*args):
        assert args[-1] == 7
        return [batch[-1], wire(alice, updated, "text", b"after restart")], 8
    monkeypatch.setattr(mcp, "_recv_once", after_restart)
    assert mcp.receive_messages(record["id"])["count"] == 1
    history = cli._load_history(path, record["id"])
    assert len(history) == 8
    assert history[-1]["unsafe_body"] == "after restart"


def test_removed_pinned_contact_blocks_guidance(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    pin_contact(path, "http://localhost:9999", "counsel", "legal", "Counsel", "human", record["id"], bob["keyID"].hex())
    prepare_request(path, "http://localhost:9999", "counsel", "Question")
    event = wire(alice, record, "group_remove", create_group_remove_body([bob["keyID"]], "left"))
    monkeypatch.setattr(mcp, "_recv_once", lambda *args: ([event], 1))
    assert mcp.receive_messages(record["id"])["count"] == 1
    with pytest.raises(ValueError, match="recipient"):
        prepare_request(path, "http://localhost:9999", "counsel", "Question")


def test_excluded_member_does_not_obtain_rekey(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    cli._save_identity(path,bob)
    removal=wire(alice,record,"group_remove",create_group_remove_body([bob["keyID"]],"left"))
    state=GroupState();state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("test","",alice,[])))
    rekey,updated=rotated({**record,"group_state":state.to_dict()},alice)
    batch=[removal,wire(alice,record,"group_rekey",rekey),wire(alice,updated,"text",b"excluded")]
    monkeypatch.setattr(mcp,"_recv_once",lambda *args:(batch,3))
    result=mcp.receive_messages(record["id"])
    assert result["count"]==2
    assert cli._load_conversations(path)[0]["current_epoch"]==0
    assert cli._load_conversations(path)[0]["excluded"]
    assert all(e.get("unsafe_body")!="excluded" for e in cli._load_history(path,record["id"]))


def test_history_write_failure_does_not_advance_cursor_or_keys(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    rekey, updated = rotated(record, alice)
    batch = [wire(bob, record, "group_rekey", rekey), wire(alice, updated, "text", b"saved on retry")]
    monkeypatch.setattr(mcp, "_recv_once", lambda *args: (batch, 2))
    save_history = cli._save_history
    def fail(*args):
        raise OSError("disk full")
    monkeypatch.setattr(cli, "_save_history", fail)
    assert "disk full" in mcp.receive_messages(record["id"])["error"]
    assert cli._load_cursors(path) == {}
    assert cli._load_conversations(path)[0]["current_epoch"] == 0
    monkeypatch.setattr(cli, "_save_history", save_history)
    assert mcp.receive_messages(record["id"])["count"] == 2


def test_stale_rekey_cannot_roll_back_epoch(conversation, monkeypatch):
    path, record, alice, _, _ = conversation
    _, updated = rotated(record, alice, 2)
    cli._save_conversations(path, [updated])
    old_rekey, _ = rotated(record, alice, 1)
    monkeypatch.setattr(mcp, "_recv_once", lambda *args: ([wire(alice, updated, "group_rekey", old_rekey)], 1))
    assert mcp.receive_messages(record["id"])["count"] == 0
    assert cli._load_conversations(path)[0]["keys"] == updated["keys"]
