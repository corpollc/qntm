"""Tests for group event CBOR→JSON decoding, human-readable formatting, and
group state application on receive in CLI."""

import json
import os
import tempfile
import pytest

from qntm.cli import (
    _decode_group_body,
    _format_group_event,
    _json_safe,
    _apply_group_event,
    _save_conversations,
    _load_conversations,
)
from qntm.group import (
    GroupState,
    create_group_genesis_body,
    create_group_add_body,
    create_group_remove_body,
    create_group_rekey_body,
    create_rekey,
    parse_group_genesis_body,
)
from qntm.identity import generate_identity, key_id_from_public_key, base64url_encode
from qntm.crypto import QSP1Suite

_suite = QSP1Suite()


def _make_identity():
    return generate_identity()


class TestDecodeGroupBody:
    def test_genesis_decodes_to_json(self):
        creator = _make_identity()
        body = create_group_genesis_body("Ops", "Ops group", creator, [])
        result = _decode_group_body("group_genesis", body)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["group_name"] == "Ops"
        assert len(parsed["founding_members"]) == 1

    def test_add_decodes_to_json(self):
        adder = _make_identity()
        new_member = _make_identity()
        body = create_group_add_body(adder, [new_member["publicKey"]])
        result = _decode_group_body("group_add", body)
        assert result is not None
        parsed = json.loads(result)
        assert len(parsed["new_members"]) == 1

    def test_remove_decodes_to_json(self):
        member = _make_identity()
        kid = key_id_from_public_key(member["publicKey"])
        body = create_group_remove_body([kid], "policy violation")
        result = _decode_group_body("group_remove", body)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["reason"] == "policy violation"
        assert len(parsed["removed_members"]) == 1

    def test_rekey_decodes_to_json(self):
        m1 = _make_identity()
        kid = key_id_from_public_key(m1["publicKey"])
        conv_id = b"\xab" * 16
        new_key = _suite.generate_group_key()
        members = [{"kid": kid, "public_key": m1["publicKey"]}]
        body = create_group_rekey_body(new_key, 2, members, conv_id)
        result = _decode_group_body("group_rekey", body)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["new_conv_epoch"] == 2
        assert len(parsed["wrapped_keys"]) == 1

    def test_returns_none_for_text(self):
        assert _decode_group_body("text", b"hello") is None

    def test_returns_none_for_bad_cbor(self):
        assert _decode_group_body("group_genesis", b"not cbor") is None


class TestFormatGroupEvent:
    def test_genesis_format(self):
        body_json = json.dumps({
            "group_name": "Ops Team",
            "founding_members": [{"key_id": "a"}, {"key_id": "b"}],
        })
        result = _format_group_event("group_genesis", body_json, "abc12345")
        assert result is not None
        assert "Ops Team" in result
        assert "2 members" in result

    def test_add_format(self):
        body_json = json.dumps({
            "new_members": [{"key_id": "c"}],
        })
        result = _format_group_event("group_add", body_json, "abc12345")
        assert "abc12345" in result
        assert "added 1 member" in result

    def test_remove_format_with_reason(self):
        body_json = json.dumps({
            "removed_members": ["c"],
            "reason": "violated policy",
        })
        result = _format_group_event("group_remove", body_json, "abc12345")
        assert "removed 1 member" in result
        assert "violated policy" in result

    def test_remove_format_without_reason(self):
        body_json = json.dumps({
            "removed_members": ["c"],
            "reason": "",
        })
        result = _format_group_event("group_remove", body_json, "abc12345")
        assert "violated policy" not in result

    def test_rekey_format(self):
        body_json = json.dumps({
            "new_conv_epoch": 5,
            "wrapped_keys": {},
        })
        result = _format_group_event("group_rekey", body_json)
        assert "Security keys rotated" in result
        assert "epoch 5" in result

    def test_returns_none_for_unknown_type(self):
        assert _format_group_event("text", "{}") is None

    def test_returns_none_for_bad_json(self):
        assert _format_group_event("group_genesis", "not json") is None


class TestApplyGroupEvent:
    """Tests for _apply_group_event which mutates conversation state on receive."""

    def _make_conv_record(self, config_dir, identity):
        """Create a minimal conversation record."""
        kid_hex = identity["keyID"].hex().lower()
        pk_hex = identity["publicKey"].hex()
        conv_record = {
            "id": os.urandom(16).hex(),
            "type": "group",
            "keys": {
                "root": os.urandom(32).hex(),
                "aead_key": os.urandom(32).hex(),
                "nonce_key": os.urandom(32).hex(),
            },
            "participants": [kid_hex],
            "participant_public_keys": [pk_hex],
            "current_epoch": 0,
        }
        conversations = [conv_record]
        _save_conversations(config_dir, conversations)
        return conv_record, conversations

    def test_group_add_updates_roster(self, tmp_path):
        config_dir = str(tmp_path)
        alice = _make_identity()
        bob = _make_identity()

        conv_record, conversations = self._make_conv_record(config_dir, alice)

        body = create_group_add_body(alice, [bob["publicKey"]])
        _apply_group_event(config_dir, conv_record, conversations, "group_add", body, alice)

        bob_kid_hex = key_id_from_public_key(bob["publicKey"]).hex().lower()
        assert bob_kid_hex in conv_record["participants"]
        assert bob["publicKey"].hex() in conv_record["participant_public_keys"]

    def test_group_remove_updates_roster(self, tmp_path):
        config_dir = str(tmp_path)
        alice = _make_identity()
        bob = _make_identity()
        bob_kid = key_id_from_public_key(bob["publicKey"])

        conv_record, conversations = self._make_conv_record(config_dir, alice)
        # Add bob first
        conv_record["participants"].append(bob_kid.hex().lower())
        conv_record["participant_public_keys"].append(bob["publicKey"].hex())

        body = create_group_remove_body([bob_kid])
        _apply_group_event(config_dir, conv_record, conversations, "group_remove", body, alice)

        assert bob_kid.hex().lower() not in conv_record["participants"]

    def test_group_rekey_updates_epoch_and_keys(self, tmp_path):
        config_dir = str(tmp_path)
        alice = _make_identity()

        conv_record, conversations = self._make_conv_record(config_dir, alice)
        conv_id_bytes = bytes.fromhex(conv_record["id"])

        # Build a group state with alice
        state = GroupState()
        genesis = create_group_genesis_body("Test", "", alice, [])
        state.apply_genesis(parse_group_genesis_body(genesis))

        # Create a rekey (need a conv_crypto dict)
        conv_crypto = {
            "id": conv_id_bytes,
            "type": "group",
            "keys": {
                "root": bytes.fromhex(conv_record["keys"]["root"]),
                "aeadKey": bytes.fromhex(conv_record["keys"]["aead_key"]),
                "nonceKey": bytes.fromhex(conv_record["keys"]["nonce_key"]),
            },
            "participants": [alice["keyID"]],
            "currentEpoch": 0,
        }
        rekey_body, new_group_key = create_rekey(alice, conv_crypto, state, conv_id_bytes)

        old_epoch = conv_record["current_epoch"]
        _apply_group_event(config_dir, conv_record, conversations, "group_rekey", rekey_body, alice)

        assert conv_record["current_epoch"] == 1
        assert conv_record["current_epoch"] != old_epoch

    def test_group_rekey_excluded_member_no_update(self, tmp_path):
        config_dir = str(tmp_path)
        alice = _make_identity()
        bob = _make_identity()

        conv_record, conversations = self._make_conv_record(config_dir, alice)
        conv_id_bytes = bytes.fromhex(conv_record["id"])

        # Build a group state with only bob (alice excluded)
        state = GroupState()
        genesis = create_group_genesis_body("Test", "", bob, [])
        state.apply_genesis(parse_group_genesis_body(genesis))

        conv_crypto = {
            "id": conv_id_bytes,
            "type": "group",
            "keys": {
                "root": bytes.fromhex(conv_record["keys"]["root"]),
                "aeadKey": bytes.fromhex(conv_record["keys"]["aead_key"]),
                "nonceKey": bytes.fromhex(conv_record["keys"]["nonce_key"]),
            },
            "participants": [bob["keyID"]],
            "currentEpoch": 0,
        }
        rekey_body, _ = create_rekey(bob, conv_crypto, state, conv_id_bytes)

        old_keys = dict(conv_record["keys"])
        _apply_group_event(config_dir, conv_record, conversations, "group_rekey", rekey_body, alice)

        # Alice couldn't unwrap — keys should NOT change
        assert conv_record["keys"]["aead_key"] == old_keys["aead_key"]
        assert conv_record["keys"]["nonce_key"] == old_keys["nonce_key"]
        assert conv_record["current_epoch"] == 0

    def test_ignores_text_body_type(self, tmp_path):
        config_dir = str(tmp_path)
        alice = _make_identity()
        conv_record, conversations = self._make_conv_record(config_dir, alice)
        old_participants = list(conv_record["participants"])
        _apply_group_event(config_dir, conv_record, conversations, "text", b"hello", alice)
        assert conv_record["participants"] == old_participants
