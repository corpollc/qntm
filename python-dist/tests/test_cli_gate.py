"""Tests for gate CLI commands.

Tests the logic functions that back the CLI gate subcommands,
not the argparse wiring itself.
"""

import base64
import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from qntm.identity import generate_identity, base64url_encode, base64url_decode
from qntm.gate import (
    Recipe,
    RecipeParam,
    compute_payload_hash,
    hash_request,
    resolve_recipe,
    seal_secret,
    open_secret,
    sign_approval,
    sign_request,
    verify_approval,
    verify_request,
    GateConversationMessage,
    GATE_MESSAGE_REQUEST,
    GATE_MESSAGE_APPROVAL,
    GATE_MESSAGE_EXECUTED,
    GATE_MESSAGE_PROMOTE,
    GATE_MESSAGE_SECRET,
    PromotePayload,
    SecretPayload,
    ThresholdRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config_dir_with_identity():
    """Create a temp config dir with a generated identity and return (dir, identity)."""
    tmpdir = tempfile.mkdtemp()
    ident = generate_identity()
    ident_data = {
        "private_key": ident["privateKey"].hex(),
        "public_key": ident["publicKey"].hex(),
        "key_id": ident["keyID"].hex(),
    }
    with open(os.path.join(tmpdir, "identity.json"), "w") as f:
        json.dump(ident_data, f)
    return tmpdir, ident


def _make_conversation(tmpdir, ident):
    """Create a dummy conversation and return (conv_id_hex, conv_record)."""
    from qntm.invite import create_invite, derive_conversation_keys, create_conversation, add_participant
    invite = create_invite(ident, "group")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, ident["publicKey"])
    conv_id_hex = conv["id"].hex()
    conv_record = {
        "id": conv_id_hex,
        "name": "test-conv",
        "type": "group",
        "keys": {
            "root": keys["root"].hex(),
            "aead_key": keys["aeadKey"].hex(),
            "nonce_key": keys["nonceKey"].hex(),
        },
        "participants": [p.hex() for p in conv["participants"]],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "current_epoch": 0,
    }
    convs_path = os.path.join(tmpdir, "conversations.json")
    with open(convs_path, "w") as f:
        json.dump([conv_record], f)
    return conv_id_hex, conv_record


def _write_history(tmpdir, conv_id_hex, entries):
    """Write chat history entries to the expected path."""
    chats_dir = os.path.join(tmpdir, "chats")
    os.makedirs(chats_dir, exist_ok=True)
    with open(os.path.join(chats_dir, f"{conv_id_hex}.json"), "w") as f:
        json.dump(entries, f)


def _write_participant_key_cache(tmpdir, conv_id_hex, identities):
    """Write learned participant public keys for a conversation."""
    cache = {}
    for ident in identities:
        cache[ident["keyID"].hex()] = ident["publicKey"].hex()
    with open(os.path.join(tmpdir, "participant_keys.json"), "w") as f:
        json.dump({conv_id_hex.lower(): cache}, f)


# ---------------------------------------------------------------------------
# Test: load_starter_catalog
# ---------------------------------------------------------------------------

class TestLoadStarterCatalog:
    def test_load_catalog_returns_recipes(self):
        from qntm.cli import _load_starter_catalog
        catalog = _load_starter_catalog()
        assert isinstance(catalog, dict)
        assert len(catalog) > 0

    def test_catalog_contains_known_recipe(self):
        from qntm.cli import _load_starter_catalog
        catalog = _load_starter_catalog()
        assert "jokes.dad" in catalog
        recipe = catalog["jokes.dad"]
        assert isinstance(recipe, Recipe)
        assert recipe.service == "dadjokes"
        assert recipe.verb == "GET"

    def test_catalog_recipe_with_path_params(self):
        from qntm.cli import _load_starter_catalog
        catalog = _load_starter_catalog()
        assert "hn.get-item" in catalog
        recipe = catalog["hn.get-item"]
        assert len(recipe.path_params) == 1
        assert recipe.path_params[0].name == "id"
        assert recipe.path_params[0].required is True

    def test_catalog_env_override(self, tmp_path):
        """QNTM_RECIPE_CATALOG_PATH env var overrides default catalog."""
        custom = {
            "recipes": {
                "custom.test": {
                    "name": "custom.test",
                    "description": "A custom recipe",
                    "service": "test",
                    "verb": "GET",
                    "endpoint": "/test",
                    "target_url": "http://example.com/test",
                    "risk_tier": "read",
                    "threshold": 1,
                }
            }
        }
        p = tmp_path / "custom_catalog.json"
        p.write_text(json.dumps(custom))
        old = os.environ.get("QNTM_RECIPE_CATALOG_PATH")
        try:
            os.environ["QNTM_RECIPE_CATALOG_PATH"] = str(p)
            from qntm.cli import _load_starter_catalog
            catalog = _load_starter_catalog()
            assert "custom.test" in catalog
        finally:
            if old is None:
                os.environ.pop("QNTM_RECIPE_CATALOG_PATH", None)
            else:
                os.environ["QNTM_RECIPE_CATALOG_PATH"] = old


class TestLoadKnownParticipantPublicKeys:
    def test_merges_local_identity_and_learned_cache(self):
        from qntm.cli import _load_known_participant_public_keys

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)

        carol = generate_identity()
        _write_participant_key_cache(tmpdir, conv_id_hex, [carol])

        merged = _load_known_participant_public_keys(tmpdir, conv_record, identity=alice)
        merged_hex = {pk.hex() for pk in merged.values()}

        assert alice["publicKey"].hex() in merged_hex
        assert carol["publicKey"].hex() in merged_hex


class TestGateCommandParticipantRosters:
    def test_gate_run_uses_conversation_participant_kids_without_public_key_cache(self, monkeypatch):
        from qntm.cli import cmd_gate_run

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()
        conv_record["participants"].append(bob["keyID"].hex())
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump([conv_record], f)

        recipe = Recipe(
            name="jokes.dad",
            description="Get a dad joke",
            service="dadjokes",
            verb="GET",
            endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read",
            threshold=2,
        )
        captured = {}

        monkeypatch.setattr("qntm.cli._load_starter_catalog", lambda: {"jokes.dad": recipe})
        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        def fake_send(identity, conv_crypto, conv_id_hex, body_type, payload_dict, dropbox_url):
            captured["payload"] = payload_dict
            return {"seq": 1}, {"msg_id": uuid.uuid4().bytes, "created_ts": int(time.time())}

        monkeypatch.setattr("qntm.cli._send_gate_message_to_conv", fake_send)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            recipe="jokes.dad",
            arg=[],
        )
        cmd_gate_run(args)

        assert set(captured["payload"]["eligible_signer_kids"]) == {
            base64url_encode(alice["keyID"]),
            base64url_encode(bob["keyID"]),
        }

    def test_gate_promote_fails_closed_when_participant_public_keys_are_missing(self, monkeypatch):
        from qntm.cli import cmd_gate_promote

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()
        conv_record["participants"].append(bob["keyID"].hex())
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump([conv_record], f)

        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)
        monkeypatch.setattr("qntm.cli._error", lambda message: (_ for _ in ()).throw(RuntimeError(message)))

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            gateway_kid="gateway-kid",
            threshold=2,
        )

        with pytest.raises(RuntimeError, match="missing participant public keys"):
            cmd_gate_promote(args)


class TestGovernanceCommands:
    def test_gov_propose_add_builds_member_add_payload(self, monkeypatch):
        from qntm.cli import cmd_gov_propose_add

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, _conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()
        captured = {}

        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        def fake_send(identity, conv_crypto, conv_id_hex, body_type, payload_dict, dropbox_url):
            captured["body_type"] = body_type
            captured["payload"] = payload_dict
            return {"seq": 1}, {"msg_id": uuid.uuid4().bytes, "created_ts": int(time.time())}

        monkeypatch.setattr("qntm.cli._send_gate_message_to_conv", fake_send)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            public_key=base64url_encode(bob["publicKey"]),
            required_approvals=0,
            expires_in=3600,
        )
        cmd_gov_propose_add(args)

        assert captured["body_type"] == "gov.propose"
        assert captured["payload"]["proposal_type"] == "member_add"
        assert captured["payload"]["proposed_members"][0]["kid"] == base64url_encode(bob["keyID"])
        assert captured["payload"]["proposed_members"][0]["public_key"] == base64url_encode(bob["publicKey"])
        assert captured["payload"]["required_approvals"] == 1
        assert captured["payload"]["eligible_signer_kids"] == [base64url_encode(alice["keyID"])]

    def test_gov_propose_floor_defaults_required_approvals_to_current_participant_quorum(self, monkeypatch):
        from qntm.cli import cmd_gov_propose_floor

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()
        conv_record["participants"].append(bob["keyID"].hex())
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump([conv_record], f)
        _write_history(tmpdir, conv_id_hex, [{
            "msg_id": uuid.uuid4().hex,
            "direction": "incoming",
            "body_type": "gate.promote",
            "unsafe_body": json.dumps({
                "type": "gate.promote",
                "conv_id": conv_id_hex,
                "floor": 3,
                "rules": [{"service": "*", "endpoint": "*", "verb": "*", "m": 3}],
            }),
            "created_ts": int(time.time()),
        }])
        captured = {}

        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        def fake_send(identity, conv_crypto, conv_id_hex, body_type, payload_dict, dropbox_url):
            captured["payload"] = payload_dict
            return {"seq": 1}, {"msg_id": uuid.uuid4().bytes, "created_ts": int(time.time())}

        monkeypatch.setattr("qntm.cli._send_gate_message_to_conv", fake_send)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            floor=4,
            required_approvals=0,
            expires_in=3600,
        )
        cmd_gov_propose_floor(args)

        assert captured["payload"]["proposal_type"] == "floor_change"
        assert captured["payload"]["proposed_floor"] == 4
        assert captured["payload"]["required_approvals"] == 2

    def test_gov_propose_remove_defaults_required_approvals_to_remaining_members(self, monkeypatch):
        from qntm.cli import cmd_gov_propose_remove

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()
        charlie = generate_identity()
        conv_record["participants"].extend([bob["keyID"].hex(), charlie["keyID"].hex()])
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump([conv_record], f)
        captured = {}

        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        def fake_send(identity, conv_crypto, conv_id_hex, body_type, payload_dict, dropbox_url):
            captured["payload"] = payload_dict
            return {"seq": 1}, {"msg_id": uuid.uuid4().bytes, "created_ts": int(time.time())}

        monkeypatch.setattr("qntm.cli._send_gate_message_to_conv", fake_send)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            key_id=base64url_encode(charlie["keyID"]),
            required_approvals=0,
            expires_in=3600,
        )
        cmd_gov_propose_remove(args)

        assert captured["payload"]["proposal_type"] == "member_remove"
        assert captured["payload"]["required_approvals"] == 2

    def test_gov_approve_uses_history_proposal_hash(self, monkeypatch):
        from qntm.cli import cmd_gov_approve
        from qntm.governance import create_proposal_body

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, _conv_record = _make_conversation(tmpdir, alice)
        proposal = create_proposal_body(
            alice,
            conv_id=conv_id_hex,
            proposal_type="floor_change",
            proposed_floor=3,
            eligible_signer_kids=[base64url_encode(alice["keyID"])],
            required_approvals=1,
            expires_in_seconds=3600,
        )
        _write_history(tmpdir, conv_id_hex, [{
            "msg_id": uuid.uuid4().hex,
            "direction": "incoming",
            "body_type": "gov.propose",
            "unsafe_body": json.dumps(proposal),
            "created_ts": int(time.time()),
        }])
        captured = {}

        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        def fake_send(identity, conv_crypto, conv_id_hex, body_type, payload_dict, dropbox_url):
            captured["body_type"] = body_type
            captured["payload"] = payload_dict
            return {"seq": 1}, {"msg_id": uuid.uuid4().bytes, "created_ts": int(time.time())}

        monkeypatch.setattr("qntm.cli._send_gate_message_to_conv", fake_send)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
            proposal_id=proposal["proposal_id"],
        )
        cmd_gov_approve(args)

        assert captured["body_type"] == "gov.approve"
        assert captured["payload"]["proposal_id"] == proposal["proposal_id"]
        assert captured["payload"]["signature"]


class TestRecvParticipantLearning:
    def test_recv_merges_sender_into_conversation_participants(self, monkeypatch):
        from qntm.cli import cmd_recv, _load_conversations
        from qntm.message import create_message, serialize_envelope, default_ttl

        tmpdir, alice = _make_config_dir_with_identity()
        conv_id_hex, conv_record = _make_conversation(tmpdir, alice)
        bob = generate_identity()

        conv_crypto = {
            "id": bytes.fromhex(conv_id_hex),
            "type": "direct",
            "keys": {
                "root": bytes.fromhex(conv_record["keys"]["root"]),
                "aeadKey": bytes.fromhex(conv_record["keys"]["aead_key"]),
                "nonceKey": bytes.fromhex(conv_record["keys"]["nonce_key"]),
            },
            "participants": [bytes.fromhex(kid_hex) for kid_hex in conv_record["participants"]],
            "createdAt": datetime.now(timezone.utc),
            "currentEpoch": conv_record["current_epoch"],
        }
        envelope = create_message(
            bob,
            conv_crypto,
            "text",
            b"hello from bob",
            None,
            default_ttl(),
        )
        envelope_b64 = base64.b64encode(serialize_envelope(envelope)).decode()

        monkeypatch.setattr("qntm.cli._http_poll", lambda *_args, **_kwargs: (
            [{"seq": 1, "envelope_b64": envelope_b64}],
            1,
        ))
        monkeypatch.setattr("qntm.cli._output", lambda *args, **kwargs: None)

        args = SimpleNamespace(
            config_dir=tmpdir,
            dropbox_url="http://example.test",
            conversation=conv_id_hex,
        )
        cmd_recv(args)

        updated = _load_conversations(tmpdir)[0]
        assert bob["keyID"].hex() in updated["participants"]


# ---------------------------------------------------------------------------
# Test: build_gate_request_message
# ---------------------------------------------------------------------------

class TestBuildGateRequestMessage:
    def test_builds_valid_request(self):
        from qntm.cli import _build_gate_request_message
        ident = generate_identity()
        recipe = Recipe(
            name="jokes.dad",
            description="Get a dad joke",
            service="dadjokes",
            verb="GET",
            endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read",
            threshold=1,
        )
        msg, request_id = _build_gate_request_message(
            identity=ident,
            recipe=recipe,
            conv_id="test-conv-id",
            args=None,
        )
        assert msg["type"] == GATE_MESSAGE_REQUEST
        assert msg["conv_id"] == "test-conv-id"
        assert msg["verb"] == "GET"
        assert msg["target_endpoint"] == "/"
        assert msg["target_service"] == "dadjokes"
        assert msg["target_url"] == "https://icanhazdadjoke.com/"
        assert msg["signer_kid"] == base64url_encode(ident["keyID"])
        assert "signature" in msg
        assert "expires_at" in msg
        assert msg["request_id"] == request_id
        assert msg["eligible_signer_kids"] == [base64url_encode(ident["keyID"])]
        assert msg["required_approvals"] == 1

    def test_resolves_path_params(self):
        from qntm.cli import _build_gate_request_message
        ident = generate_identity()
        recipe = Recipe(
            name="hn.get-item",
            description="Get HN item",
            service="hackernews",
            verb="GET",
            endpoint="/item/{id}.json",
            target_url="https://hacker-news.firebaseio.com/v0/item/{id}.json",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", required=True, type="string")],
        )
        msg, _ = _build_gate_request_message(
            identity=ident,
            recipe=recipe,
            conv_id="test-conv-id",
            args={"id": "12345"},
        )
        assert msg["target_endpoint"] == "/item/12345.json"
        assert "12345" in msg["target_url"]

    def test_missing_required_param_raises(self):
        from qntm.cli import _build_gate_request_message
        ident = generate_identity()
        recipe = Recipe(
            name="hn.get-item",
            description="Get HN item",
            service="hackernews",
            verb="GET",
            endpoint="/item/{id}.json",
            target_url="https://hacker-news.firebaseio.com/v0/item/{id}.json",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", required=True, type="string")],
        )
        with pytest.raises(ValueError, match="missing required"):
            _build_gate_request_message(
                identity=ident,
                recipe=recipe,
                conv_id="test-conv-id",
                args={},
            )

    def test_signature_is_valid(self):
        from qntm.cli import _build_gate_request_message
        ident = generate_identity()
        recipe = Recipe(
            name="jokes.dad",
            description="Get a dad joke",
            service="dadjokes",
            verb="GET",
            endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read",
            threshold=1,
        )
        msg, _ = _build_gate_request_message(
            identity=ident,
            recipe=recipe,
            conv_id="test-conv-id",
            args=None,
        )
        # Verify the signature
        sig = base64url_decode(msg["signature"])
        from datetime import datetime, timezone
        expires_dt = datetime.fromisoformat(msg["expires_at"].replace("Z", "+00:00"))
        expires_unix = int(expires_dt.timestamp())
        payload_hash = compute_payload_hash(msg.get("payload"))
        assert verify_request(
            ident["publicKey"],
            sig,
            conv_id=msg["conv_id"],
            request_id=msg["request_id"],
            verb=msg["verb"],
            target_endpoint=msg["target_endpoint"],
            target_service=msg["target_service"],
            target_url=msg["target_url"],
            expires_at_unix=expires_unix,
            payload_hash=payload_hash,
            eligible_signer_kids=msg["eligible_signer_kids"],
            required_approvals=msg["required_approvals"],
        )

    def test_recipe_name_and_arguments_included(self):
        from qntm.cli import _build_gate_request_message
        ident = generate_identity()
        recipe = Recipe(
            name="hn.get-item",
            description="Get HN item",
            service="hackernews",
            verb="GET",
            endpoint="/item/{id}.json",
            target_url="https://hacker-news.firebaseio.com/v0/item/{id}.json",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", required=True, type="string")],
        )
        msg, _ = _build_gate_request_message(
            identity=ident,
            recipe=recipe,
            conv_id="test-conv-id",
            args={"id": "42"},
        )
        assert msg["recipe_name"] == "hn.get-item"
        assert msg["arguments"] == {"id": "42"}


# ---------------------------------------------------------------------------
# Test: build_gate_approval_message
# ---------------------------------------------------------------------------

class TestBuildGateApprovalMessage:
    def test_builds_valid_approval(self):
        from qntm.cli import _build_gate_request_message, _build_gate_approval_message
        ident = generate_identity()
        recipe = Recipe(
            name="jokes.dad",
            description="Get a dad joke",
            service="dadjokes",
            verb="GET",
            endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read",
            threshold=1,
        )
        req_msg, request_id = _build_gate_request_message(
            identity=ident, recipe=recipe, conv_id="test-conv-id", args=None,
        )
        # Different identity approves
        approver = generate_identity()
        approval_msg = _build_gate_approval_message(
            identity=approver,
            request_msg=req_msg,
        )
        assert approval_msg["type"] == GATE_MESSAGE_APPROVAL
        assert approval_msg["conv_id"] == "test-conv-id"
        assert approval_msg["request_id"] == request_id
        assert approval_msg["signer_kid"] == base64url_encode(approver["keyID"])
        assert "signature" in approval_msg

    def test_approval_signature_is_valid(self):
        from qntm.cli import _build_gate_request_message, _build_gate_approval_message
        ident = generate_identity()
        recipe = Recipe(
            name="jokes.dad", description="", service="dadjokes",
            verb="GET", endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read", threshold=1,
        )
        req_msg, _ = _build_gate_request_message(
            identity=ident, recipe=recipe, conv_id="test-conv-id", args=None,
        )
        approver = generate_identity()
        approval_msg = _build_gate_approval_message(
            identity=approver, request_msg=req_msg,
        )
        # Verify the approval signature
        from datetime import datetime, timezone
        expires_dt = datetime.fromisoformat(req_msg["expires_at"].replace("Z", "+00:00"))
        expires_unix = int(expires_dt.timestamp())
        payload_hash = compute_payload_hash(req_msg.get("payload"))
        req_hash = hash_request(
            conv_id=req_msg["conv_id"],
            request_id=req_msg["request_id"],
            verb=req_msg["verb"],
            target_endpoint=req_msg["target_endpoint"],
            target_service=req_msg["target_service"],
            target_url=req_msg["target_url"],
            expires_at_unix=expires_unix,
            payload_hash=payload_hash,
            eligible_signer_kids=req_msg.get("eligible_signer_kids", []),
            required_approvals=req_msg.get("required_approvals", 1),
        )
        sig = base64url_decode(approval_msg["signature"])
        assert verify_approval(
            approver["publicKey"],
            sig,
            conv_id=approval_msg["conv_id"],
            request_id=approval_msg["request_id"],
            request_hash=req_hash,
        )


# ---------------------------------------------------------------------------
# Test: scan_gate_history
# ---------------------------------------------------------------------------

class TestScanGateHistory:
    def _make_request_entry(self, ident, conv_id="test-conv-id"):
        from qntm.cli import _build_gate_request_message
        recipe = Recipe(
            name="jokes.dad", description="", service="dadjokes",
            verb="GET", endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read", threshold=1,
        )
        msg, request_id = _build_gate_request_message(
            identity=ident, recipe=recipe, conv_id=conv_id, args=None,
        )
        return {
            "msg_id": uuid.uuid4().hex,
            "direction": "incoming",
            "body_type": GATE_MESSAGE_REQUEST,
            "unsafe_body": json.dumps(msg),
            "created_ts": int(time.time()),
        }, msg, request_id

    def _make_approval_entry(self, approver_ident, request_msg):
        from qntm.cli import _build_gate_approval_message
        approval_msg = _build_gate_approval_message(
            identity=approver_ident, request_msg=request_msg,
        )
        return {
            "msg_id": uuid.uuid4().hex,
            "direction": "incoming",
            "body_type": GATE_MESSAGE_APPROVAL,
            "unsafe_body": json.dumps(approval_msg),
            "created_ts": int(time.time()),
        }, approval_msg

    def _make_executed_entry(self, request_msg):
        exec_msg = {
            "type": GATE_MESSAGE_EXECUTED,
            "conv_id": request_msg["conv_id"],
            "request_id": request_msg["request_id"],
        }
        return {
            "msg_id": uuid.uuid4().hex,
            "direction": "incoming",
            "body_type": GATE_MESSAGE_EXECUTED,
            "unsafe_body": json.dumps(exec_msg),
            "created_ts": int(time.time()),
        }

    def test_finds_pending_request(self):
        from qntm.cli import _scan_gate_history
        ident = generate_identity()
        entry, msg, req_id = self._make_request_entry(ident)
        requests, approvals, executed = _scan_gate_history([entry])
        assert req_id in requests
        assert requests[req_id]["type"] == GATE_MESSAGE_REQUEST

    def test_finds_approvals(self):
        from qntm.cli import _scan_gate_history
        ident = generate_identity()
        req_entry, req_msg, req_id = self._make_request_entry(ident)
        approver = generate_identity()
        app_entry, _ = self._make_approval_entry(approver, req_msg)
        requests, approvals, executed = _scan_gate_history([req_entry, app_entry])
        assert req_id in approvals
        assert len(approvals[req_id]) == 1

    def test_marks_executed(self):
        from qntm.cli import _scan_gate_history
        ident = generate_identity()
        req_entry, req_msg, req_id = self._make_request_entry(ident)
        exec_entry = self._make_executed_entry(req_msg)
        requests, approvals, executed = _scan_gate_history([req_entry, exec_entry])
        assert req_id in executed

    def test_ignores_non_gate_messages(self):
        from qntm.cli import _scan_gate_history
        entries = [
            {"msg_id": "abc", "body_type": "text", "unsafe_body": "hello"},
        ]
        requests, approvals, executed = _scan_gate_history(entries)
        assert len(requests) == 0
        assert len(approvals) == 0
        assert len(executed) == 0


# ---------------------------------------------------------------------------
# Test: build_promote_payload
# ---------------------------------------------------------------------------

class TestBuildPromotePayload:
    def test_builds_payload(self):
        from qntm.cli import _build_promote_payload
        ident = generate_identity()
        payload = _build_promote_payload(
            identity=ident, conv_id_hex="abc123", gateway_kid="gw-kid-1", threshold=2,
        )
        assert payload["conv_id"] == "abc123"
        assert payload["gateway_kid"] == "gw-kid-1"
        assert base64url_encode(ident["keyID"]) in payload["participants"]
        assert payload["rules"][0]["m"] == 2
        assert payload["rules"][0]["service"] == "*"
        assert payload["floor"] == 2

    def test_threshold_minimum(self):
        from qntm.cli import _build_promote_payload
        ident = generate_identity()
        with pytest.raises(ValueError, match="threshold must be at least 1"):
            _build_promote_payload(identity=ident, conv_id_hex="abc123", gateway_kid="gw-kid-1", threshold=0)



# ---------------------------------------------------------------------------
# Test: build_secret_payload
# ---------------------------------------------------------------------------

class TestBuildSecretPayload:
    def test_builds_and_encrypts(self):
        from qntm.cli import _build_secret_payload
        sender = generate_identity()
        gateway = generate_identity()
        payload = _build_secret_payload(
            identity=sender,
            gateway_pubkey_wire=base64url_encode(gateway["publicKey"]),
            service="stripe",
            value="sk_test_123",
            header_name="Authorization",
            header_template="Bearer {value}",
        )
        assert payload["service"] == "stripe"
        assert payload["header_name"] == "Authorization"
        assert payload["header_template"] == "Bearer {value}"
        assert payload["sender_kid"] == base64url_encode(sender["keyID"])
        assert "encrypted_blob" in payload
        assert "secret_id" in payload

        # Verify we can decrypt
        ct = base64url_decode(payload["encrypted_blob"])
        plaintext = open_secret(gateway["privateKey"], sender["publicKey"], ct)
        assert plaintext == b"sk_test_123"

    def test_invalid_gateway_pubkey(self):
        from qntm.cli import _build_secret_payload
        sender = generate_identity()
        with pytest.raises(ValueError, match="32 bytes"):
            _build_secret_payload(
                identity=sender,
                gateway_pubkey_wire=base64url_encode(b"short"),
                service="stripe",
                value="sk_test_123",
            )


# ---------------------------------------------------------------------------
# Test: find_gate_request_in_history
# ---------------------------------------------------------------------------

class TestFindGateRequest:
    def test_finds_request(self):
        from qntm.cli import _build_gate_request_message, _find_gate_request_in_history
        ident = generate_identity()
        recipe = Recipe(
            name="jokes.dad", description="", service="dadjokes",
            verb="GET", endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read", threshold=1,
        )
        msg, request_id = _build_gate_request_message(
            identity=ident, recipe=recipe, conv_id="test-conv-id", args=None,
        )
        history = [{
            "msg_id": "abc",
            "body_type": GATE_MESSAGE_REQUEST,
            "unsafe_body": json.dumps(msg),
        }]
        found = _find_gate_request_in_history(history, request_id)
        assert found is not None
        assert found["request_id"] == request_id

    def test_not_found_raises(self):
        from qntm.cli import _find_gate_request_in_history
        with pytest.raises(ValueError, match="not found"):
            _find_gate_request_in_history([], "nonexistent-id")
