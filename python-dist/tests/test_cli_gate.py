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

import pytest

from qntm.identity import generate_identity, base64url_encode, key_id_to_string
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
    GATE_MESSAGE_CONFIG,
    GATE_MESSAGE_SECRET,
    PromotePayload,
    ConfigPayload,
    SecretPayload,
    ThresholdRule,
    Signer,
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
            org_id="test-org",
            args=None,
        )
        assert msg["type"] == GATE_MESSAGE_REQUEST
        assert msg["org_id"] == "test-org"
        assert msg["verb"] == "GET"
        assert msg["target_endpoint"] == "/"
        assert msg["target_service"] == "dadjokes"
        assert msg["target_url"] == "https://icanhazdadjoke.com/"
        assert msg["signer_kid"] == ident["keyID"].hex()
        assert "signature" in msg
        assert "expires_at" in msg
        assert msg["request_id"] == request_id

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
            org_id="test-org",
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
                org_id="test-org",
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
            org_id="test-org",
            args=None,
        )
        # Verify the signature
        sig = bytes.fromhex(msg["signature"])
        from datetime import datetime, timezone
        expires_dt = datetime.fromisoformat(msg["expires_at"].replace("Z", "+00:00"))
        expires_unix = int(expires_dt.timestamp())
        payload_hash = compute_payload_hash(msg.get("payload"))
        assert verify_request(
            ident["publicKey"],
            sig,
            org_id=msg["org_id"],
            request_id=msg["request_id"],
            verb=msg["verb"],
            target_endpoint=msg["target_endpoint"],
            target_service=msg["target_service"],
            target_url=msg["target_url"],
            expires_at_unix=expires_unix,
            payload_hash=payload_hash,
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
            org_id="test-org",
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
            identity=ident, recipe=recipe, org_id="test-org", args=None,
        )
        # Different identity approves
        approver = generate_identity()
        approval_msg = _build_gate_approval_message(
            identity=approver,
            request_msg=req_msg,
        )
        assert approval_msg["type"] == GATE_MESSAGE_APPROVAL
        assert approval_msg["org_id"] == "test-org"
        assert approval_msg["request_id"] == request_id
        assert approval_msg["signer_kid"] == approver["keyID"].hex()
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
            identity=ident, recipe=recipe, org_id="test-org", args=None,
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
            org_id=req_msg["org_id"],
            request_id=req_msg["request_id"],
            verb=req_msg["verb"],
            target_endpoint=req_msg["target_endpoint"],
            target_service=req_msg["target_service"],
            target_url=req_msg["target_url"],
            expires_at_unix=expires_unix,
            payload_hash=payload_hash,
        )
        sig = bytes.fromhex(approval_msg["signature"])
        assert verify_approval(
            approver["publicKey"],
            sig,
            org_id=approval_msg["org_id"],
            request_id=approval_msg["request_id"],
            request_hash=req_hash,
        )


# ---------------------------------------------------------------------------
# Test: scan_gate_history
# ---------------------------------------------------------------------------

class TestScanGateHistory:
    def _make_request_entry(self, ident, org_id="test-org"):
        from qntm.cli import _build_gate_request_message
        recipe = Recipe(
            name="jokes.dad", description="", service="dadjokes",
            verb="GET", endpoint="/",
            target_url="https://icanhazdadjoke.com/",
            risk_tier="read", threshold=1,
        )
        msg, request_id = _build_gate_request_message(
            identity=ident, recipe=recipe, org_id=org_id, args=None,
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
            "org_id": request_msg["org_id"],
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
            identity=ident, org_id="test-org", threshold=2,
        )
        assert payload["org_id"] == "test-org"
        assert len(payload["signers"]) == 1
        assert payload["signers"][0]["kid"] == ident["keyID"].hex()
        assert payload["rules"][0]["m"] == 2
        assert payload["rules"][0]["service"] == "*"

    def test_threshold_minimum(self):
        from qntm.cli import _build_promote_payload
        ident = generate_identity()
        with pytest.raises(ValueError, match="threshold must be at least 1"):
            _build_promote_payload(identity=ident, org_id="test-org", threshold=0)


# ---------------------------------------------------------------------------
# Test: build_config_payload
# ---------------------------------------------------------------------------

class TestBuildConfigPayload:
    def test_builds_payload(self):
        from qntm.cli import _build_config_payload
        payload = _build_config_payload(threshold=3)
        assert len(payload["rules"]) == 1
        assert payload["rules"][0]["m"] == 3
        assert payload["rules"][0]["service"] == "*"

    def test_threshold_minimum(self):
        from qntm.cli import _build_config_payload
        with pytest.raises(ValueError, match="threshold must be at least 1"):
            _build_config_payload(threshold=0)


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
            gateway_pubkey_hex=gateway["publicKey"].hex(),
            service="stripe",
            value="sk_test_123",
            header_name="Authorization",
            header_template="Bearer {value}",
        )
        assert payload["service"] == "stripe"
        assert payload["header_name"] == "Authorization"
        assert payload["header_template"] == "Bearer {value}"
        assert payload["sender_kid"] == sender["keyID"].hex()
        assert "encrypted_blob" in payload
        assert "secret_id" in payload

        # Verify we can decrypt
        ct = base64.b64decode(payload["encrypted_blob"])
        plaintext = open_secret(gateway["privateKey"], sender["publicKey"], ct)
        assert plaintext == b"sk_test_123"

    def test_invalid_gateway_pubkey(self):
        from qntm.cli import _build_secret_payload
        sender = generate_identity()
        with pytest.raises(ValueError, match="gateway public key"):
            _build_secret_payload(
                identity=sender,
                gateway_pubkey_hex="deadbeef",
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
            identity=ident, recipe=recipe, org_id="test-org", args=None,
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
