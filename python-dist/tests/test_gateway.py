"""Tests for the gateway module: init, state management, message routing."""

import base64
import json
import os
import tempfile

import pytest

from qntm.gate import (
    GATE_MESSAGE_APPROVAL,
    GATE_MESSAGE_CONFIG,
    GATE_MESSAGE_PROMOTE,
    GATE_MESSAGE_REQUEST,
    GATE_MESSAGE_SECRET,
    ThresholdRule,
    compute_payload_hash,
    hash_request,
    seal_secret,
    sign_approval,
    sign_request,
)
from qntm.identity import (
    base64url_encode,
    generate_identity,
    key_id_to_string,
)
from qntm.gateway import (
    ConversationGateState,
    Gateway,
    init_gateway,
)


# ---------------------------------------------------------------------------
# Gateway init
# ---------------------------------------------------------------------------


class TestGatewayInit:
    def test_init_creates_identity_and_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            result = init_gateway(config_dir)

            # Identity file created
            assert os.path.isfile(os.path.join(config_dir, "identity.json"))
            # Conversations file created
            assert os.path.isfile(os.path.join(config_dir, "conversations.json"))
            # Vault directory created
            assert os.path.isdir(os.path.join(config_dir, "vault"))

            # Result has expected fields
            assert result["key_id"]
            assert result["public_key"]
            assert result["config_dir"] == config_dir
            assert result["vault_dir"] == os.path.join(config_dir, "vault")
            assert result["identity_path"] == os.path.join(config_dir, "identity.json")

    def test_init_fails_if_identity_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)

            with pytest.raises(FileExistsError):
                init_gateway(config_dir)

    def test_init_force_overwrites(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            result1 = init_gateway(config_dir)
            result2 = init_gateway(config_dir, force=True)

            # New identity generated
            assert result1["key_id"] != result2["key_id"]

    def test_init_identity_is_valid(self):
        """The generated identity should be loadable by the Gateway."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)

            gw = Gateway(config_dir)
            identity = gw.load_identity()
            assert identity is not None
            assert len(identity["privateKey"]) == 64
            assert len(identity["publicKey"]) == 32
            assert len(identity["keyID"]) > 0

    def test_init_conversations_file_is_empty_array(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)

            with open(os.path.join(config_dir, "conversations.json")) as f:
                data = json.load(f)
            assert data == []


# ---------------------------------------------------------------------------
# Gateway state management
# ---------------------------------------------------------------------------


def _make_conv_id():
    return os.urandom(16)


class TestGatewayState:
    def test_handle_promote(self):
        """Processing a gate.promote message should register conversation state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer = generate_identity()
            promote_payload = {
                "org_id": "test-org",
                "signers": [
                    {
                        "kid": signer["keyID"].hex(),
                        "public_key": base64url_encode(signer["publicKey"]),
                        "label": "alice",
                    }
                ],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            }

            gw.handle_promote(conv_id, promote_payload)

            state = gw.get_conversation_state(conv_id)
            assert state is not None
            assert state.org_id == "test-org"
            assert len(state.rules) == 1
            assert state.rules[0].m == 1
            assert signer["keyID"].hex() in state.participants

    def test_handle_config_updates_rules(self):
        """Processing a gate.config message should replace rules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer = generate_identity()

            # First promote
            gw.handle_promote(conv_id, {
                "org_id": "test-org",
                "signers": [{
                    "kid": signer["keyID"].hex(),
                    "public_key": base64url_encode(signer["publicKey"]),
                    "label": "alice",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            })

            # Then update config
            new_rules = [
                {"service": "bank-api", "endpoint": "*", "verb": "*", "m": 2, "n": 3}
            ]
            gw.handle_config(conv_id, {"rules": new_rules})

            state = gw.get_conversation_state(conv_id)
            assert len(state.rules) == 1
            assert state.rules[0].service == "bank-api"
            assert state.rules[0].m == 2

    def test_handle_config_without_promote_raises(self):
        """Config for non-promoted conversation should raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            with pytest.raises(ValueError, match="non-promoted"):
                gw.handle_config(conv_id, {"rules": []})

    def test_handle_secret(self):
        """Processing a gate.secret should store decrypted credential."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            identity = gw.load_identity()

            conv_id = _make_conv_id()
            sender = generate_identity()

            # Promote first
            gw.handle_promote(conv_id, {
                "org_id": "test-org",
                "signers": [{
                    "kid": sender["keyID"].hex(),
                    "public_key": base64url_encode(sender["publicKey"]),
                    "label": "alice",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            })

            # Seal a secret to the gateway's public key
            secret_value = b"sk-test-secret-key-12345"
            encrypted = seal_secret(
                sender["privateKey"],
                identity["publicKey"],
                secret_value,
            )

            secret_payload = {
                "secret_id": "cred-1",
                "service": "bank-api",
                "header_name": "Authorization",
                "header_template": "Bearer {value}",
                "encrypted_blob": base64.b64encode(encrypted).decode(),
                "sender_kid": sender["keyID"].hex(),
            }

            gw.handle_secret(conv_id, secret_payload)

            state = gw.get_conversation_state(conv_id)
            assert "bank-api" in state.credentials
            cred = state.credentials["bank-api"]
            assert cred["service"] == "bank-api"
            assert cred["header_name"] == "Authorization"
            # The decrypted value should be the original secret
            assert cred["value"] == secret_value.decode()

    def test_handle_promote_rejects_non_canonical_public_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            sender = generate_identity()

            with pytest.raises(ValueError, match="signer public key"):
                gw.handle_promote(conv_id, {
                    "org_id": "test-org",
                    "signers": [{
                        "kid": sender["keyID"].hex(),
                        "public_key": base64.b64encode(sender["publicKey"]).decode(),
                        "label": "alice",
                    }],
                    "rules": [
                        {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                    ],
                })

    def test_handle_secret_rejects_non_canonical_encodings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            identity = gw.load_identity()

            conv_id = _make_conv_id()
            sender = generate_identity()

            gw.handle_promote(conv_id, {
                "org_id": "test-org",
                "signers": [{
                    "kid": sender["keyID"].hex(),
                    "public_key": base64url_encode(sender["publicKey"]),
                    "label": "alice",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            })

            encrypted = seal_secret(
                sender["privateKey"],
                identity["publicKey"],
                b"legacy-secret",
            )

            with pytest.raises(ValueError, match="standard base64 encoding, not hex"):
                gw.handle_secret(conv_id, {
                    "secret_id": "cred-legacy-hex",
                    "service": "legacy-api",
                    "header_name": "Authorization",
                    "header_template": "Bearer {value}",
                    "encrypted_blob": encrypted.hex(),
                    "sender_kid": sender["keyID"].hex(),
                })

            with pytest.raises(ValueError, match="invalid encrypted_blob encoding"):
                gw.handle_secret(conv_id, {
                    "secret_id": "cred-legacy-urlsafe",
                    "service": "legacy-api",
                    "header_name": "Authorization",
                    "header_template": "Bearer {value}",
                    "encrypted_blob": base64.urlsafe_b64encode(encrypted).decode().rstrip("="),
                    "sender_kid": sender["keyID"].hex(),
                })


# ---------------------------------------------------------------------------
# Message routing
# ---------------------------------------------------------------------------


class TestMessageRouting:
    def test_route_promote(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer = generate_identity()

            body = json.dumps({
                "org_id": "test-org",
                "signers": [{
                    "kid": signer["keyID"].hex(),
                    "public_key": base64url_encode(signer["publicKey"]),
                    "label": "bob",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            }).encode()

            gw.process_message(conv_id, GATE_MESSAGE_PROMOTE, body)

            state = gw.get_conversation_state(conv_id)
            assert state is not None
            assert state.org_id == "test-org"

    def test_route_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer = generate_identity()

            # Promote first
            gw.process_message(conv_id, GATE_MESSAGE_PROMOTE, json.dumps({
                "org_id": "test-org",
                "signers": [{
                    "kid": signer["keyID"].hex(),
                    "public_key": base64url_encode(signer["publicKey"]),
                    "label": "bob",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            }).encode())

            # Config update
            gw.process_message(conv_id, GATE_MESSAGE_CONFIG, json.dumps({
                "rules": [
                    {"service": "api", "endpoint": "/foo", "verb": "GET", "m": 2, "n": 3}
                ],
            }).encode())

            state = gw.get_conversation_state(conv_id)
            assert state.rules[0].service == "api"

    def test_route_unknown_type_ignored(self):
        """Unknown body types should be silently ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            # Should not raise
            gw.process_message(conv_id, "text", b"hello world")

    def test_route_request_stores_message(self):
        """gate.request should be stored in per-conversation message store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer = generate_identity()

            # Promote
            gw.handle_promote(conv_id, {
                "org_id": "test-org",
                "signers": [{
                    "kid": signer["keyID"].hex(),
                    "public_key": base64url_encode(signer["publicKey"]),
                    "label": "alice",
                }],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1}
                ],
            })

            import time
            expires_at_unix = int(time.time()) + 3600
            payload_hash = compute_payload_hash(None)

            sig = sign_request(
                signer["privateKey"],
                org_id="test-org",
                request_id="req-001",
                verb="GET",
                target_endpoint="/health",
                target_service="api",
                target_url="https://api.test/health",
                expires_at_unix=expires_at_unix,
                payload_hash=payload_hash,
            )

            request_body = json.dumps({
                "type": GATE_MESSAGE_REQUEST,
                "org_id": "test-org",
                "request_id": "req-001",
                "signer_kid": signer["keyID"].hex(),
                "signature": base64.b64encode(sig).decode(),
                "verb": "GET",
                "target_endpoint": "/health",
                "target_service": "api",
                "target_url": "https://api.test/health",
                "expires_at": str(expires_at_unix),
            }).encode()

            gw.process_message(conv_id, GATE_MESSAGE_REQUEST, request_body)

            # Should be stored
            messages = gw.get_gate_messages(conv_id)
            assert len(messages) == 1
            assert messages[0]["request_id"] == "req-001"

    def test_route_approval_stores_message(self):
        """gate.approval should be stored in per-conversation message store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "gw")
            init_gateway(config_dir)
            gw = Gateway(config_dir)
            gw.load_identity()

            conv_id = _make_conv_id()
            signer1 = generate_identity()
            signer2 = generate_identity()

            # Promote
            gw.handle_promote(conv_id, {
                "org_id": "test-org",
                "signers": [
                    {
                        "kid": signer1["keyID"].hex(),
                        "public_key": base64url_encode(signer1["publicKey"]),
                        "label": "alice",
                    },
                    {
                        "kid": signer2["keyID"].hex(),
                        "public_key": base64url_encode(signer2["publicKey"]),
                        "label": "bob",
                    },
                ],
                "rules": [
                    {"service": "*", "endpoint": "*", "verb": "*", "m": 2, "n": 2}
                ],
            })

            import time
            expires_at_unix = int(time.time()) + 3600
            payload_hash = compute_payload_hash(None)

            # Request from signer1
            sig1 = sign_request(
                signer1["privateKey"],
                org_id="test-org",
                request_id="req-002",
                verb="GET",
                target_endpoint="/health",
                target_service="api",
                target_url="https://api.test/health",
                expires_at_unix=expires_at_unix,
                payload_hash=payload_hash,
            )

            gw.process_message(conv_id, GATE_MESSAGE_REQUEST, json.dumps({
                "type": GATE_MESSAGE_REQUEST,
                "org_id": "test-org",
                "request_id": "req-002",
                "signer_kid": signer1["keyID"].hex(),
                "signature": base64.b64encode(sig1).decode(),
                "verb": "GET",
                "target_endpoint": "/health",
                "target_service": "api",
                "target_url": "https://api.test/health",
                "expires_at": str(expires_at_unix),
            }).encode())

            # Approval from signer2
            req_hash = hash_request(
                org_id="test-org",
                request_id="req-002",
                verb="GET",
                target_endpoint="/health",
                target_service="api",
                target_url="https://api.test/health",
                expires_at_unix=expires_at_unix,
                payload_hash=payload_hash,
            )

            sig2 = sign_approval(
                signer2["privateKey"],
                org_id="test-org",
                request_id="req-002",
                request_hash=req_hash,
            )

            gw.process_message(conv_id, GATE_MESSAGE_APPROVAL, json.dumps({
                "type": GATE_MESSAGE_APPROVAL,
                "org_id": "test-org",
                "request_id": "req-002",
                "signer_kid": signer2["keyID"].hex(),
                "signature": base64.b64encode(sig2).decode(),
            }).encode())

            messages = gw.get_gate_messages(conv_id)
            assert len(messages) == 2
