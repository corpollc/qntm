"""Tests for the qntm MCP server."""

import json
import os
import tempfile

import pytest


def _skip_if_no_mcp():
    """Skip test if MCP SDK is not installed."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("mcp package not installed (install with: pip install 'qntm[mcp]')")


class TestMCPServer:
    """Test MCP server tool functions directly."""

    def setup_method(self):
        _skip_if_no_mcp()
        self.tmpdir = tempfile.mkdtemp(prefix="qntm-mcp-test-")
        os.environ["QNTM_CONFIG_DIR"] = self.tmpdir
        os.environ["QNTM_RELAY_URL"] = "https://inbox.qntm.corpo.llc"

    def teardown_method(self):
        os.environ.pop("QNTM_CONFIG_DIR", None)
        os.environ.pop("QNTM_RELAY_URL", None)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_import(self):
        """MCP server module imports successfully."""
        from qntm.mcp_server import mcp
        assert mcp is not None

    def test_tools_registered(self):
        """All expected tools are registered."""
        from qntm.mcp_server import mcp
        tools = mcp._tool_manager._tools
        expected = {
            "identity_generate",
            "identity_show",
            "conversation_list",
            "conversation_create",
            "conversation_join",
            "send_message",
            "receive_messages",
            "conversation_history",
            "protocol_info",
        }
        assert expected.issubset(set(tools.keys()))

    def test_identity_generate(self):
        """identity_generate creates a new identity."""
        from qntm.mcp_server import identity_generate
        result = identity_generate()
        assert result["status"] == "created"
        assert "key_id" in result
        assert "public_key" in result
        assert len(result["key_id"]) > 0  # non-empty key ID

    def test_identity_generate_idempotent(self):
        """identity_generate returns existing identity if one exists."""
        from qntm.mcp_server import identity_generate
        first = identity_generate()
        second = identity_generate()
        assert first["key_id"] == second["key_id"]
        assert second["status"] == "exists"

    def test_identity_show_no_identity(self):
        """identity_show returns error when no identity exists."""
        from qntm.mcp_server import identity_show
        result = identity_show()
        assert "error" in result

    def test_identity_show_with_identity(self):
        """identity_show returns identity after generation."""
        from qntm.mcp_server import identity_generate, identity_show
        gen = identity_generate()
        show = identity_show()
        assert show["key_id"] == gen["key_id"]

    def test_conversation_list_empty(self):
        """conversation_list returns empty list with no conversations."""
        from qntm.mcp_server import conversation_list
        result = conversation_list()
        assert result == []

    def test_protocol_info(self):
        """protocol_info returns correct protocol information."""
        from qntm.mcp_server import protocol_info
        result = protocol_info()
        assert result["protocol"] == "QSP v1.1 (qntm Secure Protocol)"
        assert "X25519" in result["encryption"]["key_agreement"]
        assert "XChaCha20" in result["encryption"]["cipher"]
        assert "Ed25519" in result["encryption"]["signatures"]
        assert "corpollc/qntm" in result["docs"]

    def test_send_message_no_identity(self):
        """send_message returns error when no identity exists."""
        from qntm.mcp_server import send_message
        result = send_message("abc123", "hello")
        assert "error" in result

    def test_receive_messages_no_identity(self):
        """receive_messages returns error when no identity exists."""
        from qntm.mcp_server import receive_messages
        result = receive_messages("abc123")
        assert "error" in result

    def test_conversation_create_no_identity(self):
        """conversation_create returns error when no identity exists."""
        from qntm.mcp_server import conversation_create
        result = conversation_create()
        assert "error" in result

    def test_conversation_join_no_identity(self):
        """conversation_join returns error when no identity exists."""
        from qntm.mcp_server import conversation_join
        result = conversation_join("fake-token")
        assert "error" in result

    def test_resource_identity(self):
        """Identity resource returns correct data."""
        from qntm.mcp_server import resource_identity, identity_generate
        # Before identity
        data = json.loads(resource_identity())
        assert data["status"] == "no identity"

        # After identity
        identity_generate()
        data = json.loads(resource_identity())
        assert "key_id" in data

    def test_resource_conversations(self):
        """Conversations resource returns correct data."""
        from qntm.mcp_server import resource_conversations
        data = json.loads(resource_conversations())
        assert isinstance(data, list)
        assert len(data) == 0

    def test_conversation_join_persists_inviter_and_participant_keys_and_supports_v1_2_groups(self):
        """MCP conversation_join achieves parity with CLI for both v1.0 and v1.2 group invites."""
        import shutil
        from qntm import cli
        from qntm.group import GroupState, create_group_genesis_body, parse_group_genesis_body, create_rekey, apply_rekey
        from qntm.group_bootstrap import create_current_epoch_invite
        from qntm.group_session import crypto, save_crypto, save_state
        from qntm.identity import generate_identity
        from qntm.invite import create_invite, create_conversation, derive_conversation_keys
        from qntm.message import create_message
        from qntm.mcp_server import identity_generate, conversation_create, conversation_join

        inviter_dir = tempfile.mkdtemp(prefix="qntm-mcp-inviter-")
        try:
            os.environ["QNTM_CONFIG_DIR"] = inviter_dir
            inviter_info = identity_generate()
            created = conversation_create("Pair Chat")

            os.environ["QNTM_CONFIG_DIR"] = self.tmpdir
            joiner_info = identity_generate()
            joined = conversation_join(created["invite_token"], "Pair Chat")
            assert joined["status"] == "joined"

            convs = cli._load_conversations(self.tmpdir)
            assert len(convs) == 1
            assert convs[0]["inviter_key_id"] == inviter_info["key_id"]
            assert convs[0]["inviter_public_key"] == inviter_info["public_key"]
            learned = cli._load_participant_public_keys(self.tmpdir, created["conversation_id"])
            assert set(learned.keys()) == {inviter_info["key_id"], joiner_info["key_id"]}

            # Now test v1.2 sealed current-epoch group invite
            owner = generate_identity()
            joiner_identity = cli._load_identity(self.tmpdir)
            g_inv = create_invite(owner, "group")
            g_conv = create_conversation(g_inv, derive_conversation_keys(g_inv))
            state = GroupState()
            state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("Ops Group", "", owner, [joiner_identity["publicKey"]])))
            rekey_body, new_root = create_rekey(owner, g_conv, state, g_conv["id"])
            rekey_env = create_message(owner, g_conv, "group_rekey", rekey_body)
            apply_rekey(g_conv, new_root, 1)
            g_record = {"id": g_conv["id"].hex(), "type": "group", "name": "Ops Group"}
            save_crypto(g_record, g_conv)
            save_state(g_record, state)

            v12_token = create_current_epoch_invite(
                owner,
                crypto(g_record),
                state,
                joiner_identity["publicKey"],
                rekey_env["msg_id"],
            )
            joined_group = conversation_join(v12_token, "Ops Group")
            assert joined_group["status"] == "joined"
            assert joined_group["type"] == "group"
            assert joined_group["epoch"] == 1
            assert joined_group["participants"] == 2
            group_learned = cli._load_participant_public_keys(self.tmpdir, g_record["id"])
            assert set(group_learned.keys()) == {owner["keyID"].hex(), joiner_identity["keyID"].hex()}
        finally:
            os.environ["QNTM_CONFIG_DIR"] = self.tmpdir
            shutil.rmtree(inviter_dir, ignore_errors=True)

    def test_send_and_guidance_send_handle_delivery_unknown_gracefully(self, monkeypatch):
        """MCP send_message and guidance_send catch SendDeliveryUnknown and record unknown delivery."""
        from qntm import cli
        from qntm.guidance import pin_contact, prepare_request
        from qntm.identity import generate_identity
        from qntm.mcp_server import identity_generate, conversation_create, send_message, guidance_send

        identity_generate()
        created = conversation_create("Ambiguous Relay")
        cid = created["conversation_id"]
        peer = generate_identity()
        convs = cli._load_conversations(self.tmpdir)
        convs[0]["participants"].append(peer["keyID"].hex())
        cli._save_conversations(self.tmpdir, convs)

        def raise_unknown(relay_url, conv_id_hex, envelope_bytes, **kw):
            raise cli.SendDeliveryUnknown(conv_id_hex, "de" * 16, TimeoutError("ack lost"))

        monkeypatch.setattr("qntm.mcp_server._http_send", raise_unknown)
        monkeypatch.setattr("qntm.cli._http_send", raise_unknown)

        res = send_message(cid, "hello relay")
        assert res["status"] == "delivery_unknown"
        assert res["delivery"] == "unknown"
        assert res["conversation_id"] == cid
        assert cli._load_history(self.tmpdir, cid)[-1]["delivery"] == "unknown"

        pin_contact(self.tmpdir, "https://inbox.qntm.corpo.llc", "counsel", "legal", "Counsel", "human", cid, peer["keyID"].hex())
        draft = prepare_request(self.tmpdir, "https://inbox.qntm.corpo.llc", "counsel", "Proceed?")
        gres = guidance_send("counsel", "Proceed?", draft["review_token"])
        assert gres["status"] == "delivery_unknown"
        assert gres["delivery"] == "unknown"
        assert gres["conversation_id"] == cid
