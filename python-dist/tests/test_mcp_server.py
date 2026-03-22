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
