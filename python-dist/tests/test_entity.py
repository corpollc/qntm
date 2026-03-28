"""Tests for entity verification module."""

import json
import http.server
import threading
import pytest

from qntm.entity import (
    EntityVerification,
    EntityVerificationError,
    verify_entity,
    verify_sender_entity,
)
from qntm.identity import generate_identity, key_id_from_public_key


# ── Mock Corpo API ──────────────────────────────────────────────────

TEST_ENTITY = {
    "entity_id": "test-entity",
    "name": "Test Verification DAO LLC",
    "status": "active",
    "entity_type": "wyoming_dao_llc",
    "authority_ceiling": ["hold_assets"],
    "verified_at": "2026-03-23T08:26:05Z",
}

SUSPENDED_ENTITY = {
    "entity_id": "suspended-entity",
    "name": "Suspended Corp",
    "status": "suspended",
    "entity_type": "wyoming_dao_llc",
    "authority_ceiling": [],
    "verified_at": "2026-01-01T00:00:00Z",
}


class MockCorpoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/entities/test-entity/" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(TEST_ENTITY).encode())
        elif "/entities/suspended-entity/" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(SUSPENDED_ENTITY).encode())
        elif "/entities/dissolved-entity/" in self.path:
            self.send_response(410)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logs during tests


@pytest.fixture(scope="module")
def mock_api():
    """Start a mock Corpo API server."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockCorpoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/api/v1"
    server.shutdown()


# ── Tests ───────────────────────────────────────────────────────────


def test_verify_entity_active(mock_api):
    result = verify_entity("test-entity", api_base=mock_api)
    assert isinstance(result, EntityVerification)
    assert result.entity_id == "test-entity"
    assert result.name == "Test Verification DAO LLC"
    assert result.status == "active"
    assert result.is_active is True
    assert result.verified is True
    assert result.entity_type == "wyoming_dao_llc"
    assert "hold_assets" in result.authority_ceiling


def test_verify_entity_suspended(mock_api):
    result = verify_entity("suspended-entity", api_base=mock_api)
    assert result.status == "suspended"
    assert result.is_active is False
    assert result.verified is False


def test_verify_entity_not_found(mock_api):
    with pytest.raises(EntityVerificationError, match="not found"):
        verify_entity("nonexistent", api_base=mock_api)


def test_verify_entity_dissolved(mock_api):
    with pytest.raises(EntityVerificationError, match="dissolved"):
        verify_entity("dissolved-entity", api_base=mock_api)


def test_verify_sender_entity_full_chain(mock_api):
    """Full chain: DID → key → sender match → entity."""
    identity = generate_identity()

    def mock_resolve(did_uri):
        assert did_uri == "did:test:abc"
        return identity["publicKey"]

    verified, entity = verify_sender_entity(
        sender_key_id=identity["keyID"],
        did="did:test:abc",
        entity_id="test-entity",
        resolve_did_fn=mock_resolve,
        api_base=mock_api,
    )
    assert verified is True
    assert entity is not None
    assert entity.entity_id == "test-entity"


def test_verify_sender_entity_key_mismatch(mock_api):
    """DID resolves to wrong key → rejected."""
    identity = generate_identity()
    other_identity = generate_identity()

    def mock_resolve(did_uri):
        return other_identity["publicKey"]  # Wrong key!

    verified, entity = verify_sender_entity(
        sender_key_id=identity["keyID"],
        did="did:test:wrong",
        entity_id="test-entity",
        resolve_did_fn=mock_resolve,
        api_base=mock_api,
    )
    assert verified is False
    assert entity is None


def test_verify_sender_entity_no_did(mock_api):
    """No DID → entity-only verification."""
    identity = generate_identity()

    verified, entity = verify_sender_entity(
        sender_key_id=identity["keyID"],
        did=None,
        entity_id="test-entity",
        api_base=mock_api,
    )
    assert verified is True
    assert entity is not None


def test_verify_sender_entity_suspended(mock_api):
    """Suspended entity → not verified."""
    identity = generate_identity()

    verified, entity = verify_sender_entity(
        sender_key_id=identity["keyID"],
        did=None,
        entity_id="suspended-entity",
        api_base=mock_api,
    )
    assert verified is False
    assert entity is not None
    assert entity.status == "suspended"
