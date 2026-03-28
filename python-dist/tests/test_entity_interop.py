"""Cross-implementation acceptance tests for entity verification.

Tests the AgentID resolve_did → qntm verify_sender_entity integration pattern.
This is the exact bridge haroldmalikfrimpong-ops described on APS#5:

    from agentid.did import resolve_did
    verified, entity = verify_sender_entity(
        sender_key_id=envelope["sender"],
        did=envelope.get("did"),
        entity_id="test-entity",
        resolve_did_fn=resolve_did,  # AgentID's multi-method resolver
    )

Since we can't import agentid here, we mock the resolver to prove the
interface contract works for both did:agentid and did:aps methods.
"""

import json
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import MagicMock

from qntm.entity import verify_sender_entity, EntityVerification
from qntm.identity import key_id_from_public_key

# Known test keys from specs/test-vectors/
# These are the same Ed25519→X25519 vectors the WG uses
TEST_ED25519_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7e8c6f0a5b5"  # vector 1
)


class MockCorpoHandler(BaseHTTPRequestHandler):
    """Mock Corpo staging API for entity verification."""

    def log_message(self, *args):
        pass  # suppress logs

    def do_GET(self):
        if "/entities/test-entity/verify" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "entity_id": "test-entity",
                        "name": "Test Verification DAO LLC",
                        "status": "active",
                        "entity_type": "Wyoming DAO LLC",
                        "authority_ceiling": ["messaging", "signing"],
                        "verified_at": "2026-03-23T00:00:00Z",
                    }
                ).encode()
            )
        elif "/entities/revoked-entity/verify" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "entity_id": "revoked-entity",
                        "name": "Revoked Corp",
                        "status": "suspended",
                        "entity_type": "Delaware C-Corp",
                        "authority_ceiling": [],
                        "verified_at": "2026-03-23T00:00:00Z",
                    }
                ).encode()
            )
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}')


class TestEntityInterop(unittest.TestCase):
    """Tests the cross-implementation entity verification interface."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockCorpoHandler)
        cls.port = cls.server.server_address[1]
        cls.api_base = f"http://127.0.0.1:{cls.port}/api/v1"
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_agentid_resolver_pattern(self):
        """Prove AgentID's resolve_did plugs into verify_sender_entity.

        This is the exact pattern haroldmalikfrimpong-ops described:
        AgentID's resolve_did() returns a 32-byte Ed25519 public key,
        and qntm's verify_sender_entity() uses it to match sender_key_id.
        """
        # Mock AgentID's multi-method resolver
        def mock_resolve_did(did_uri: str) -> bytes:
            """Simulates agentid.did.resolve_did for did:agentid method."""
            if did_uri.startswith("did:agentid:"):
                return TEST_ED25519_PUBLIC_KEY
            raise ValueError(f"Unknown DID method: {did_uri}")

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:agentid:z6QQ5asBUnXiM4JsgfnG36",
            entity_id="test-entity",
            resolve_did_fn=mock_resolve_did,
            api_base=self.api_base,
        )

        self.assertTrue(verified)
        self.assertIsNotNone(entity)
        self.assertEqual(entity.name, "Test Verification DAO LLC")
        self.assertTrue(entity.is_active)

    def test_aps_resolver_pattern(self):
        """Prove APS's resolve_did plugs into verify_sender_entity.

        Same interface, different DID method (did:aps).
        """

        def mock_resolve_did(did_uri: str) -> bytes:
            """Simulates aeoess's APS resolver for did:aps method."""
            if did_uri.startswith("did:aps:"):
                return TEST_ED25519_PUBLIC_KEY
            raise ValueError(f"Unknown DID method: {did_uri}")

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:aps:tima-founder-agent",
            entity_id="test-entity",
            resolve_did_fn=mock_resolve_did,
            api_base=self.api_base,
        )

        self.assertTrue(verified)
        self.assertIsNotNone(entity)

    def test_aip_resolver_pattern(self):
        """Prove AIP's resolve_did could plug into verify_sender_entity.

        The-Nexus-Guard's AIP uses the same Ed25519 identity layer.
        """

        def mock_resolve_did(did_uri: str) -> bytes:
            """Simulates AIP resolver for did:aip method."""
            if did_uri.startswith("did:aip:"):
                return TEST_ED25519_PUBLIC_KEY
            raise ValueError(f"Unknown DID method: {did_uri}")

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:aip:c1965a89866ecbfaad49",
            entity_id="test-entity",
            resolve_did_fn=mock_resolve_did,
            api_base=self.api_base,
        )

        self.assertTrue(verified)
        self.assertIsNotNone(entity)

    def test_multi_method_resolver(self):
        """Prove a resolver handling multiple DID methods works.

        This is the AgentID pattern: one resolve_did() that handles
        did:agentid, did:aps, and did:aip by dispatching to the
        appropriate backend.
        """

        def multi_resolve_did(did_uri: str) -> bytes:
            """Multi-method resolver a la AgentID's resolve_did()."""
            for prefix in ("did:agentid:", "did:aps:", "did:aip:"):
                if did_uri.startswith(prefix):
                    return TEST_ED25519_PUBLIC_KEY
            raise ValueError(f"Unsupported DID method: {did_uri}")

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        # All three methods should work through the same interface
        for did in [
            "did:agentid:z6QQ5asBUnXiM4JsgfnG36",
            "did:aps:tima-founder-agent",
            "did:aip:c1965a89866ecbfaad49",
        ]:
            with self.subTest(did=did):
                verified, entity = verify_sender_entity(
                    sender_key_id=sender_key_id,
                    did=did,
                    entity_id="test-entity",
                    resolve_did_fn=multi_resolve_did,
                    api_base=self.api_base,
                )
                self.assertTrue(verified, f"Failed for {did}")

    def test_key_mismatch_rejects(self):
        """If the resolved DID key doesn't match sender_key_id, reject."""
        wrong_key = bytes(32)  # all zeros — doesn't match test key

        def mock_resolve_did(did_uri: str) -> bytes:
            return wrong_key

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:agentid:wrong-key-agent",
            entity_id="test-entity",
            resolve_did_fn=mock_resolve_did,
            api_base=self.api_base,
        )

        self.assertFalse(verified)
        self.assertIsNone(entity)

    def test_entity_suspended_rejects(self):
        """Active DID + suspended entity = not verified."""

        def mock_resolve_did(did_uri: str) -> bytes:
            return TEST_ED25519_PUBLIC_KEY

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:agentid:suspended-agent",
            entity_id="revoked-entity",
            resolve_did_fn=mock_resolve_did,
            api_base=self.api_base,
        )

        self.assertFalse(verified)
        self.assertIsNotNone(entity)  # entity returned even if suspended
        self.assertEqual(entity.status, "suspended")

    def test_resolver_failure_rejects(self):
        """If the DID resolver throws, reject gracefully."""

        def failing_resolve_did(did_uri: str) -> bytes:
            raise ConnectionError("DID resolution service unavailable")

        sender_key_id = key_id_from_public_key(TEST_ED25519_PUBLIC_KEY)

        verified, entity = verify_sender_entity(
            sender_key_id=sender_key_id,
            did="did:agentid:unreachable-agent",
            entity_id="test-entity",
            resolve_did_fn=failing_resolve_did,
            api_base=self.api_base,
        )

        self.assertFalse(verified)
        self.assertIsNone(entity)

    def test_no_did_entity_only(self):
        """No DID provided — entity-only verification (backwards compatible)."""
        verified, entity = verify_sender_entity(
            sender_key_id=b"\x00" * 16,  # any key ID
            did=None,
            entity_id="test-entity",
            resolve_did_fn=None,
            api_base=self.api_base,
        )

        self.assertTrue(verified)
        self.assertIsNotNone(entity)
        self.assertEqual(entity.name, "Test Verification DAO LLC")


if __name__ == "__main__":
    unittest.main()
