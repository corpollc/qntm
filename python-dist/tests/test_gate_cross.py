"""Cross-client gate signing vectors — verifies Python ↔ Go compatibility."""

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qntm.gate import (
    compute_payload_hash,
    hash_request,
    sign_approval,
    sign_request,
    verify_approval,
    verify_request,
)
from qntm.identity import key_id_to_string, key_id_from_public_key

# Deterministic seed shared across all clients
SEED = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)

# Derive the same keypair as Go/TS
_sk = Ed25519PrivateKey.from_private_bytes(SEED)
_pk_bytes = _sk.public_key().public_bytes_raw()
_sk_bytes = SEED + _pk_bytes  # 64-byte Ed25519 private key format

# Expected values from Go reference implementation
EXPECTED_KID = "ZbYGc9btiEvwHCwiLYKtoA"
EXPECTED_PAYLOAD_HASH = "4d4bbe59c6aad22442cde199a6a8a5f034405fcd78fb5a81c24ef249de1c45f1"
EXPECTED_REQUEST_HASH = "b614fd216523ebf55838ecef7acfa6206afef8b1c92dd69eeeb8713728888633"
EXPECTED_REQUEST_SIG = "bfbda1ca7cb496efe9c6f252994f47812cc8e7172371d47a96fd5ba0c433c3e23378e9321e1117de95f1db353cf6074fc75dc6126c38f7332dab208ad52bd80d"
EXPECTED_APPROVAL_SIG = "3e05276b4635d562f14bbea45041ee17ab116c992ec3ea2780ecf987c97c0ebec28d20714aba1d8c44a554aa796bff2cbe8ac33d6c7baafecf06e9138d49290b"

SIGNABLE_KWARGS = {
    "org_id": "test-org",
    "request_id": "req-001",
    "verb": "POST",
    "target_endpoint": "/v1/transfers",
    "target_service": "bank-api",
    "target_url": "https://api.bank.test/v1/transfers",
    "expires_at_unix": 1700000000,
    "payload_hash": bytes.fromhex(EXPECTED_PAYLOAD_HASH),
}


class TestCrossClientGate:
    def test_kid_matches(self):
        kid = key_id_from_public_key(_pk_bytes)
        assert key_id_to_string(kid) == EXPECTED_KID

    def test_payload_hash_matches(self):
        # Go uses ComputePayloadHash([]byte(`{"amount":100}`))
        # which is SHA-256 of the raw JSON bytes
        h = hashlib.sha256(b'{"amount":100}').digest()
        assert h.hex() == EXPECTED_PAYLOAD_HASH

    def test_request_hash_matches(self):
        h = hash_request(**SIGNABLE_KWARGS)
        assert h.hex() == EXPECTED_REQUEST_HASH

    def test_request_signature_matches(self):
        sig = sign_request(_sk_bytes, **SIGNABLE_KWARGS)
        assert sig.hex() == EXPECTED_REQUEST_SIG

    def test_request_signature_verifies(self):
        sig = bytes.fromhex(EXPECTED_REQUEST_SIG)
        assert verify_request(_pk_bytes, sig, **SIGNABLE_KWARGS)

    def test_approval_signature_matches(self):
        req_hash = bytes.fromhex(EXPECTED_REQUEST_HASH)
        sig = sign_approval(
            _sk_bytes,
            org_id="test-org",
            request_id="req-001",
            request_hash=req_hash,
        )
        assert sig.hex() == EXPECTED_APPROVAL_SIG

    def test_approval_signature_verifies(self):
        req_hash = bytes.fromhex(EXPECTED_REQUEST_HASH)
        sig = bytes.fromhex(EXPECTED_APPROVAL_SIG)
        assert verify_approval(
            _pk_bytes,
            sig,
            org_id="test-org",
            request_id="req-001",
            request_hash=req_hash,
        )
