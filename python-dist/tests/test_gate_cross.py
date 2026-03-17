"""Cross-client gate signing vectors -- verifies Python / TypeScript compatibility.

Updated for the conversation-scoped schema (conv_id replaces org_id,
eligible_signer_kids and required_approvals added to signable).
"""

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

# Derive the same keypair as TS
_sk = Ed25519PrivateKey.from_private_bytes(SEED)
_pk_bytes = _sk.public_key().public_bytes_raw()
_sk_bytes = SEED + _pk_bytes  # 64-byte Ed25519 private key format

# Expected values from TypeScript reference implementation
EXPECTED_KID = "ZbYGc9btiEvwHCwiLYKtoA"
EXPECTED_PAYLOAD_HASH = "4d4bbe59c6aad22442cde199a6a8a5f034405fcd78fb5a81c24ef249de1c45f1"
EXPECTED_REQUEST_HASH = "29c92653c04007fbabf1feae1e42ba3a16a00bc3e83d099763bfe60d5c85e94c"
EXPECTED_REQUEST_SIG = "ed6474e054e9b30a51c0c672f51bbb068251ef70bfdf87bd1b09757eaf3cabe3100de97271ae9bc9b71b0043ebf03af1088f36bb2c6402a705c5f0a5bbb31803"
EXPECTED_APPROVAL_SIG = "ad0a0eb3fb501b9c3c33996ce9eba67a28a581f41af1f57ca0f37777f200569105f0f0598c76f77ede439f9c9252df592e347a2301e25da90d4d2b951ee15005"

SIGNABLE_KWARGS = {
    "conv_id": "test-conv",
    "request_id": "req-001",
    "verb": "POST",
    "target_endpoint": "/v1/transfers",
    "target_service": "bank-api",
    "target_url": "https://api.bank.test/v1/transfers",
    "expires_at_unix": 1700000000,
    "payload_hash": bytes.fromhex(EXPECTED_PAYLOAD_HASH),
    "eligible_signer_kids": [EXPECTED_KID],
    "required_approvals": 1,
}


class TestCrossClientGate:
    def test_kid_matches(self):
        kid = key_id_from_public_key(_pk_bytes)
        assert key_id_to_string(kid) == EXPECTED_KID

    def test_payload_hash_matches(self):
        # TS uses computePayloadHash(Buffer.from('{"amount":100}'))
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
            conv_id="test-conv",
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
            conv_id="test-conv",
            request_id="req-001",
            request_hash=req_hash,
        )
