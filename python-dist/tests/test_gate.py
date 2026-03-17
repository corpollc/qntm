"""Tests for the gate module: signing, verification, threshold matching."""

import hashlib
import json
import time

from qntm.gate import (
    ThresholdRule,
    compute_payload_hash,
    hash_request,
    lookup_threshold,
    sign_approval,
    sign_request,
    verify_approval,
    verify_request,
)
from qntm.identity import generate_identity, key_id_to_string


def _signable_kwargs(identity, payload=None):
    """Helper to build common signable keyword args."""
    payload_hash = compute_payload_hash(payload)
    return {
        "conv_id": "test-conv-id",
        "request_id": "req-001",
        "verb": "POST",
        "target_endpoint": "/v1/transfers",
        "target_service": "bank-api",
        "target_url": "https://api.bank.test/v1/transfers",
        "expires_at_unix": int(time.time()) + 3600,
        "payload_hash": payload_hash,
        "eligible_signer_kids": [identity["keyID"].hex()],
        "required_approvals": 1,
    }


# --- Request signing ---

class TestRequestSigning:
    def test_sign_and_verify(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident)

        sig = sign_request(ident["privateKey"], **kwargs)
        assert len(sig) == 64
        assert verify_request(ident["publicKey"], sig, **kwargs)

    def test_wrong_key_rejects(self):
        ident1 = generate_identity()
        ident2 = generate_identity()
        kwargs = _signable_kwargs(ident1)

        sig = sign_request(ident1["privateKey"], **kwargs)
        assert not verify_request(ident2["publicKey"], sig, **kwargs)

    def test_tampered_field_rejects(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident)

        sig = sign_request(ident["privateKey"], **kwargs)
        kwargs["verb"] = "DELETE"
        assert not verify_request(ident["publicKey"], sig, **kwargs)

    def test_tampered_payload_hash_rejects(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident, payload={"amount": 100})

        sig = sign_request(ident["privateKey"], **kwargs)
        kwargs["payload_hash"] = compute_payload_hash({"amount": 999})
        assert not verify_request(ident["publicKey"], sig, **kwargs)


# --- Approval signing ---

class TestApprovalSigning:
    def test_sign_and_verify(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident)
        req_hash = hash_request(**kwargs)

        sig = sign_approval(
            ident["privateKey"],
            conv_id="test-conv-id",
            request_id="req-001",
            request_hash=req_hash,
        )
        assert len(sig) == 64
        assert verify_approval(
            ident["publicKey"],
            sig,
            conv_id="test-conv-id",
            request_id="req-001",
            request_hash=req_hash,
        )

    def test_wrong_request_hash_rejects(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident)
        req_hash = hash_request(**kwargs)

        sig = sign_approval(
            ident["privateKey"],
            conv_id="test-conv-id",
            request_id="req-001",
            request_hash=req_hash,
        )
        assert not verify_approval(
            ident["publicKey"],
            sig,
            conv_id="test-conv-id",
            request_id="req-001",
            request_hash=b"\x00" * 32,
        )


# --- Hash request ---

class TestHashRequest:
    def test_deterministic(self):
        ident = generate_identity()
        kwargs = _signable_kwargs(ident)

        h1 = hash_request(**kwargs)
        h2 = hash_request(**kwargs)
        assert h1 == h2
        assert len(h1) == 32

    def test_different_inputs_different_hash(self):
        ident = generate_identity()
        kwargs1 = _signable_kwargs(ident)
        kwargs2 = _signable_kwargs(ident)
        kwargs2["request_id"] = "req-002"

        assert hash_request(**kwargs1) != hash_request(**kwargs2)


# --- Payload hash ---

class TestPayloadHash:
    def test_none_payload(self):
        h = compute_payload_hash(None)
        assert h == hashlib.sha256(b"").digest()

    def test_dict_payload(self):
        h = compute_payload_hash({"amount": 100, "to": "alice"})
        expected = hashlib.sha256(
            json.dumps({"amount": 100, "to": "alice"}, separators=(",", ":")).encode()
        ).digest()
        assert h == expected


# --- Threshold matching ---

class TestThresholdMatching:
    def _rules(self):
        return [
            ThresholdRule(service="*", endpoint="*", verb="*", m=2),
            ThresholdRule(service="bank-api", endpoint="*", verb="*", m=3),
            ThresholdRule(service="bank-api", endpoint="/v1/transfers", verb="*", m=3),
            ThresholdRule(service="bank-api", endpoint="/v1/transfers", verb="POST", m=4),
        ]

    def test_exact_match(self):
        rule = lookup_threshold(self._rules(), "bank-api", "/v1/transfers", "POST")
        assert rule is not None
        assert rule.m == 4

    def test_service_endpoint_match(self):
        rule = lookup_threshold(self._rules(), "bank-api", "/v1/transfers", "GET")
        assert rule is not None
        assert rule.m == 3

    def test_service_match(self):
        rule = lookup_threshold(self._rules(), "bank-api", "/v1/balance", "GET")
        assert rule is not None
        assert rule.m == 3

    def test_wildcard_match(self):
        rule = lookup_threshold(self._rules(), "hr-api", "/employees", "GET")
        assert rule is not None
        assert rule.m == 2

    def test_no_rules(self):
        rule = lookup_threshold([], "bank-api", "/v1/transfers", "POST")
        assert rule is None
