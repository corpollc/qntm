"""Tests for the gate module: signing, verification, threshold matching."""

import hashlib
import json
import time
from pathlib import Path

import pytest

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

@pytest.mark.parametrize("case", json.loads((Path(__file__).parents[2] / "specs/test-vectors/gateway-thresholds.json").read_text()), ids=lambda case: case["name"])
def test_shared_threshold_selection(case):
    rules = [ThresholdRule(**rule) for rule in case["rules"]]
    selected = lookup_threshold(rules, case["service"], case["endpoint"], case["verb"])
    expected = case["expected_index"]
    assert selected is (None if expected is None else rules[expected])

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

    def test_case_insensitive_verb_and_param_template_matching(self):
        rules = [
            ThresholdRule(service="github", endpoint="/repos/{owner}/{repo}/issues", verb="post", m=3),
            ThresholdRule(service="github", endpoint="/repos/{owner}/special/issues", verb="POST", m=5),
        ]
        # Exact segment outranks {param} template on tie, and verb matching is case-insensitive
        assert lookup_threshold(rules, "github", "/repos/acme/widgets/issues", "POST") is rules[0]
        assert lookup_threshold(rules, "github", "/repos/acme/widgets/issues", "post") is rules[0]
        assert lookup_threshold(rules, "github", "/repos/acme/special/issues", "post") is rules[1]
        # Dot-segment traversal does not match {param}
        assert lookup_threshold(rules, "github", "/repos/../widgets/issues", "POST") is None
        assert lookup_threshold(rules, "github", "/repos/./widgets/issues", "POST") is None


class TestSecretOriginResolutionAndRecipeEncoding:
    def test_builtin_service_origins_exact_map(self):
        from qntm.gate import BUILTIN_SERVICE_ORIGINS, resolve_service_origins

        expected = {
            "github": ["https://api.github.com"],
            "openai": ["https://api.openai.com"],
            "anthropic": ["https://api.anthropic.com"],
            "gemini": ["https://generativelanguage.googleapis.com"],
            "stripe": ["https://api.stripe.com"],
            "hackernews": ["https://hacker-news.firebaseio.com"],
            "httpbin": ["https://httpbin.org"],
            "dadjokes": ["https://icanhazdadjoke.com"],
            "trivia": ["https://opentdb.com"],
            "dogs": ["https://dog.ceo"],
            "fun": ["http://localhost:9090"],
        }
        assert BUILTIN_SERVICE_ORIGINS == expected
        for name, origins in expected.items():
            assert resolve_service_origins(name) == origins
            assert resolve_service_origins(name.upper()) == origins

    def test_canonicalize_and_resolve_service_origins_rules(self):
        from qntm.gate import canonicalize_origin, resolve_service_origins

        assert canonicalize_origin("HTTPS://API.Example.COM:443/") == "https://api.example.com"
        assert canonicalize_origin("https://api.example.com:8443") == "https://api.example.com:8443"
        assert canonicalize_origin("http://LOCALHOST:9090/") == "http://localhost:9090"
        assert canonicalize_origin("http://127.0.0.1:80") == "http://127.0.0.1"
        assert canonicalize_origin("http://[::1]:3000/") == "http://[::1]:3000"

        assert resolve_service_origins("api.example.com") == ["https://api.example.com"]
        assert resolve_service_origins("localhost:9090") == ["http://localhost:9090"]
        assert resolve_service_origins("127.0.0.1:4000") == ["http://127.0.0.1:4000"]
        assert resolve_service_origins("[::1]:5000") == ["http://[::1]:5000"]
        assert resolve_service_origins("https://custom.example.org:443/") == ["https://custom.example.org"]
        assert resolve_service_origins(
            "unknown-alias",
            explicit_origins=["https://A.example.com/", "https://a.example.com:443", "https://b.example.com:8443"],
        ) == ["https://a.example.com", "https://b.example.com:8443"]

        for bad_origin in (
            "http://api.example.com",
            "https://user:pass@api.example.com",
            "https://api.example.com/v1",
            "https://api.example.com?x=1",
            "https://api.example.com#frag",
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[::ffff:127.0.0.1]",
            "ftp://api.example.com",
        ):
            with pytest.raises(ValueError):
                canonicalize_origin(bad_origin)

        with pytest.raises(ValueError, match="Unknown service"):
            resolve_service_origins("mysteryservice")

        with pytest.raises(ValueError, match="between 1 and 16"):
            resolve_service_origins(
                "stripe",
                explicit_origins=[f"https://s{i}.example.com" for i in range(17)],
            )

    def test_resolve_recipe_url_encodes_path_and_query_params(self):
        from qntm.gate import Recipe, RecipeParam, resolve_recipe

        recipe = Recipe(
            name="items.lookup",
            description="Lookup item",
            service="httpbin",
            verb="GET",
            endpoint="/items/{id}",
            target_url="https://httpbin.org/items/{id}",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", type="string", required=True)],
            query_params=[RecipeParam(name="filter", description="Filter", type="string", required=False)],
        )
        endpoint, url, body = resolve_recipe(
            recipe,
            {"id": "foo/bar?baz=1#frag", "filter": "a b&admin=true"},
        )
        assert body is None
        assert endpoint == "/items/foo%2Fbar%3Fbaz%3D1%23frag"
        assert url == "https://httpbin.org/items/foo%2Fbar%3Fbaz%3D1%23frag?filter=a%20b%26admin%3Dtrue"

        for traversal in (".", "..", ""):
            with pytest.raises(ValueError):
                resolve_recipe(recipe, {"id": traversal})
