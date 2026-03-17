"""Tests for gate rearchitecture: recipes, new message types, payloads, secrets."""

import json

import pytest

from qntm.gate import (
    # Message type constants
    GATE_MESSAGE_REQUEST,
    GATE_MESSAGE_APPROVAL,
    GATE_MESSAGE_EXECUTED,
    GATE_MESSAGE_PROMOTE,
    GATE_MESSAGE_SECRET,
    GATE_MESSAGE_CONFIG,
    # New dataclasses
    RecipeParam,
    Recipe,
    PromotePayload,
    SecretPayload,
    GateConversationMessage,
    ThresholdRule,
    # Functions
    resolve_recipe,
    seal_secret,
    open_secret,
)
from qntm.identity import generate_identity


# ---------------------------------------------------------------------------
# Message type constants
# ---------------------------------------------------------------------------

class TestMessageTypeConstants:
    def test_request_constant(self):
        assert GATE_MESSAGE_REQUEST == "gate.request"

    def test_approval_constant(self):
        assert GATE_MESSAGE_APPROVAL == "gate.approval"

    def test_executed_constant(self):
        assert GATE_MESSAGE_EXECUTED == "gate.executed"

    def test_promote_constant(self):
        assert GATE_MESSAGE_PROMOTE == "gate.promote"

    def test_secret_constant(self):
        assert GATE_MESSAGE_SECRET == "gate.secret"

    def test_config_constant(self):
        assert GATE_MESSAGE_CONFIG == "gate.config"


# ---------------------------------------------------------------------------
# RecipeParam dataclass
# ---------------------------------------------------------------------------

class TestRecipeParam:
    def test_required_param(self):
        p = RecipeParam(name="id", description="Item ID", required=True, type="string")
        assert p.name == "id"
        assert p.required is True
        assert p.default == ""

    def test_optional_param_with_default(self):
        p = RecipeParam(name="limit", description="Max results", required=False, default="10", type="integer")
        assert p.default == "10"
        assert p.required is False


# ---------------------------------------------------------------------------
# Recipe dataclass
# ---------------------------------------------------------------------------

class TestRecipe:
    def test_basic_recipe(self):
        r = Recipe(
            name="hn.top-stories",
            description="Get HN top stories",
            service="hackernews",
            verb="GET",
            endpoint="/v0/topstories.json",
            target_url="https://hacker-news.firebaseio.com/v0/topstories.json",
            risk_tier="read",
            threshold=1,
        )
        assert r.name == "hn.top-stories"
        assert r.verb == "GET"
        assert r.path_params == []
        assert r.query_params == []
        assert r.body_schema is None

    def test_recipe_with_params(self):
        r = Recipe(
            name="test.with-params",
            description="Test",
            service="test",
            verb="GET",
            endpoint="/items/{id}",
            target_url="https://api.test/items/{id}",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", required=True, type="string")],
            query_params=[RecipeParam(name="format", description="Format", required=False, default="json", type="string")],
        )
        assert len(r.path_params) == 1
        assert r.path_params[0].name == "id"
        assert len(r.query_params) == 1


# ---------------------------------------------------------------------------
# resolve_recipe
# ---------------------------------------------------------------------------

class TestResolveRecipe:
    def _simple_recipe(self):
        return Recipe(
            name="test.item",
            description="Get item",
            service="test-api",
            verb="GET",
            endpoint="/items/{id}",
            target_url="https://api.test/items/{id}",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="id", description="Item ID", required=True, type="string")],
        )

    def _query_recipe(self):
        return Recipe(
            name="test.search",
            description="Search",
            service="test-api",
            verb="GET",
            endpoint="/search",
            target_url="https://api.test/search",
            risk_tier="read",
            threshold=1,
            query_params=[
                RecipeParam(name="q", description="Query", required=True, type="string"),
                RecipeParam(name="limit", description="Limit", required=False, default="10", type="integer"),
            ],
        )

    def _post_recipe(self):
        return Recipe(
            name="test.create",
            description="Create item",
            service="test-api",
            verb="POST",
            endpoint="/items",
            target_url="https://api.test/items",
            risk_tier="write",
            threshold=2,
            body_schema=json.dumps({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "integer"},
                },
                "required": ["name"],
            }),
        )

    def test_path_param_substitution(self):
        endpoint, url, body = resolve_recipe(self._simple_recipe(), {"id": "42"})
        assert endpoint == "/items/42"
        assert url == "https://api.test/items/42"
        assert body is None

    def test_missing_required_path_param(self):
        with pytest.raises(ValueError, match="missing required path parameter"):
            resolve_recipe(self._simple_recipe(), {})

    def test_query_params_appended(self):
        endpoint, url, body = resolve_recipe(self._query_recipe(), {"q": "hello"})
        assert endpoint == "/search"
        assert "q=hello" in url
        assert "limit=10" in url  # default applied

    def test_missing_required_query_param(self):
        with pytest.raises(ValueError, match="missing required query parameter"):
            resolve_recipe(self._query_recipe(), {})

    def test_body_building_from_schema(self):
        endpoint, url, body = resolve_recipe(
            self._post_recipe(), {"name": "widget", "value": "100"}
        )
        assert body is not None
        parsed = json.loads(body)
        assert parsed["name"] == "widget"
        assert parsed["value"] == "100"

    def test_missing_required_body_param(self):
        with pytest.raises(ValueError, match="missing required body parameter"):
            resolve_recipe(self._post_recipe(), {"value": "100"})

    def test_none_args_treated_as_empty(self):
        """When args is None, required params should still be checked."""
        with pytest.raises(ValueError, match="missing required path parameter"):
            resolve_recipe(self._simple_recipe(), None)

    def test_default_used_for_missing_path_param(self):
        r = Recipe(
            name="test.default",
            description="Test",
            service="test",
            verb="GET",
            endpoint="/v/{version}/items",
            target_url="https://api.test/v/{version}/items",
            risk_tier="read",
            threshold=1,
            path_params=[RecipeParam(name="version", description="API version", required=True, default="2", type="string")],
        )
        endpoint, url, body = resolve_recipe(r, {})
        assert endpoint == "/v/2/items"
        assert "v/2/items" in url


# ---------------------------------------------------------------------------
# PromotePayload, ConfigPayload, SecretPayload
# ---------------------------------------------------------------------------

class TestPayloadDataclasses:
    def test_promote_payload(self):
        p = PromotePayload(
            conv_id="a" * 32,
            gateway_kid="gw-kid",
            participants={"kid1": "pk1"},
            rules=[ThresholdRule(service="*", endpoint="*", verb="*", m=2)],
            floor=2,
        )
        assert p.conv_id == "a" * 32
        assert len(p.participants) == 1
        assert len(p.rules) == 1
        assert p.floor == 2

    def test_secret_payload(self):
        p = SecretPayload(
            secret_id="sec-1",
            service="bank-api",
            header_name="Authorization",
            header_template="Bearer {value}",
            encrypted_blob="base64data",
            sender_kid="kid1",
        )
        assert p.secret_id == "sec-1"
        assert p.header_template == "Bearer {value}"


# ---------------------------------------------------------------------------
# GateConversationMessage with recipe fields
# ---------------------------------------------------------------------------

class TestGateConversationMessage:
    def test_basic_fields(self):
        m = GateConversationMessage(
            type=GATE_MESSAGE_REQUEST,
            conv_id="conv-1",
            request_id="req-1",
            signer_kid="kid1",
            signature="sig1",
        )
        assert m.type == "gate.request"
        assert m.conv_id == "conv-1"

    def test_recipe_fields(self):
        m = GateConversationMessage(
            type=GATE_MESSAGE_REQUEST,
            conv_id="conv-1",
            request_id="req-1",
            signer_kid="kid1",
            signature="sig1",
            recipe_name="hn.top-stories",
            arguments={"limit": "10"},
        )
        assert m.recipe_name == "hn.top-stories"
        assert m.arguments == {"limit": "10"}

    def test_recipe_fields_default_none(self):
        m = GateConversationMessage(
            type=GATE_MESSAGE_REQUEST,
            conv_id="conv-1",
            request_id="req-1",
            signer_kid="kid1",
            signature="sig1",
        )
        assert m.recipe_name is None
        assert m.arguments is None

    def test_request_fields(self):
        m = GateConversationMessage(
            type=GATE_MESSAGE_REQUEST,
            conv_id="conv-1",
            request_id="req-1",
            verb="POST",
            target_endpoint="/v1/transfers",
            target_service="bank-api",
            target_url="https://api.bank.test/v1/transfers",
            signer_kid="kid1",
            signature="sig1",
        )
        assert m.verb == "POST"
        assert m.target_service == "bank-api"


# ---------------------------------------------------------------------------
# NaCl box seal_secret / open_secret
# ---------------------------------------------------------------------------

class TestSealOpenSecret:
    def test_roundtrip(self):
        sender = generate_identity()
        gateway = generate_identity()
        plaintext = b"super-secret-api-key-12345"

        ciphertext = seal_secret(
            sender_private_key=sender["privateKey"],
            gateway_public_key=gateway["publicKey"],
            plaintext=plaintext,
        )

        # Ciphertext should be longer than plaintext (nonce + overhead)
        assert len(ciphertext) > len(plaintext)

        recovered = open_secret(
            gateway_private_key=gateway["privateKey"],
            sender_public_key=sender["publicKey"],
            ciphertext=ciphertext,
        )
        assert recovered == plaintext

    def test_wrong_gateway_key_fails(self):
        sender = generate_identity()
        gateway = generate_identity()
        wrong_gateway = generate_identity()

        ciphertext = seal_secret(
            sender_private_key=sender["privateKey"],
            gateway_public_key=gateway["publicKey"],
            plaintext=b"secret",
        )

        with pytest.raises(Exception):
            open_secret(
                gateway_private_key=wrong_gateway["privateKey"],
                sender_public_key=sender["publicKey"],
                ciphertext=ciphertext,
            )

    def test_wrong_sender_key_fails(self):
        sender = generate_identity()
        gateway = generate_identity()
        wrong_sender = generate_identity()

        ciphertext = seal_secret(
            sender_private_key=sender["privateKey"],
            gateway_public_key=gateway["publicKey"],
            plaintext=b"secret",
        )

        with pytest.raises(Exception):
            open_secret(
                gateway_private_key=gateway["privateKey"],
                sender_public_key=wrong_sender["publicKey"],
                ciphertext=ciphertext,
            )

    def test_short_ciphertext_fails(self):
        gateway = generate_identity()
        sender = generate_identity()

        with pytest.raises(ValueError, match="too short"):
            open_secret(
                gateway_private_key=gateway["privateKey"],
                sender_public_key=sender["publicKey"],
                ciphertext=b"short",
            )

    def test_empty_plaintext(self):
        sender = generate_identity()
        gateway = generate_identity()

        ciphertext = seal_secret(
            sender_private_key=sender["privateKey"],
            gateway_public_key=gateway["publicKey"],
            plaintext=b"",
        )

        recovered = open_secret(
            gateway_private_key=gateway["privateKey"],
            sender_public_key=sender["publicKey"],
            ciphertext=ciphertext,
        )
        assert recovered == b""
