"""Transport and signed-evidence failures must not establish charter trust."""

import copy
import hashlib

import httpx
import pytest

from qntm import QSP1Suite, base64url_encode, generate_identity
from qntm.charter import (
    CharterError, CharterRegistryClient, CharterRegistryError, charter_json_bytes,
    charter_key, create_charter, verify_charter_heads,
)


@pytest.fixture
def registrar():
    identity = generate_identity()
    trust = {"registry": "test.registry", "registrar": charter_key(identity["publicKey"])}

    def signed(body):
        return {"signed": body, "kid": trust["registrar"]["kid"],
                "sig": base64url_encode(QSP1Suite().sign(identity["privateKey"], charter_json_bytes(body)))}

    empty = hashlib.sha256(b"").hexdigest()
    common = {"registry": trust["registry"], "timestamp": "2026-09-09T00:00:00Z"}
    heads = {"log": signed({**common, "kind": "charter.log", "tree_size": 0, "root_hash": empty}),
             "epoch": signed({**common, "kind": "charter.epoch", "epoch": 0, "map_size": 0,
                              "map_root": empty, "log_size": 0, "log_root": empty})}
    return trust, heads, signed


def mock_http(client, handler):
    client._http.close()
    client._http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


@pytest.mark.parametrize("url", [
    "http://example.com", "https://user:password@example.com", "https://user@example.com",
    "https://example.com?secret=1", "https://example.com#part", "https://example.com?",
    "https://example.com#", "https://example.com:65536", "https://", "file:///tmp/registry",
    "http://127.0.0.1.example.com", "https://example.com\\@evil.test", "https://example.com\n",
])
def test_reject_unsafe_base_urls(registrar, url):
    with pytest.raises(CharterError):
        CharterRegistryClient(url, registrar[0])


@pytest.mark.parametrize("url", ["http://localhost:8085", "http://127.0.0.1:8085", "http://[::1]:8085", "https://registry.example/prefix/"])
def test_accept_loopback_and_https(registrar, url):
    with CharterRegistryClient(url, registrar[0]):
        pass


def test_pins_are_required_and_detached(registrar):
    trust, heads, _ = registrar
    with pytest.raises(CharterError):
        CharterRegistryClient("https://registry.test", {})
    with CharterRegistryClient("https://registry.test", trust) as client:
        trust["registry"] = "mutated"
        trust["registrar"]["kid"] = "0" * 32
        mock_http(client, lambda _: httpx.Response(200, json=heads))
        assert client.heads() == heads


def test_validate_paths_and_sizes_before_network(registrar):
    with CharterRegistryClient("https://registry.test", registrar[0]) as client:
        def no_request(_):
            raise AssertionError("Invalid inputs must not send requests")
        mock_http(client, no_request)
        for agent in ("../info", "0" * 31, "0" * 33, None, [], "A" * 32):
            with pytest.raises(CharterError):
                client.chain(agent)
        for count in (-1, True, 0.5, 2**53, "0", float("nan")):
            with pytest.raises(CharterError):
                client.heads(count)


def test_redirect_is_rejected_without_following_or_reposting(registrar):
    requests = []
    agent = generate_identity()
    statement = create_charter(registry=registrar[0]["registry"], agent=agent, governance=None)
    with CharterRegistryClient("https://registry.test", registrar[0]) as client:
        def handler(request):
            requests.append(request)
            return httpx.Response(307, headers={"Location": "http://localhost/private"})
        mock_http(client, handler)
        with pytest.raises(CharterRegistryError) as error:
            client.submit(statement)
        assert error.value.code == "redirect_rejected"
        assert len(requests) == 1 and requests[0].method == "POST"
        assert requests[0].content == charter_json_bytes(statement)


def test_uncertain_submission_is_never_automatically_retried(registrar):
    requests = []
    agent = generate_identity()
    statement = create_charter(registry=registrar[0]["registry"], agent=agent, governance=None)
    with CharterRegistryClient("https://registry.test", registrar[0]) as client:
        def handler(request):
            requests.append(request)
            raise httpx.ReadError("response lost", request=request)
        mock_http(client, handler)
        with pytest.raises(httpx.ReadError):
            client.submit(statement)
        assert len(requests) == 1


@pytest.mark.parametrize("body", [b'{"log":{},"log":{}}', b'{"log":NaN}', b'{"a":"\xff"}', b'not json'])
def test_reject_bad_response_json(registrar, body):
    with CharterRegistryClient("https://registry.test", registrar[0]) as client:
        mock_http(client, lambda _: httpx.Response(200, content=body))
        with pytest.raises(CharterRegistryError) as error:
            client.heads()
        assert error.value.code == "invalid_json"


def test_bound_response_bytes(registrar):
    with CharterRegistryClient("https://registry.test", registrar[0], max_response_bytes=64) as client:
        mock_http(client, lambda _: httpx.Response(200, content=b" " * 65))
        with pytest.raises(CharterError, match="byte limit"):
            client.heads()


def test_structured_http_failure_and_wrong_historical_size(registrar):
    with CharterRegistryClient("https://registry.test", registrar[0]) as client:
        mock_http(client, lambda _: httpx.Response(409, json={"error": "sequence_conflict", "message": "Already committed"}))
        with pytest.raises(CharterRegistryError) as error:
            client.heads()
        assert (error.value.status, error.value.code) == (409, "sequence_conflict")
        mock_http(client, lambda _: httpx.Response(200, json=registrar[1]))
        with pytest.raises(CharterError, match="Wrong snapshot size"):
            client.heads(1)


@pytest.mark.parametrize("mutation", [
    lambda heads: heads["log"]["signed"].update(tree_size=True),
    lambda heads: heads["log"]["signed"].update(root_hash="0" * 64),
    lambda heads: heads["log"]["signed"].update(kind="charter.epoch"),
    lambda heads: heads["epoch"]["signed"].update(epoch=1),
    lambda heads: heads["epoch"]["signed"].update(timestamp="2026-09-10T00:00:00Z"),
    lambda heads: heads["epoch"]["signed"].update(timestamp="2026-02-30T00:00:00Z"),
    lambda heads: heads["epoch"]["signed"].update(log_root="0" * 64),
    lambda heads: heads["epoch"]["signed"].update(map_root="0" * 64),
])
def test_signed_but_invalid_head_bindings_are_rejected(registrar, mutation):
    trust, heads, sign = registrar
    heads = copy.deepcopy(heads)
    mutation(heads)
    heads = {key: sign(head["signed"]) for key, head in heads.items()}
    with pytest.raises(CharterError):
        verify_charter_heads(heads, trust)


@pytest.mark.parametrize("heads", [None, {}, {"log": []}, {"log": {"signed": []}, "epoch": None}])
def test_malformed_evidence_produces_validation_error(registrar, heads):
    with pytest.raises(CharterError):
        verify_charter_heads(heads, registrar[0])


@pytest.mark.parametrize("page", [
    {"from": 0, "next": 0, "entries": []},
    {"from": 1, "next": 2, "entries": [{}]},
    {"from": 0, "next": 2, "entries": [{}]},
    {"from": False, "next": 1, "entries": [{}]},
    {"from": 0, "next": 1, "entries": None},
])
def test_bad_log_pagination_cannot_loop_or_skip(registrar, page):
    trust, heads, sign = registrar
    heads["log"]["signed"]["tree_size"] = 1
    heads["epoch"]["signed"].update(epoch=1, map_size=1, log_size=1)
    heads = {key: sign(head["signed"]) for key, head in heads.items()}
    with CharterRegistryClient("https://registry.test", trust) as client:
        mock_http(client, lambda _: httpx.Response(200, json=page))
        with pytest.raises(CharterError):
            client.log(heads)
