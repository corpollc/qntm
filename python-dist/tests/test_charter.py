"""Shared Go/TypeScript authority vectors and Python API boundary regressions."""

import copy
import json
import re
from pathlib import Path

import pytest

from qntm import QSP1Suite, generate_identity
from qntm.charter import (
    CharterError, canonicalize_charter_json, charter_agent_id, charter_governance_commitment,
    charter_json_bytes, charter_key, charter_statement_hash, create_charter,
    create_charter_statement, parse_charter_json, parse_charter_statement,
    replay_charter_chain, sign_charter_statement,
)
from qntm.charter.crypto import validate_charter_public_key, verify_charter_signature

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "specs/test-vectors/charter-registry-v02.json").read_text())


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=lambda v: v["name"])
def test_shared_authority_vectors(vector):
    def replay():
        return replay_charter_chain(vector["chain"], registry=vector["registry"], agent_id=vector["agent_id"])
    if vector["valid"]:
        record = replay()
        assert record.head_hash == vector["head_hash"]
        assert record.sequence == len(vector["chain"]) - 1
    else:
        with pytest.raises(CharterError):
            replay()


@pytest.mark.parametrize("vector", VECTORS["json"], ids=lambda v: v["name"])
def test_shared_json_vectors(vector):
    if vector["canonical"] is None:
        with pytest.raises(CharterError):
            canonicalize_charter_json(parse_charter_json(vector["input"]))
    else:
        assert canonicalize_charter_json(parse_charter_json(vector["input"])) == vector["canonical"]


def test_deterministic_signature_matches_typescript_genesis():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = bytes([1]) * 32
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    identity = {"privateKey": seed + public_key, "publicKey": public_key}
    statement = create_charter(registry="test.registry", agent=identity,
                               governance={"keys": [charter_key(public_key)], "threshold": 1},
                               issued_at="2026-09-08T12:00:00Z")
    assert statement == VECTORS["cases"][0]["chain"][0]
    assert charter_statement_hash(statement) == VECTORS["cases"][0]["head_hash"]
    assert parse_charter_statement(canonicalize_charter_json(statement)) == statement


def test_namespaces_are_uninterpreted_and_inputs_are_detached():
    agent = generate_identity()
    governance = {"keys": [charter_key(agent["publicKey"])], "threshold": 1}
    extensions = {"__proto__": {"admin": True}, "freeform": [1, None, "music"]}
    genesis = create_charter(registry="local", agent=agent, governance=governance, extensions=extensions)
    original = copy.deepcopy(genesis)
    extensions["freeform"].append("changed")
    event = sign_charter_statement(create_charter_statement(genesis, "statement", {
        "namespace": "__proto__", "data": {"governance": None},
    }), agent)
    state = replay_charter_chain([genesis, event], registry="local", agent_id=charter_agent_id(agent["publicKey"]))
    assert state.governance == governance
    assert state.charter["extensions"]["freeform"] == [1, None, "music"]
    assert state.statements[0]["data"] == {"governance": None}
    state.charter["extensions"]["freeform"].append("mutated result")
    assert genesis == original
    assert sign_charter_statement(genesis, agent) == genesis


def test_governance_commitments_ignore_key_order_but_include_threshold():
    keys = [charter_key(generate_identity()["publicKey"]) for _ in range(2)]
    assert charter_governance_commitment({"keys": keys, "threshold": 2}) == charter_governance_commitment({"keys": keys[::-1], "threshold": 2})
    assert charter_governance_commitment({"keys": keys, "threshold": 1}) != charter_governance_commitment({"keys": keys, "threshold": 2})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), b"bytes", (1,), {1: "key"}, "\ud800", "\udc00", object(), {"value": object()}, 2**53 + 1, 10**400])
def test_reject_non_json_or_inexact_python_numbers(value):
    with pytest.raises(CharterError):
        charter_json_bytes(value)


def test_json_does_not_invoke_custom_types():
    class Hostile(dict):
        def items(self):
            raise AssertionError("must not call user code")
    with pytest.raises(CharterError):
        charter_json_bytes(Hostile())
    cycle = []
    cycle.append(cycle)
    with pytest.raises(CharterError):
        charter_json_bytes(cycle)


def test_binary64_wire_parity_without_silent_python_integer_rounding():
    assert canonicalize_charter_json(parse_charter_json("9007199254740993")) == "9007199254740992"
    assert canonicalize_charter_json(2**53) == "9007199254740992"
    assert canonicalize_charter_json(1e20) == "100000000000000000000"
    assert canonicalize_charter_json(1e21) == "1e+21"
    assert canonicalize_charter_json(5e-324) == "5e-324"
    for text in ("NaN", "Infinity", "-Infinity", "[" * 2000 + "0" + "]" * 2000):
        with pytest.raises(CharterError):
            parse_charter_json(text)


@pytest.mark.parametrize("change", [
    lambda identity: identity.update(publicKey=generate_identity()["publicKey"]),
    lambda identity: identity.update(privateKey=identity["privateKey"][:32]),
    lambda identity: identity.update(privateKey=bytes(32) + identity["publicKey"]),
])
def test_reject_mismatched_signing_identity(change):
    agent = generate_identity()
    charter = create_charter(registry="local", agent=agent, governance=None)
    change(agent)
    with pytest.raises(CharterError, match="Identity"):
        sign_charter_statement(charter, agent)


def test_timestamp_calendar_and_safe_sequence_are_strict():
    agent = generate_identity()
    for at in ("2026-02-29T00:00:00Z", "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:60Z"):
        with pytest.raises(CharterError):
            create_charter(registry="local", agent=agent, governance=None, issued_at=at)
    create_charter(registry="local", agent=agent, governance=None, issued_at="0000-02-29T00:00:00.123456789Z")
    valid = create_charter(registry="local", agent=agent, governance=None)
    for value in (True, False, -1, 0.5, 2**53, None):
        malformed = copy.deepcopy(valid)
        malformed["signed"]["seq"] = value
        with pytest.raises(CharterError):
            parse_charter_statement(canonicalize_charter_json(malformed))


def test_strict_subgroup_check_even_when_sodium_point_predicate_is_permissive(monkeypatch):
    import qntm.charter.crypto as crypto
    from qntm.identity import base64url_decode
    mixed = next(v for v in VECTORS["cases"] if v["name"] == "reject mixed torsion governance key")
    key = base64url_decode(mixed["chain"][0]["signed"]["body"]["governance"]["keys"][-1]["pubkey"])
    monkeypatch.setattr(crypto.sodium, "crypto_core_ed25519_is_valid_point", lambda _: True)
    with pytest.raises(CharterError):
        validate_charter_public_key(key)


def test_signature_profile_rejects_noncanonical_scalar_and_allows_prime_order_keys():
    agent = generate_identity()
    message = b"charter signature boundary"
    signature = QSP1Suite().sign(agent["privateKey"], message)
    assert verify_charter_signature(agent["publicKey"], message, signature)
    order = 2**252 + 27742317777372353535851937790883648493
    bad = signature[:32] + (int.from_bytes(signature[32:], "little") + order).to_bytes(32, "little")
    assert not verify_charter_signature(agent["publicKey"], message, bad)
    assert not verify_charter_signature(agent["publicKey"], message, b"")


def test_python_readme_charter_example_runs_without_network():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    section = readme.split("## Experimental charter library\n", 1)[1].split("## Links", 1)[0]
    code = re.search(r"```python\n(.*?)```", section, re.S).group(1)
    scope = {}
    exec(compile(code, "python-dist/README.md", "exec"), scope)
    assert scope["record"].statements[0]["data"] == {"collaboration": "welcome"}
