"""Experimental Charter Registry v0.2 construction and offline authority replay."""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from ..crypto import QSP1Suite
from ..identity import base64url_decode, base64url_encode
from .crypto import validate_charter_public_key, verify_charter_signature
from .json import (CharterError, MAX_SAFE_INTEGER, charter_json_bytes, clone,
                   parse_charter_json)

CHARTER_DRAFT_VERSION = "0.2"
CHARTER_GENESIS_HASH = "0" * 64
CharterStatementType = Literal["charter", "constitution.amend", "governance.rotate",
                              "opkey.delegate", "opkey.revoke", "agent.decommission",
                              "agent.successor", "liveness.update", "statement"]
CharterAgentRight = Literal["liveness.update", "statement"]
_TYPES = {"charter", "constitution.amend", "governance.rotate", "opkey.delegate",
          "opkey.revoke", "agent.decommission", "agent.successor", "liveness.update", "statement"}


class CharterKey(TypedDict):
    kid: str
    pubkey: str


class CharterGovernance(TypedDict):
    keys: list[CharterKey]
    threshold: int


class CharterSignedBody(TypedDict):
    registry: str
    agent_id: str
    seq: int
    prev_hash: str
    type: CharterStatementType
    issued_at: str
    body: Any


class CharterSignature(TypedDict):
    kid: str
    sig: str


class CharterStatement(TypedDict):
    signed: CharterSignedBody
    signatures: list[CharterSignature]


@dataclass
class CharterRecord:
    registry: str
    agent_id: str
    agent_public_key: str
    sequence: int
    head_hash: str
    charter: dict
    governance: CharterGovernance | None
    agent_rights: list[CharterAgentRight]
    next_governance_commitment: str | None = None
    constitution: Any = None
    liveness: Any = None
    operational_keys: dict[str, dict] = field(default_factory=dict)
    successor: str | None = None
    decommissioned: bool = False
    statements: list[dict] = field(default_factory=list)


def check(condition: Any, message: str) -> None:
    if not condition:
        raise CharterError(message)


def obj(value: Any, label: str) -> dict:
    check(type(value) is dict, f"{label} must be an object")
    return value


def nonempty(value: Any, label: str) -> None:
    check(type(value) is str and len(value) > 0, f"{label} must be a non-empty string")


def valid_hash(value: Any) -> None:
    check(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "Invalid SHA-256 hash")


def valid_id(value: Any) -> None:
    check(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value), "Invalid key/agent ID")


def size(value: Any) -> int:
    check(type(value) in (int, float) and 0 <= value <= MAX_SAFE_INTEGER and int(value) == value,
          "Invalid safe integer size/index")
    return int(value)


def wire(value: Any, length: int) -> bytes:
    check(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value),
          "Expected canonical base64url string")
    try:
        result = base64url_decode(value)
    except (ValueError, UnicodeError) as exc:
        raise CharterError("Invalid canonical base64url encoding") from exc
    check(len(result) == length and base64url_encode(result) == value,
          "Invalid canonical base64url encoding")
    return result


def timestamp(value: Any) -> None:
    check(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", value),
          "Expected RFC 3339 UTC timestamp")
    try:
        # datetime cannot represent year 0000; year 0400 has the same leap rules.
        calendar = ("0400" if value[:4] == "0000" else value[:4]) + value[4:19]
        datetime.strptime(calendar, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise CharterError("Invalid timestamp") from exc


def validate_governance(value: Any) -> None:
    governance = obj(value, "Governance")
    keys = governance.get("keys")
    check(type(keys) is list and len(keys) > 0, "Governance keys cannot be empty")
    threshold = size(governance.get("threshold"))
    check(1 <= threshold <= len(keys), "Invalid governance threshold")
    seen = set()
    for raw in keys:
        key = obj(raw, "Governance key")
        valid_id(key.get("kid"))
        public_key = wire(key.get("pubkey"), 32)
        validate_charter_public_key(public_key)
        check(charter_agent_id(public_key) == key["kid"], "Governance key ID does not match public key")
        check(key["kid"] not in seen, "Duplicate governance key")
        seen.add(key["kid"])
        check(set(key) <= {"kid", "pubkey"}, "Unknown governance-key field")
    check(set(governance) <= {"keys", "threshold"}, "Unknown governance field")


def _charter_body(value: Any, agent_id: str) -> dict:
    body = obj(value, "Charter body")
    public_key = wire(body.get("agent_pubkey"), 32)
    validate_charter_public_key(public_key)
    check(charter_agent_id(public_key) == agent_id, "Agent public key does not match agent ID")
    check("governance" in body, "Missing governance")
    if body["governance"] is not None:
        validate_governance(body["governance"])
    rights = body.get("agent_rights")
    check(type(rights) is list and all(r in ("liveness.update", "statement") for r in rights),
          "Agent rights may grant only informational statement types")
    check(len(set(rights)) == len(rights), "Duplicate agent right")
    if "next_governance_commitment" in body:
        valid_hash(body["next_governance_commitment"])
    if "extensions" in body:
        for namespace in obj(body["extensions"], "Charter extensions"):
            nonempty(namespace, "Extension namespace")
    return clone(body)


def charter_agent_id(public_key: bytes) -> str:
    check(type(public_key) is bytes and len(public_key) == 32, "Expected 32-byte Ed25519 public key")
    return hashlib.sha256(public_key).digest()[:16].hex()


def charter_key(public_key: bytes) -> CharterKey:
    return {"kid": charter_agent_id(public_key), "pubkey": base64url_encode(public_key)}


def charter_governance_commitment(governance: CharterGovernance) -> str:
    validate_governance(governance)
    return hashlib.sha256(charter_json_bytes({
        "keys": sorted(governance["keys"], key=lambda key: key["kid"]),
        "threshold": governance["threshold"],
    })).hexdigest()


def charter_statement_hash(statement: CharterStatement | CharterSignedBody) -> str:
    value = obj(statement, "Statement")
    return hashlib.sha256(charter_json_bytes(value["signed"] if "signed" in value else value)).hexdigest()


def sign_charter_statement(statement: CharterStatement, identity: dict) -> CharterStatement:
    """Add/replace this key's signature without changing the input document."""
    result = clone(statement)
    identity = obj(identity, "Identity")
    public_key, private_key = identity.get("publicKey"), identity.get("privateKey")
    validate_charter_public_key(public_key)
    check(type(private_key) is bytes and len(private_key) == 64 and private_key[32:] == public_key,
          "Identity private/public keys do not match")
    signed = charter_json_bytes(obj(result, "Statement").get("signed"))
    signature = QSP1Suite().sign(private_key, signed)
    check(verify_charter_signature(public_key, signed, signature), "Identity private/public keys do not match")
    check(type(result.get("signatures")) is list, "Missing signatures")
    signer = charter_agent_id(public_key)
    result["signatures"] = [s for s in result["signatures"] if obj(s, "Signature").get("kid") != signer]
    result["signatures"].append({"kid": signer, "sig": base64url_encode(signature)})
    return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def create_charter(*, registry: str, agent: dict, governance: CharterGovernance | None,
                   agent_rights: list[CharterAgentRight] | None = None,
                   extensions: dict | None = None, next_governance_commitment: str | None = None,
                   issued_at: str | None = None) -> CharterStatement:
    """Create an agent-signed genesis; add any required governors' signatures."""
    agent = obj(agent, "Agent identity")
    public_key = agent.get("publicKey")
    agent_id = charter_agent_id(public_key)
    body = {"agent_pubkey": base64url_encode(public_key), "governance": governance,
            "agent_rights": [] if agent_rights is None else agent_rights}
    if extensions is not None:
        body["extensions"] = extensions
    if next_governance_commitment is not None:
        body["next_governance_commitment"] = next_governance_commitment
    statement = {"signed": {"registry": registry, "agent_id": agent_id, "seq": 0,
                            "prev_hash": CHARTER_GENESIS_HASH, "type": "charter",
                            "issued_at": _now() if issued_at is None else issued_at, "body": body},
                 "signatures": []}
    validate_shape(statement)
    _charter_body(body, agent_id)
    return sign_charter_statement(statement, agent)


def create_charter_statement(previous: CharterStatement, statement_type: CharterStatementType,
                             body: Any, issued_at: str | None = None) -> CharterStatement:
    """Create an unsigned successor. Authenticate the full previous chain first."""
    validate_shape(previous)
    check(statement_type != "charter", "Charter cannot be replaced")
    prior = previous["signed"]
    result = {"signed": {"registry": prior["registry"], "agent_id": prior["agent_id"],
                         "seq": prior["seq"] + 1, "prev_hash": charter_statement_hash(previous),
                         "type": statement_type, "issued_at": _now() if issued_at is None else issued_at,
                         "body": clone(body)}, "signatures": []}
    validate_shape(result)
    return result


def validate_shape(statement: Any) -> None:
    charter_json_bytes(statement)
    envelope = obj(statement, "Statement")
    check(set(envelope) <= {"signed", "signatures"}, "Unknown envelope field")
    signed = obj(envelope.get("signed"), "Signed body")
    check(set(signed) <= {"registry", "agent_id", "seq", "prev_hash", "type", "issued_at", "body"},
          "Unknown signed-body field")
    nonempty(signed.get("registry"), "Registry")
    valid_id(signed.get("agent_id"))
    valid_hash(signed.get("prev_hash"))
    timestamp(signed.get("issued_at"))
    size(signed.get("seq"))
    check(type(signed.get("type")) is str and signed["type"] in _TYPES, "Unknown core statement type")
    check("body" in signed and type(envelope.get("signatures")) is list, "Missing body or signatures")
    seen = set()
    for raw in envelope["signatures"]:
        signature = obj(raw, "Signature")
        valid_id(signature.get("kid"))
        wire(signature.get("sig"), 64)
        check(set(signature) <= {"kid", "sig"}, "Unknown signature field")
        check(signature["kid"] not in seen, "Duplicate signature key")
        seen.add(signature["kid"])


def parse_charter_statement(text: str) -> CharterStatement:
    statement = parse_charter_json(text)
    validate_shape(statement)
    return clone(statement)


def replay_charter_chain(chain: list[CharterStatement], *, registry: str, agent_id: str) -> CharterRecord:
    """Validate every signature and authority transition for an explicit audience."""
    nonempty(registry, "Expected registry")
    valid_id(agent_id)
    check(type(chain) is list and len(chain) > 0, "Charter chain is empty")
    state = None
    for incoming in chain:
        validate_shape(incoming)
        statement = clone(incoming)
        signed = statement["signed"]
        check(signed["registry"] == registry and signed["agent_id"] == agent_id, "Registry or agent audience mismatch")
        check(signed["seq"] == (state.sequence + 1 if state else 0), "Sequence gap, duplicate, or out-of-order statement")
        check(signed["prev_hash"] == (state.head_hash if state else CHARTER_GENESIS_HASH), "Previous statement hash mismatch")
        check(not state or not state.decommissioned, "Decommissioned records are terminal")
        genesis = None
        if state is None:
            check(signed["type"] == "charter", "First statement must be a charter")
            genesis = _charter_body(signed["body"], agent_id)
        else:
            check(signed["type"] != "charter", "Charter cannot be replaced")
            check(state.governance is not None, "Record is frozen at birth")
        governance = genesis["governance"] if genesis is not None else state.governance
        public_key = genesis["agent_pubkey"] if genesis is not None else state.agent_public_key
        authorized = {key["kid"]: key["pubkey"] for key in governance["keys"]} if governance else {}
        authorized[agent_id] = public_key
        signers = set()
        for signature in statement["signatures"]:
            check(signature["kid"] in authorized, "Signature is from a key outside the current authority")
            check(verify_charter_signature(wire(authorized[signature["kid"]], 32),
                                            charter_json_bytes(signed), wire(signature["sig"], 64)),
                  "Invalid statement signature")
            signers.add(signature["kid"])
        governed = governance is not None and sum(key["kid"] in signers for key in governance["keys"]) >= governance["threshold"]
        if genesis is not None:
            check(agent_id in signers, "Charter requires the agent signature")
            check(governance is None or governed, "Charter requires governance acceptance")
            state = CharterRecord(registry, agent_id, public_key, 0, charter_statement_hash(statement),
                                  genesis, clone(governance), list(genesis["agent_rights"]),
                                  next_governance_commitment=genesis.get("next_governance_commitment"))
            continue
        agent_allowed = signed["type"] in state.agent_rights and agent_id in signers
        check(governed or agent_allowed, "Statement lacks current governing authority")
        kind, body = signed["type"], signed["body"]
        if kind == "constitution.amend":
            state.constitution = body
        elif kind == "liveness.update":
            state.liveness = body
        elif kind == "statement":
            obj(body, "Namespaced statement")
            nonempty(body.get("namespace"), "Namespace")
            check("data" in body, "Namespaced statement requires data")
            entry = {"seq": signed["seq"], "namespace": body["namespace"], "data": body["data"]}
            if "schema" in body:
                nonempty(body["schema"], "Schema identifier")
                entry["schema"] = body["schema"]
            state.statements.append(entry)
        elif kind == "governance.rotate":
            obj(body, "Governance rotation")
            validate_governance(body.get("governance"))
            if state.next_governance_commitment:
                check(charter_governance_commitment(body["governance"]) == state.next_governance_commitment,
                      "Rotation violates governance commitment")
            if "next_governance_commitment" in body:
                valid_hash(body["next_governance_commitment"])
            state.governance = clone(body["governance"])
            state.next_governance_commitment = body.get("next_governance_commitment")
        elif kind in ("opkey.delegate", "opkey.revoke"):
            obj(body, "Operational key")
            valid_id(body.get("kid"))
            if kind == "opkey.delegate":
                nonempty(body.get("scope"), "Scope")
                delegation = {"scope": body["scope"]}
                if "expires_at" in body:
                    timestamp(body["expires_at"])
                    delegation["expires_at"] = body["expires_at"]
                state.operational_keys[body["kid"]] = delegation
            else:
                check(body["kid"] in state.operational_keys, "Operational key is not delegated")
                del state.operational_keys[body["kid"]]
        elif kind == "agent.successor":
            obj(body, "Successor")
            valid_id(body.get("agent_id"))
            check(body["agent_id"] != agent_id, "Successor must be a different agent")
            state.successor = body["agent_id"]
        elif kind == "agent.decommission":
            state.decommissioned = True
        state.sequence = size(signed["seq"])
        state.head_hash = charter_statement_hash(statement)
    return state
