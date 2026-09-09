"""Pinned registrar signatures, Merkle evidence and full snapshot audits."""

import hashlib
from functools import wraps
from typing import TypedDict

from .core import (CharterKey, CharterRecord, CharterStatement, charter_agent_id,
                   charter_statement_hash, check, obj, replay_charter_chain, size,
                   timestamp, valid_hash, valid_id, wire)
from .crypto import verify_charter_signature
from .json import CharterError, charter_json_bytes, canonicalize_charter_json


class CharterTrust(TypedDict):
    registry: str
    registrar: CharterKey


EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _evidence(function):
    @wraps(function)
    def verify(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (KeyError, TypeError, IndexError, AttributeError) as exc:
            raise CharterError("Malformed charter evidence") from exc
    return verify


def _leaf(value) -> str:
    return hashlib.sha256(b"\x00" + charter_json_bytes(value)).hexdigest()


def _node(left: str, right: str) -> str:
    valid_hash(left)
    valid_hash(right)
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _split(count: int) -> int:
    return 1 << ((count - 1).bit_length() - 1)


@_evidence
def verify_charter_heads(heads: dict, trust: CharterTrust) -> None:
    """Authenticate both heads with a caller-supplied registrar pin and audience."""
    charter_json_bytes(heads)
    public_key = wire(trust["registrar"]["pubkey"], 32)
    check(charter_agent_id(public_key) == trust["registrar"]["kid"] and
          type(trust["registry"]) is str and len(trust["registry"]) > 0, "Invalid registrar pin")
    for head in (heads["log"], heads["epoch"]):
        signed = obj(head["signed"], "Signed head")
        check(signed["registry"] == trust["registry"] and head["kid"] == trust["registrar"]["kid"],
              "Head audience or signing key mismatch")
        check(verify_charter_signature(public_key, charter_json_bytes(signed), wire(head["sig"], 64)),
              "Invalid registrar head signature")
        timestamp(signed["timestamp"])
    log, epoch = heads["log"]["signed"], heads["epoch"]["signed"]
    check(log["kind"] == "charter.log" and epoch["kind"] == "charter.epoch", "Head domain mismatch")
    for number in (log["tree_size"], epoch["map_size"], epoch["log_size"], epoch["epoch"]):
        size(number)
    for root in (log["root_hash"], epoch["map_root"], epoch["log_root"]):
        valid_hash(root)
    check(epoch["epoch"] == epoch["map_size"] == epoch["log_size"] == log["tree_size"] and
          epoch["log_root"] == log["root_hash"] and epoch["timestamp"] == log["timestamp"],
          "Epoch/log binding mismatch")
    if log["tree_size"] == 0:
        check(log["root_hash"] == epoch["map_root"] == EMPTY_ROOT, "Invalid empty tree roots")


def _inclusion_root(leaf_hash: str, index: int, count: int, siblings: list[str]) -> str:
    index, count = size(index), size(count)
    check(count > 0 and index < count and type(siblings) is list and len(siblings) <= 53,
          "Invalid inclusion index/path")
    used = 0

    def visit(i: int, n: int) -> str:
        nonlocal used
        if n == 1:
            return leaf_hash
        split = _split(n)
        child = visit(i, split) if i < split else visit(i - split, n - split)
        check(used < len(siblings), "Truncated inclusion path")
        sibling = siblings[used]
        used += 1
        valid_hash(sibling)
        return _node(child, sibling) if i < split else _node(sibling, child)

    root = visit(index, count)
    check(used == len(siblings), "Extra inclusion path elements")
    return root


@_evidence
def verify_charter_inclusion(proof: dict, head: dict) -> None:
    """Caller must first authenticate the log head with verify_charter_heads."""
    timestamp(proof["entry"]["received_at"])
    check(_inclusion_root(_leaf(proof["entry"]), proof["index"], head["tree_size"], proof["siblings"]) == head["root_hash"],
          "Log inclusion proof mismatch")


@_evidence
def verify_charter_consistency(older: dict, newer: dict, proof: list[str]) -> None:
    """Prove append-only growth between already-authenticated log heads."""
    first, last = size(older["tree_size"]), size(newer["tree_size"])
    valid_hash(older["root_hash"])
    valid_hash(newer["root_hash"])
    check(older["registry"] == newer["registry"] and older["kind"] == newer["kind"] == "charter.log" and first <= last,
          "Invalid consistency head range")
    check(type(proof) is list and len(proof) <= 54, "Invalid consistency path")
    if first == 0:
        check(older["root_hash"] == EMPTY_ROOT and not proof and (last != 0 or newer["root_hash"] == EMPTY_ROOT),
              "Invalid empty consistency proof")
        return
    used = 0

    def take() -> str:
        nonlocal used
        check(used < len(proof), "Truncated consistency proof")
        value = proof[used]
        used += 1
        valid_hash(value)
        return value

    def visit(m: int, n: int, complete: bool) -> tuple[str, str]:
        if m == n:
            root = older["root_hash"] if complete else take()
            return root, root
        split = _split(n)
        if m <= split:
            a, b = visit(m, split, complete)
            return a, _node(b, take())
        a, b = visit(m - split, n - split, False)
        left = take()
        return _node(left, a), _node(left, b)

    before, after = visit(first, last, True)
    check(used == len(proof) and before == older["root_hash"] and after == newer["root_hash"],
          "Log consistency proof mismatch")


def _map_witness(witness: dict, head: dict) -> None:
    leaf = witness["leaf"]
    valid_id(leaf["agent_id"])
    size(leaf["seq"])
    valid_hash(leaf["statement_hash"])
    check(_inclusion_root(_leaf(leaf), witness["index"], head["map_size"], witness["siblings"]) == head["map_root"],
          "Map inclusion proof mismatch")


@_evidence
def verify_charter_chain_response(response: dict, trust: CharterTrust, agent_id: str) -> CharterRecord | None:
    """Prove completeness or absence, then replay every authority transition."""
    valid_id(agent_id)
    verify_charter_heads(response["heads"], trust)
    proof, head = response["proof"], response["heads"]["epoch"]["signed"]
    check(proof["agent_id"] == agent_id and type(proof["present"]) is bool and type(response["chain"]) is list,
          "Range proof audience/shape mismatch")
    left, right = proof["left"], proof["right"]
    if left is not None:
        _map_witness(left, head)
    if right is not None:
        _map_witness(right, head)
    if left is None and right is None:
        check(head["map_size"] == 0 and head["map_root"] == EMPTY_ROOT, "Missing range witnesses")
    elif left is None:
        check(right["index"] == 0, "Invalid lower tree boundary")
    elif right is None:
        check(left["index"] == head["map_size"] - 1, "Invalid upper tree boundary")
    else:
        check(left["index"] + 1 == right["index"], "Range witnesses are not adjacent")
    if right is not None:
        check(right["leaf"]["agent_id"] > agent_id, "Successor does not bound agent range")
    if not proof["present"]:
        check(not response["chain"] and (left is None or left["leaf"]["agent_id"] < agent_id),
              "Invalid non-membership proof")
        return None
    check(left is not None and left["leaf"]["agent_id"] == agent_id and len(response["chain"]) == left["leaf"]["seq"] + 1,
          "Incomplete charter chain")
    state = replay_charter_chain(response["chain"], registry=trust["registry"], agent_id=agent_id)
    check(state.head_hash == left["leaf"]["statement_hash"], "Chain head does not match map")
    return state


@_evidence
def verify_charter_receipt(receipt: dict, statement: CharterStatement, trust: CharterTrust) -> None:
    verify_charter_heads(receipt["heads"], trust)
    check(statement["signed"]["registry"] == trust["registry"] and
          receipt["statement_hash"] == charter_statement_hash(statement) and
          receipt["index"] == receipt["inclusion"]["index"] and
          canonicalize_charter_json(receipt["inclusion"]["entry"]["statement"]) == canonicalize_charter_json(statement),
          "Receipt is for a different statement")
    verify_charter_inclusion(receipt["inclusion"], receipt["heads"]["log"]["signed"])


@_evidence
def audit_charter_snapshot(entries: list[dict], heads: dict, trust: CharterTrust) -> None:
    """Authenticate every chain and recompute the chronological log and sorted map."""
    verify_charter_heads(heads, trust)
    check(type(entries) is list and len(entries) == heads["log"]["signed"]["tree_size"], "Snapshot log length mismatch")
    chains = {}
    leaves = []
    hashes = []
    for entry in entries:
        timestamp(entry["received_at"])
        statement = entry["statement"]
        signed = statement["signed"]
        chains.setdefault(signed["agent_id"], []).append(statement)
        leaves.append({"agent_id": signed["agent_id"], "seq": signed["seq"], "statement_hash": charter_statement_hash(statement)})
        hashes.append(_leaf(entry))
    for agent_id, chain in chains.items():
        replay_charter_chain(chain, registry=trust["registry"], agent_id=agent_id)
    leaves.sort(key=lambda value: (value["agent_id"], value["seq"]))

    def root(values: list[str]) -> str:
        if not values:
            return EMPTY_ROOT
        if len(values) == 1:
            return values[0]
        split = _split(len(values))
        return _node(root(values[:split]), root(values[split:]))

    check(root(hashes) == heads["log"]["signed"]["root_hash"] and root([_leaf(v) for v in leaves]) == heads["epoch"]["signed"]["map_root"],
          "Snapshot log/map mismatch")
