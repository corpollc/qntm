"""Real Python peer for the mandatory TypeScript/Go charter journey (test keys only)."""

import copy
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qntm.charter import (
    CharterError, CharterRegistryClient, CharterRegistryError, audit_charter_snapshot,
    charter_agent_id, charter_key, create_charter, create_charter_statement,
    sign_charter_statement, verify_charter_chain_response, verify_charter_consistency,
    verify_charter_heads, verify_charter_inclusion, verify_charter_receipt,
)


def identity(seed):
    seed = bytes.fromhex(seed)
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return {"privateKey": seed + public_key, "publicKey": public_key}


def rejected(operation):
    try:
        operation()
    except CharterError:
        return
    raise AssertionError("Invalid charter evidence was accepted")


def main():
    request = json.load(sys.stdin)
    trust = request["trust"]
    parent = identity(request["parent_seed"])
    child = identity("5b" * 32)
    parent_id, child_id = charter_agent_id(parent["publicKey"]), charter_agent_id(child["publicKey"])
    with CharterRegistryClient(request["base"], trust) as client:
        if request["action"] == "bootstrap":
            parent_record = client.chain(parent_id).record
            assert parent_record.governance["keys"] == [charter_key(parent["publicKey"])]
            verify_charter_receipt(request["parent_receipt"], request["parent_charter"], trust)
            genesis = create_charter(
                registry=trust["registry"], agent=child,
                governance={"keys": [charter_key(parent["publicKey"])], "threshold": 1},
                agent_rights=["statement", "liveness.update"],
                extensions={"unregistered.art": {"ideas": ["gardens", "🎨", None], "numbers": [1e-7, 333333333.33333329]}},
            )
            try:
                client.submit(genesis)
                raise AssertionError("Missing parent acceptance succeeded")
            except CharterRegistryError as exc:
                assert (exc.status, exc.code) == (422, "authority_rejected")
            genesis = sign_charter_statement(genesis, parent)
            first = client.submit(genesis)
            statement = sign_charter_statement(create_charter_statement(genesis, "statement", {
                "namespace": "unregistered.art/experiment", "data": {"10": 10, "2": 2, "governance": None},
            }), child)
            receipt = client.submit(statement)
            verify_charter_receipt(first, genesis, trust)
            client.consistency(first["heads"], receipt["heads"])
            print(json.dumps({"agent_id": child_id, "child_key": charter_key(child["publicKey"]), "statement": statement, "receipt": receipt}))
        elif request["action"] == "transition":
            result = client.chain(child_id)
            assert result.record.sequence == 2 and result.record.governance["threshold"] == 2
            statement = sign_charter_statement(create_charter_statement(result.evidence["chain"][-1], "constitution.amend", {
                "values": ["curiosity", "care"], "source": "python",
            }), child)
            try:
                client.submit(statement)
                raise AssertionError("Insufficient threshold accepted")
            except CharterRegistryError as exc:
                assert (exc.status, exc.code) == (422, "authority_rejected")
            statement = sign_charter_statement(statement, parent)
            receipt = client.submit(statement)
            try:
                client.submit(statement)
                raise AssertionError("Duplicate accepted")
            except CharterRegistryError as exc:
                assert (exc.status, exc.code) == (409, "sequence_conflict")
            changed = copy.deepcopy(statement)
            changed["signed"]["body"]["source"] = "forged"
            rejected(lambda: verify_charter_receipt(receipt, changed, trust))
            print(json.dumps({"receipt": receipt, "statement": statement}))
        elif request["action"] == "documentation":
            readme = (Path(__file__).resolve().parents[2] / "charter-registry/README.md").read_text()
            section = readme.split("## Python client\n", 1)[1].split("## Reference HTTP profile", 1)[0]
            code = re.search(r"```python\n(.*?)```", section, re.S).group(1)
            scope = {"configured_registry_url": request["base"], "configured_registry_id": trust["registry"],
                     "configured_registrar_key": trust["registrar"]}
            exec(compile(code, "charter-registry/README.md", "exec"), scope)
            assert scope["result"].record.statements[0]["data"] == {"collaboration": "welcome"}
            print(json.dumps({"sequence": scope["result"].record.sequence}))
        elif request["action"] == "audit":
            latest = client.heads()
            assert latest == request["heads"]
            assert client.chain(child_id).record.constitution["source"] == "python"
            entries = client.log(latest)
            audit_charter_snapshot(entries, latest, trust)
            altered = copy.deepcopy(entries)
            altered[0]["received_at"] = "2000-01-01T00:00:00Z"
            rejected(lambda: audit_charter_snapshot(altered, latest, trust))
            checkpoints = []
            for count in range(latest["log"]["signed"]["tree_size"] + 1):
                heads = client.heads(count)
                checkpoints.append(heads)
                for index in range(count):
                    evidence = client._request(f"/v1/inclusion/{index}?size={count}")
                    verify_charter_heads(evidence["heads"], trust)
                    verify_charter_inclusion(evidence["inclusion"], heads["log"]["signed"])
                    bad = copy.deepcopy(evidence["inclusion"])
                    bad["siblings"].append("0" * 64)
                    rejected(lambda: verify_charter_inclusion(bad, heads["log"]["signed"]))
                for agent_id in (parent_id, child_id, "0" * 32, "f" * 32):
                    result = client.chain(agent_id, count)
                    if agent_id in ("0" * 32, "f" * 32):
                        assert result.record is None
            for before in checkpoints:
                for after in checkpoints[before["log"]["signed"]["tree_size"]:]:
                    proof = client.consistency(before, after)
                    if proof:
                        bad = ["0" * 64, *proof[1:]]
                        rejected(lambda: verify_charter_consistency(before["log"]["signed"], after["log"]["signed"], bad))
            rejected(lambda: client.consistency(latest, checkpoints[0]))
            complete = client.chain(child_id).evidence
            truncated = copy.deepcopy(complete)
            truncated["chain"].pop()
            rejected(lambda: verify_charter_chain_response(truncated, trust, child_id))
            hidden = copy.deepcopy(complete)
            hidden["chain"] = []
            hidden["proof"]["present"] = False
            rejected(lambda: verify_charter_chain_response(hidden, trust, child_id))
            wrong = copy.deepcopy(trust)
            wrong["registry"] = "other.registry"
            rejected(lambda: verify_charter_heads(latest, wrong))
            wrong["registry"] = trust["registry"]
            wrong["registrar"] = charter_key(parent["publicKey"])
            rejected(lambda: verify_charter_heads(latest, wrong))
            print(json.dumps({"audited_entries": len(entries), "historical_snapshots": len(checkpoints)}))
        else:
            raise AssertionError("Unknown action")


if __name__ == "__main__":
    main()
