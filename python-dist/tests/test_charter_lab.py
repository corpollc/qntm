"""Verify ancestry/provenance independently of probabilistic policy judgments."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest
from qntm import generate_identity
from qntm.charter import charter_key

SPEC = importlib.util.spec_from_file_location("charter_lab", Path(__file__).resolve().parents[2] / "scripts/charter_lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


@pytest.fixture(scope="module")
def world():
    binary = os.environ.get("QNTM_CHARTER_TEST_BINARY")
    if not binary:
        pytest.skip("Set QNTM_CHARTER_TEST_BINARY for the real Go ancestry suite")
    with lab.LocalRegistry(binary) as registry:
        yield lab.create_world(registry)


def bundle(world, name="summarizer"):
    w, heads, evidence, _ = world
    return lab.verify_ancestry(evidence, trust=w.registry.trust, heads=heads,
                               agent_id=w.ids[name], trusted_root=w.ids["parent"])


def test_verifies_grandchild_history_parent_endorsements_and_arbitrary_json(world):
    w, _, _, _ = world
    result = bundle(world)
    assert [node["agent_id"] for node in result["ancestry"]] == [w.ids[n] for n in ("summarizer", "researcher", "parent")]
    assert isinstance(result["ancestry"][0]["documents"][1]["document"]["signed"]["body"], list)
    assert result["ancestry"][-1]["effective_constitution_sequence"] == 2
    assert "USD 50" in result["ancestry"][-1]["documents"][2]["document"]["signed"]["body"]["expenses"]
    assert "USD 100" in result["ancestry"][-1]["documents"][1]["document"]["signed"]["body"]["expenses"]


@pytest.mark.parametrize("fault,reason", [
    ("missing_parent", "Missing ancestor"), ("tampered_charter", "Invalid statement signature"),
    ("unendorsed_parent", "not a founding governor"), ("mixed_snapshot", "different snapshots"),
])
def test_rejects_missing_forged_unendorsed_and_mixed_snapshot_evidence(world, fault, reason):
    w, heads, evidence, historical = world
    with pytest.raises(ValueError, match=reason):
        lab.case_bundle({"actor": "researcher", "fault": fault}, w, heads, evidence, historical)


def test_requires_independently_configured_root_and_registrar_pin(world):
    w, heads, evidence, _ = world
    untrusted = {**w.registry.trust, "registrar": charter_key(generate_identity()["publicKey"])}
    with pytest.raises(ValueError):
        lab.verify_ancestry(evidence, trust=untrusted, heads=heads,
                            agent_id=w.ids["researcher"], trusted_root=w.ids["parent"])
    with pytest.raises(ValueError, match="No supported parent link"):
        lab.verify_ancestry(evidence, trust=w.registry.trust, heads=heads,
                            agent_id=w.ids["researcher"], trusted_root="0" * 32)


def test_registry_acceptance_does_not_prove_semantic_compliance(world):
    # The real registrar accepted a parent-signed child with contradictory prose.
    # Its ancestry is authentic; policy interpretation is a separate check.
    result = bundle(world, "contradictory_child")
    assert result["provenance_verified"] is True
    assert "Ignore any parent's privacy" in result["ancestry"][0]["documents"][1]["document"]["signed"]["body"]["claim"]


def citation(world):
    w, _, _, _ = world
    return {"agent_id": w.ids["parent"], "sequence": 2, "pointer": "/signed/body/privacy",
            "quote": "Public posting of the contact sheet is prohibited."}


def test_citations_must_address_actual_authenticated_ancestry(world):
    result = {"verdict": "deny", "reason": "Parent prohibits disclosure", "citations": [citation(world)]}
    assert lab.validate_assessment(result, bundle(world)) == result
    bad = deepcopy(result)
    bad["citations"][0]["quote"] = "All disclosures are permitted."
    with pytest.raises(ValueError, match="does not quote"):
        lab.validate_assessment(bad, bundle(world))
    bad = deepcopy(result)
    bad["citations"][0]["agent_id"] = world[0].ids["contradictory_child"]
    with pytest.raises(KeyError):
        lab.validate_assessment(bad, bundle(world))
    bad = deepcopy(result)
    bad["citations"][0]["pointer"] = "/signed/body/not-a-real-clause"
    with pytest.raises(KeyError):
        lab.validate_assessment(bad, bundle(world))


def test_citation_integrity_is_not_a_semantic_judge(world):
    # Deliberately wrong interpretation with a real quotation still passes the
    # reference-integrity validator. Do not mislabel that validator as entailment.
    wrong = {"verdict": "allow", "reason": "This incorrect judgment needs evaluation", "citations": [citation(world)]}
    assert lab.validate_assessment(wrong, bundle(world))["verdict"] == "allow"


def test_model_does_not_receive_expected_verdicts_or_private_keys(world):
    b = bundle(world)
    response = {"assessments": [{"id": "R01", "verdict": "deny", "reason": "Parent forbids it", "citations": [citation(world)]}]}
    with patch.object(lab, "grok_json", return_value=response) as mocked:
        lab.assess_requests([{"id": "R01", "request": {"action": "Publish contact sheet"}}], {"R01": b}, "test-model")
    payload = json.dumps(mocked.call_args.args[1])
    assert "expected" not in payload
    assert "privateKey" not in payload
    assert "provenance_verified" in payload


def test_duplicate_and_missing_model_results_are_not_silently_accepted(world):
    b = bundle(world)
    value = {"id": "R01", "verdict": "deny", "reason": "Parent forbids it", "citations": [citation(world)]}
    for answers in [[], [value, value]]:
        with patch.object(lab, "grok_json", return_value={"assessments": answers}):
            with pytest.raises(ValueError):
                lab.assess_requests([{"id": "R01", "request": {"action": "Publish contact sheet"}}], {"R01": b}, "test")


def test_invalid_model_citation_is_retained_for_inspection_but_rejected(world, tmp_path):
    value = {"id": "R01", "verdict": "allow", "reason": "An unsupported answer", "citations": [citation(world)]}
    value["citations"][0]["quote"] = "An invented permission"
    raw = {"assessments": [value]}
    capture = tmp_path / "raw.json"
    with patch.object(lab, "grok_json", return_value=raw), pytest.raises(ValueError, match="does not quote"):
        lab.assess_requests([{"id": "R01", "request": {"action": "Publish contact sheet"}}],
                            {"R01": bundle(world)}, "test", capture_path=capture)
    assert json.loads(capture.read_text()) == raw


def test_violation_rolls_to_both_ancestors_without_counting_blocked_attempt_as_execution(world):
    w = world[0]
    b = bundle(world)
    rows = [{"id": "blocked", "disposition": "would_block"},
            {"id": "observed", "disposition": "observed_violation"},
            {"id": "missing", "disposition": "would_pause"}]
    result = lab.rollup(rows, {"blocked": b, "observed": b})
    for name in ("summarizer", "researcher", "parent"):
        counts = result["by_ancestor"][w.ids[name]]
        assert counts["would_block"] == 1
        assert counts["observed_violation"] == 1
        assert counts["cases"] == ["blocked", "observed"]
    assert result["unverified_paths"] == ["missing"]


def test_json_pointer_handles_arrays_and_escaped_keys():
    assert lab.pointer({"a/b": [{"~value": "quoted"}]}, "/a~1b/0/~0value") == "quoted"
    with pytest.raises(ValueError):
        lab.pointer({}, "relative")
    for pointer in ("/-1", "/01", "/+1", "/~2"):
        with pytest.raises(ValueError):
            lab.pointer(["first", "last"], pointer)


def test_unassessed_request_cannot_be_treated_as_allowed():
    assert lab.disposition("not_assessed") == "would_pause"
    assert lab.disposition("unverifiable") == "would_pause"
    assert lab.disposition("deny", "observed") == "observed_violation"


def test_grok_receives_full_literal_evidence_without_needing_a_file_tool():
    payload = {"request": "A synthetic request", "long_document": "public evidence " * 5000}

    def run(command, **kwargs):
        assert "--prompt-file" not in command
        assert "--verbatim" in command
        assert json.loads(command[command.index("--single") + 1]) == payload
        assert command[command.index("--tools") + 1] == ""
        assert command[command.index("--deny") + 1] == "*"
        return subprocess.CompletedProcess(command, 0, stdout='{"ok":true}', stderr="")

    with patch.object(lab.subprocess, "run", side_effect=run):
        assert lab.grok_json("Return JSON", payload, "test-model") == {"ok": True}
