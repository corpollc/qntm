"""Shared Python/TypeScript governance hashing contract for optional fields."""
import json
from pathlib import Path

import pytest

from qntm.governance import hash_proposal_body


CASES = json.loads((Path(__file__).resolve().parents[2] / "specs/test-vectors/governance-optional-fields.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_optional_governance_field_hash_matches_typescript(case):
    assert hash_proposal_body(case["body"]).hex() == case["hash_hex"]


def test_absent_and_null_branches_have_distinct_signed_meanings():
    assert hash_proposal_body(CASES[0]["body"]) != hash_proposal_body(CASES[1]["body"])
