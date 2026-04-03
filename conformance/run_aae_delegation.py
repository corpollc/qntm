#!/usr/bin/env python3
"""
run_aae_delegation.py — Conformance runner for MolTrust AAE delegation narrowing vectors.

Tests 5 delegation invariants from qntm Authority Constraints Interface spec (PR #11):
  - TV-001: Valid narrowed delegation (VALID baseline)
  - TV-002: Scope escalation rejection (SCOPE_ESCALATION)
  - TV-003: Validity window extension rejection (VALIDITY_ESCALATION)
  - TV-004: Self-issuance rejection (SELF_ISSUANCE)
  - TV-005: Expired credential rejection (EXPIRED)

No crypto dependencies — these are semantic invariants, not byte-level encoding checks.
(Contrast sv-sig-01 which requires cryptography/PyNaCl for round-trip verification.)

Usage:
    python3 run_aae_delegation.py [path/to/vectors.json]

Exit 0: all assertions pass
Exit 1: one or more failures
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def _dt(s: str) -> datetime:
    """Parse ISO 8601 UTC timestamp. Accepts trailing Z or +00:00."""
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ── Invariant checkers ────────────────────────────────────────────────────────

def check_tv001(v) -> tuple[str, str | None]:
    """TV-001: all delegation constraints must narrow or equal parent values."""
    p, c = v["parent"], v["child"]

    # Scope: child ⊆ parent
    p_scope = set(p["mandate"]["scope"])
    c_scope = set(c["mandate"]["scope"])
    over = c_scope - p_scope
    if over:
        return "INVALID", f"SCOPE_ESCALATION: {sorted(over)} not in parent"

    # Spend: child ≤ parent
    p_spend = p["constraints"]["spend_limit_usdc"]
    c_spend = c["constraints"]["spend_limit_usdc"]
    if c_spend > p_spend:
        return "INVALID", f"SPEND_ESCALATION: {c_spend} > {p_spend}"

    # Validity: child not_after ≤ parent not_after
    p_exp = _dt(p["validity"]["not_after"])
    c_exp = _dt(c["validity"]["not_after"])
    if c_exp > p_exp:
        return "INVALID", f"VALIDITY_ESCALATION: child expires {c_exp} after parent {p_exp}"

    return "VALID", None


def check_tv002(v) -> tuple[str, str | None]:
    """TV-002: scope escalation must be rejected."""
    p, c = v["parent"], v["child"]
    p_scope = set(p["mandate"]["scope"])
    c_scope = set(c["mandate"]["scope"])
    over = c_scope - p_scope
    if over:
        return "INVALID", "SCOPE_ESCALATION"
    return "VALID", None


def check_tv003(v) -> tuple[str, str | None]:
    """TV-003: validity window extension must be rejected."""
    p_exp = _dt(v["parent"]["validity"]["not_after"])
    c_exp = _dt(v["child"]["validity"]["not_after"])
    if c_exp > p_exp:
        return "INVALID", "VALIDITY_ESCALATION"
    return "VALID", None


def check_tv004(v) -> tuple[str, str | None]:
    """TV-004: self-issuance (subject == issuer) must be rejected."""
    modified = v["modified"]
    if modified["subject"] == modified["issuer"]:
        return "INVALID", "SELF_ISSUANCE"
    return "VALID", None


def check_tv005(v) -> tuple[str, str | None]:
    """TV-005: expired AAE must be rejected at evaluation_time."""
    not_after = _dt(v["aae"]["validity"]["not_after"])
    eval_time = _dt(v["evaluation_time"])   # pinned in vector; runner does NOT use now()
    if eval_time > not_after:
        return "INVALID", "EXPIRED"
    return "VALID", None


CHECKERS = {
    "moltrust-tv-001": check_tv001,
    "moltrust-tv-002": check_tv002,
    "moltrust-tv-003": check_tv003,
    "moltrust-tv-004": check_tv004,
    "moltrust-tv-005": check_tv005,
}


# ── Runner ────────────────────────────────────────────────────────────────────

def run(vectors_path: str) -> None:
    data = json.loads(Path(vectors_path).read_text())
    vectors = data["vectors"]

    passed = 0
    total = len(vectors)

    for v in vectors:
        vid = v["id"]
        checker = CHECKERS.get(vid)
        if not checker:
            print(f"SKIP  {vid:35s}  (no checker)")
            total -= 1
            continue

        outcome, reason = checker(v)

        expected_outcome = v.get("expected_outcome", "VALID")
        expected_reason = v.get("failure_reason")   # None for VALID cases

        outcome_ok = outcome == expected_outcome
        reason_ok = expected_reason is None or reason == expected_reason
        ok = outcome_ok and reason_ok

        if ok:
            passed += 1
            print(f"PASS  {vid:35s}  {outcome}  {reason or ''}")
        else:
            detail = []
            if not outcome_ok:
                detail.append(f"outcome: expected {expected_outcome!r} got {outcome!r}")
            if not reason_ok:
                detail.append(f"reason: expected {expected_reason!r} got {reason!r}")
            print(f"FAIL  {vid:35s}  {outcome}  — {'; '.join(detail)}")

    print(f"\n{passed}/{total} assertions passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "moltrust-aae-delegation-narrowing.json"
    run(path)
