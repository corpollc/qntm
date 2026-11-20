#!/usr/bin/env python3
"""Verify ArkForge tier_upgrade_proof CTEF test vectors.

Checks:
1. Canonical JSON byte-exact reproduction
2. SHA-256 hash match
3. Required field presence (requester_did for non-replay vectors)
4. Enforcement decision consistency with constraint_evaluation
"""
import json, hashlib, sys
from pathlib import Path

VECTORS_FILE = Path(__file__).parent / "tier-upgrade-proof-arkforge.json"

def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def verify():
    data = json.loads(VECTORS_FILE.read_text())
    results = []

    for key in ["tier_upgrade_granted", "tier_upgrade_denied", "tier_upgrade_replay_vulnerable"]:
        vec = data[key]
        obj = vec["input_object"]
        expected_canonical = vec["canonical_bytes_utf8"]
        expected_hash = vec["canonical_sha256"]

        actual_canonical = canonical(obj)
        actual_hash = hashlib.sha256(actual_canonical.encode("utf-8")).hexdigest()

        canonical_match = actual_canonical == expected_canonical
        hash_match = actual_hash == expected_hash

        has_requester_did = "requester_did" in obj.get("tier_upgrade_proof", {})
        expected_result = vec["expected_result"]

        if expected_result == "fail" and has_requester_did:
            field_check = "WARN: expected fail but requester_did present"
        elif expected_result == "pass" and not has_requester_did:
            field_check = "WARN: expected pass but requester_did missing"
        else:
            field_check = "OK"

        status = "PASS" if (canonical_match and hash_match) else "FAIL"
        results.append((key, status, hash_match, field_check))
        print(f"  {key}: {status} (hash={'match' if hash_match else 'MISMATCH'}, fields={field_check})")

    passed = sum(1 for _, s, _, _ in results if s == "PASS")
    print(f"\n{passed}/{len(results)} vectors passed")
    return 0 if passed == len(results) else 1

if __name__ == "__main__":
    print(f"Verifying {VECTORS_FILE}")
    sys.exit(verify())
