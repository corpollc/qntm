#!/usr/bin/env python3
"""Verify ArkForge execution attestation test vectors (CTEF v0.3.1).

Reproduces canonical JSON + SHA-256 for each vector and checks byte-exact match.
Zero dependencies beyond Python stdlib.
"""
import json, hashlib, sys
from pathlib import Path

VECTORS_FILE = Path(__file__).parent / "execution-attestation-arkforge.json"

def canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def main():
    data = json.loads(VECTORS_FILE.read_text())
    vector_keys = [k for k in data if isinstance(data[k], dict) and "input_object" in data[k]]
    passed = 0
    failed = 0

    for key in vector_keys:
        v = data[key]
        inp = v["input_object"]
        expected_canonical = v["canonical_bytes_utf8"]
        expected_sha = v["canonical_sha256"]

        computed_canonical = canonical_json(inp)
        computed_sha = hashlib.sha256(computed_canonical.encode("utf-8")).hexdigest()

        canonical_match = computed_canonical == expected_canonical
        sha_match = computed_sha == expected_sha

        if canonical_match and sha_match:
            print(f"  PASS  {key}")
            passed += 1
        else:
            print(f"  FAIL  {key}")
            if not canonical_match:
                print(f"        canonical mismatch")
            if not sha_match:
                print(f"        sha256: got {computed_sha}, expected {expected_sha}")
            failed += 1

    print(f"\n{passed}/{passed + failed} vectors pass")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
