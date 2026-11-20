"""Verify canonical-bytes pre-fix/post-fix diff test vector (CTEF v0.3.2).

Validates three properties:
1. Pre-fix (string concat) and post-fix (canonical JSON) produce different chain hashes
2. Preimage ambiguity exists in concatenation approach (collision confirmed)
3. Canonical JSON is immune to the collision class
"""
import json
import hashlib
from pathlib import Path


def canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def strip_prefix(h: str) -> str:
    return h.replace("sha256:", "")


def main():
    vector_path = Path(__file__).parent / "canonical-bytes-diff-v032.json"
    with open(vector_path) as f:
        v = json.load(f)

    c = v["components"]

    # 1. Verify pre-fix chain hash (string concatenation)
    legacy_input = (
        c["request_hash"]
        + c["response_hash"]
        + c["transaction_id"]
        + c["timestamp"]
        + c["buyer_fingerprint"]
        + c["seller"]
    )
    legacy_hash = sha256_hex(legacy_input)
    assert legacy_hash == strip_prefix(v["pre_fix"]["chain_hash"]), "pre-fix hash mismatch"
    assert legacy_input.encode("utf-8").hex() == v["pre_fix"]["canonical_bytes_hex"], "pre-fix bytes mismatch"

    # 2. Verify post-fix chain hash (canonical JSON)
    canonical_data = {
        "request_hash": c["request_hash"],
        "response_hash": c["response_hash"],
        "transaction_id": c["transaction_id"],
        "timestamp": c["timestamp"],
        "buyer_fingerprint": c["buyer_fingerprint"],
        "seller": c["seller"],
    }
    canonical_bytes = canonical_json(canonical_data)
    canonical_hash = sha256_hex(canonical_bytes)
    assert canonical_hash == strip_prefix(v["post_fix"]["chain_hash"]), "post-fix hash mismatch"
    assert canonical_bytes == v["post_fix"]["canonical_bytes_utf8"], "post-fix bytes mismatch"

    # 3. Confirm divergence
    assert legacy_hash != canonical_hash, "hashes should diverge"

    # 4. Verify preimage ambiguity collision
    amb = v["preimage_ambiguity_proof"]
    ext_input = legacy_input + amb["original"]["upstream_timestamp"]
    ext_hash = sha256_hex(ext_input)
    assert ext_hash == strip_prefix(amb["original"]["chain_hash"]), "extended hash mismatch"

    collision_input = (
        c["request_hash"]
        + c["response_hash"]
        + c["transaction_id"]
        + c["timestamp"]
        + c["buyer_fingerprint"]
        + amb["collision"]["seller"]
        + amb["collision"]["upstream_timestamp"]
    )
    collision_hash = sha256_hex(collision_input)
    assert collision_hash == ext_hash, "collision should produce same hash"
    assert collision_hash == strip_prefix(amb["collision"]["chain_hash"]), "collision hash mismatch"

    # 5. Verify canonical JSON is immune
    canonical_original = canonical_json({
        **canonical_data,
        "upstream_timestamp": amb["original"]["upstream_timestamp"],
    })
    canonical_collision = canonical_json({
        "request_hash": c["request_hash"],
        "response_hash": c["response_hash"],
        "transaction_id": c["transaction_id"],
        "timestamp": c["timestamp"],
        "buyer_fingerprint": c["buyer_fingerprint"],
        "seller": amb["collision"]["seller"],
        "upstream_timestamp": amb["collision"]["upstream_timestamp"],
    })
    assert sha256_hex(canonical_original) != sha256_hex(canonical_collision), (
        "canonical JSON should NOT produce collision"
    )

    print("All 5 checks passed.")
    print(f"  Pre-fix hash:  sha256:{legacy_hash}")
    print(f"  Post-fix hash: sha256:{canonical_hash}")
    print(f"  Collision confirmed: {collision_hash == ext_hash}")
    print(f"  Canonical immune:    {sha256_hex(canonical_original) != sha256_hex(canonical_collision)}")


if __name__ == "__main__":
    main()
