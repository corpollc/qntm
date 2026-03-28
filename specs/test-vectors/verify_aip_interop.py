#!/usr/bin/env python3
"""
AIP ↔ qntm key derivation interop test.

Verifies that AIP Ed25519 identities can derive X25519 keys
compatible with qntm's encrypted transport layer.

Requirements: pip install PyNaCl
Usage: python verify_aip_interop.py

This script verifies the cryptographic bridge between AIP's Ed25519
identity system and qntm's X25519-based encrypted messaging.
Both projects use PyNaCl (libsodium) — this confirms the derivation
path is byte-for-byte identical.
"""

import sys

try:
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: pip install PyNaCl")
    sys.exit(1)

# Known-answer vectors computed with PyNaCl (libsodium)
# Same library used by both AIP (aip_identity) and qntm
VECTORS = [
    {
        "name": "Vector 1 (RFC 8032 seed #1)",
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "ed25519_pub": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "x25519_pub": "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e",
    },
    {
        "name": "Vector 2 (RFC 8032 seed #2)",
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "ed25519_pub": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "x25519_pub": "25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47",
    },
    {
        "name": "Vector 3 (RFC 8032 seed #3)",
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "ed25519_pub": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "x25519_pub": "cbb22fc9f790bd3eba9b84680c157ca4950a9894362601701f89c3c4d9fda23a",
    },
]

passed = 0
failed = 0

for v in VECTORS:
    seed = bytes.fromhex(v["seed"])
    sk = SigningKey(seed)

    # Verify Ed25519 public key
    ed_pub = bytes(sk.verify_key).hex()
    if ed_pub != v["ed25519_pub"]:
        print(f"  FAIL {v['name']}: Ed25519 pub mismatch")
        print(f"       expected: {v['ed25519_pub']}")
        print(f"       got:      {ed_pub}")
        failed += 1
        continue

    # Derive X25519 via birational map (the bridge to qntm)
    x_priv = sk.to_curve25519_private_key()
    x_pub = bytes(x_priv.public_key).hex()

    if x_pub == v["x25519_pub"]:
        print(f"  PASS {v['name']}: X25519 = {x_pub[:16]}...")
        passed += 1
    else:
        print(f"  FAIL {v['name']}: X25519 mismatch")
        print(f"       expected: {v['x25519_pub']}")
        print(f"       got:      {x_pub}")
        failed += 1

print(f"\n{'='*50}")
print(f"AIP ↔ qntm key derivation: {passed}/{passed+failed} vectors pass")

if failed:
    print("FAIL — key derivation is not compatible")
    sys.exit(1)
else:
    print("PASS — AIP Ed25519 identities bridge to qntm X25519")
    print()
    print("What this proves:")
    print("  - AIP's Ed25519 identity keys can derive X25519 keys")
    print("  - These X25519 keys are compatible with qntm's relay")
    print("  - An AIP agent can join qntm encrypted conversations")
    print()
    print("Next steps:")
    print("  1. Join echo bot: convo dca83b70ccd763a89b5953b2cd2ee678")
    print("  2. Relay send: POST https://inbox.qntm.corpo.llc/v1/send")
    print("  3. Relay subscribe: wss://inbox.qntm.corpo.llc/v1/subscribe")
    print("  4. Full specs: github.com/corpollc/qntm/tree/main/specs")
    sys.exit(0)
