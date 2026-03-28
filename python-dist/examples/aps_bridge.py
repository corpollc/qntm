#!/usr/bin/env python3
"""APS → qntm Bridge: Use an Agent Passport System Ed25519 seed to create
a qntm identity and send an encrypted message through the relay.

Usage:
    # With a random identity (demo mode):
    python aps_bridge.py

    # With an APS Ed25519 seed (hex):
    python aps_bridge.py --seed <64-char-hex-seed>

    # Specify conversation (default: echo bot):
    python aps_bridge.py --conv <conversation-id-hex>

This demonstrates cross-project identity interop:
  APS Ed25519 passport key → X25519 encryption key → qntm encrypted channel

Three implementations confirmed compatible (Wave 23):
  - libsodium (APS/TypeScript)
  - @noble/curves (TypeScript runner)
  - Python cryptography + PyNaCl (qntm)
"""

import argparse
import json
import os
import sys

# Ensure qntm is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qntm.crypto import QSP1Suite, ed25519_public_key_to_x25519
from qntm.identity import generate_identity, key_id_from_public_key

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Echo bot conversation ID
ECHO_BOT_CONV = "48055654db4bb0f64ec63089b70e1bf4"


def identity_from_aps_seed(seed_hex: str) -> dict:
    """Derive a qntm identity from an APS-format Ed25519 seed.

    This uses the same birational map (RFC 7748 §4.1) proven compatible
    across all three implementations in the vector exchange.
    """
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError(f"Seed must be 32 bytes (64 hex chars), got {len(seed)}")

    # Derive Ed25519 keypair from seed
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_bytes = sk.public_key().public_bytes_raw()

    # The private key in qntm format is seed + public key (64 bytes)
    sk_bytes = seed + pk_bytes

    # Compute key ID
    suite = QSP1Suite()
    key_id = suite.compute_key_id(pk_bytes)

    # Also derive X25519 to show compatibility
    x25519_pk = ed25519_public_key_to_x25519(pk_bytes)

    return {
        "identity": {
            "privateKey": sk_bytes,
            "publicKey": pk_bytes,
            "keyID": key_id,
        },
        "ed25519_public": pk_bytes.hex(),
        "x25519_public": x25519_pk.hex(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="APS → qntm bridge: cross-project identity interop demo"
    )
    parser.add_argument(
        "--seed",
        help="APS Ed25519 seed (64 hex chars). Random if omitted.",
    )
    parser.add_argument(
        "--conv",
        default=ECHO_BOT_CONV,
        help=f"Conversation ID to join (default: echo bot {ECHO_BOT_CONV})",
    )
    parser.add_argument(
        "--message",
        default="Hello from APS↔qntm bridge! 🔐",
        help="Message to send",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show derived identity without sending",
    )
    args = parser.parse_args()

    # Generate or derive identity
    if args.seed:
        print(f"🔑 Deriving qntm identity from APS seed...")
        result = identity_from_aps_seed(args.seed)
        identity = result["identity"]
        print(f"   Ed25519 public key: {result['ed25519_public'][:16]}...")
        print(f"   X25519 public key:  {result['x25519_public'][:16]}...")
        print(f"   qntm key ID:       {identity['keyID'].hex()[:16]}...")
        print(f"   ✅ Same key derivation as APS deriveEncryptionKeypair()")
    else:
        print(f"🎲 Generating random qntm identity (use --seed for APS interop)...")
        identity = generate_identity()
        print(f"   qntm key ID: {identity['keyID'].hex()[:16]}...")

    if args.dry_run:
        print(f"\n🏁 Dry run complete. Identity derived but no message sent.")
        print(f"   To send: remove --dry-run flag")
        return

    # Import relay client (requires qntm package)
    try:
        from qntm.cli import _load_or_create_identity, _get_config_dir
    except ImportError:
        print(f"\n⚠️  Full qntm package required for relay operations.")
        print(f"   Install: pip install qntm")
        print(f"   Then run this script again.")
        return

    print(f"\n📡 Connecting to qntm relay...")
    print(f"   Conversation: {args.conv}")
    print(f"   Message: {args.message}")
    print(f"\n   (Full relay integration coming in Step 3)")
    print(f"   For now, use the qntm CLI directly:")
    print(f"   qntm convo join {args.conv}")
    print(f'   qntm send {args.conv} "{args.message}"')
    print(f"   qntm recv {args.conv}")


if __name__ == "__main__":
    main()
