#!/usr/bin/env python3
"""AgentID relay test — send an encrypted message through Peter Vessenes' live qntm relay.

Proves AgentID can:
  1. Derive HKDF keys from shared invite material (verified against known vectors)
  2. Encrypt a message with XChaCha20-Poly1305
  3. Build a CBOR envelope signed with Ed25519
  4. POST to the live qntm inbox relay

Dependencies: PyNaCl, cryptography, httpx
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from datetime import datetime, timezone

# -- Add SDK to path so we can import agentid.ed25519 --------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from agentid.ed25519 import Ed25519Identity

from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

import httpx

# ==============================================================================
# Constants from Peter's invite
# ==============================================================================

INVITE_SECRET = bytes.fromhex(
    "a6d89c17fb6da9e56f368c2b562978ccd434900a835062d0fdfb5b31f0bdaaa2"
)
INVITE_SALT = bytes.fromhex(
    "99c74e4a41450c294a3ffb6473141ef3ca9e97f7afbc98ffc80f45793944dd80"
)
CONV_ID = bytes.fromhex("dca83b70ccd763a89b5953b2cd2ee678")
CONV_ID_HEX = "dca83b70ccd763a89b5953b2cd2ee678"

# Expected derived keys (MUST match exactly)
EXPECTED_ROOT_KEY  = "5b9f2361408c3932d4685d8ccb9733a1da980086c49a7b6615f6bca5e1a67c01"
EXPECTED_AEAD_KEY  = "b557d6071c2237eff670aa965f8f3bb516f9ba1d788166f8faf7388f5a260ec3"
EXPECTED_NONCE_KEY = "d88a1a1dee9dd0761a61a228a368ad72c15b96108c04cb072cc2b8fd63056c4f"

SEND_URL = "https://inbox.qntm.corpo.llc/v1/send"

# ==============================================================================
# Minimal CBOR encoder (maps, byte strings, text strings, unsigned ints)
# ==============================================================================

def _cbor_encode_uint(major: int, value: int) -> bytes:
    """Encode a CBOR unsigned integer with the given major type (0-7)."""
    mt = major << 5
    if value < 24:
        return struct.pack("B", mt | value)
    elif value < 0x100:
        return struct.pack("BB", mt | 24, value)
    elif value < 0x10000:
        return struct.pack("!BH", mt | 25, value)
    elif value < 0x100000000:
        return struct.pack("!BI", mt | 26, value)
    else:
        return struct.pack("!BQ", mt | 27, value)


def cbor_encode(obj) -> bytes:
    """Minimal CBOR encoder supporting: unsigned int, bytes, str, dict."""
    if isinstance(obj, int) and obj >= 0:
        return _cbor_encode_uint(0, obj)
    elif isinstance(obj, bytes):
        return _cbor_encode_uint(2, len(obj)) + obj
    elif isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_encode_uint(3, len(encoded)) + encoded
    elif isinstance(obj, dict):
        items = list(obj.items())
        result = _cbor_encode_uint(5, len(items))
        for k, v in items:
            result += cbor_encode(k)
            result += cbor_encode(v)
        return result
    else:
        raise TypeError(f"cbor_encode: unsupported type {type(obj)}")


# ==============================================================================
# Key derivation
# ==============================================================================

def derive_keys():
    """Derive root_key, aead_key, nonce_key from invite material using HKDF-SHA-256."""

    # root_key = HKDF(ikm=invite_secret, salt=invite_salt,
    #                  info="qntm/qsp/v1/root" || conv_id, len=32)
    info_root = b"qntm/qsp/v1/root" + CONV_ID
    root_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=INVITE_SALT,
        info=info_root,
    ).derive(INVITE_SECRET)

    # aead_key = HKDF-Expand(prk=root_key, info="qntm/qsp/v1/aead" || conv_id, len=32)
    info_aead = b"qntm/qsp/v1/aead" + CONV_ID
    aead_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=info_aead,
    ).derive(root_key)

    # nonce_key = HKDF-Expand(prk=root_key, info="qntm/qsp/v1/nonce" || conv_id, len=32)
    info_nonce = b"qntm/qsp/v1/nonce" + CONV_ID
    nonce_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=info_nonce,
    ).derive(root_key)

    return root_key, aead_key, nonce_key


# ==============================================================================
# Main
# ==============================================================================

def main():
    print("=" * 70)
    print("  AgentID Relay Test — qntm encrypted channel")
    print("=" * 70)
    print()

    # ------------------------------------------------------------------
    # Step 1: Generate AgentID Ed25519 identity
    # ------------------------------------------------------------------
    print("[1] Generating AgentID Ed25519 identity ...")
    identity = Ed25519Identity.generate()
    print(f"    Ed25519 public key: {identity.ed25519_public_key_hex}")
    print(f"    X25519 public key:  {identity.x25519_public_key_hex}")
    print()

    # ------------------------------------------------------------------
    # Step 2: Derive HKDF keys and verify against expected vectors
    # ------------------------------------------------------------------
    print("[2] Deriving HKDF keys from invite material ...")
    root_key, aead_key, nonce_key = derive_keys()

    all_pass = True

    def check(name, derived, expected_hex):
        nonlocal all_pass
        derived_hex = derived.hex()
        ok = derived_hex == expected_hex
        status = "PASS" if ok else "FAIL"
        print(f"    {name}:")
        print(f"      derived:  {derived_hex}")
        print(f"      expected: {expected_hex}")
        print(f"      [{status}]")
        if not ok:
            all_pass = False

    check("root_key ", root_key, EXPECTED_ROOT_KEY)
    check("aead_key ", aead_key, EXPECTED_AEAD_KEY)
    check("nonce_key", nonce_key, EXPECTED_NONCE_KEY)
    print()

    if not all_pass:
        print("FATAL: Key derivation mismatch — aborting. Will NOT send to live relay.")
        sys.exit(1)

    print("    All 3 key vectors verified. Proceeding to encrypt and send.")
    print()

    # ------------------------------------------------------------------
    # Step 3: Build plaintext payload
    # ------------------------------------------------------------------
    print("[3] Building plaintext payload ...")
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "type": "agentid-relay-test",
        "agent_id": "agentid_relay_probe",
        "identity_system": "AgentID",
        "message": (
            "AgentID relay test - cryptographic identity verification working. "
            "Three identity systems, one encrypted channel."
        ),
        "timestamp": now_iso,
        "ed25519_public_key": identity.ed25519_public_key_hex,
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    print(f"    Plaintext length: {len(plaintext)} bytes")
    print()

    # ------------------------------------------------------------------
    # Step 4: Encrypt with XChaCha20-Poly1305
    # ------------------------------------------------------------------
    print("[4] Encrypting with XChaCha20-Poly1305 ...")

    # msg_id = random(16)
    msg_id = os.urandom(16)

    # nonce = Trunc24(HMAC-SHA-256(nonce_key, msg_id))
    nonce_full = hmac.new(nonce_key, msg_id, hashlib.sha256).digest()
    nonce = nonce_full[:24]

    # ciphertext = XChaCha20-Poly1305(aead_key, nonce, plaintext, aad=conv_id)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad=CONV_ID, nonce=nonce, key=aead_key
    )
    print(f"    msg_id:     {msg_id.hex()}")
    print(f"    nonce:      {nonce.hex()}")
    print(f"    ciphertext: {len(ciphertext)} bytes")
    print()

    # ------------------------------------------------------------------
    # Step 5: Sign the ciphertext with Ed25519
    # ------------------------------------------------------------------
    print("[5] Signing ciphertext with Ed25519 ...")
    signature = identity.sign(ciphertext)
    print(f"    signature:  {signature.hex()[:64]}...")
    print()

    # ------------------------------------------------------------------
    # Step 6: Compute key_id = Trunc16(SHA-256(ed25519_pub))
    # ------------------------------------------------------------------
    key_id = hashlib.sha256(identity.ed25519_public_key).digest()[:16]
    print(f"[6] key_id (sender): {key_id.hex()}")
    print()

    # ------------------------------------------------------------------
    # Step 7: Build CBOR envelope, then base64
    # ------------------------------------------------------------------
    print("[7] Building CBOR envelope ...")
    seq = 1
    ts = int(time.time() * 1000)  # unix milliseconds

    envelope_map = {
        "v": 1,
        "conv": CONV_ID,
        "sender": key_id,
        "seq": seq,
        "ts": ts,
        "msg_id": msg_id,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "sig": signature,
        "aad_hash": hashlib.sha256(CONV_ID).digest(),
    }

    cbor_bytes = cbor_encode(envelope_map)
    envelope_b64 = base64.b64encode(cbor_bytes).decode("ascii")
    print(f"    CBOR length:   {len(cbor_bytes)} bytes")
    print(f"    Base64 length: {len(envelope_b64)} chars")
    print(f"    Envelope preview: {envelope_b64[:80]}...")
    print()

    # ------------------------------------------------------------------
    # Step 8: POST to relay
    # ------------------------------------------------------------------
    print("[8] POSTing to relay ...")
    print(f"    URL: {SEND_URL}")

    body = {
        "conv_id": CONV_ID_HEX,
        "envelope_b64": envelope_b64,
    }

    try:
        resp = httpx.post(SEND_URL, json=body, timeout=15)
        print(f"    HTTP status: {resp.status_code}")
        print(f"    Response headers:")
        for k, v in resp.headers.items():
            print(f"      {k}: {v}")
        print(f"    Response body: {resp.text}")
    except Exception as e:
        print(f"    ERROR: {e}")
        sys.exit(1)

    print()
    print("=" * 70)
    if 200 <= resp.status_code < 300:
        print("  SUCCESS — AgentID message sent through qntm relay")
    else:
        print(f"  RELAY RESPONDED {resp.status_code} — check response above")
    print("=" * 70)


if __name__ == "__main__":
    main()
