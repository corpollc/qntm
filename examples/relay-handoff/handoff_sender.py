#!/usr/bin/env python3
"""Agent A (Copywriter) — Send a signed work artifact through the qntm relay.

Demonstrates the "sender" side of a multi-host pipeline handoff:
1. Generate (or load) a persistent Ed25519 identity
2. Create a work artifact (the output of your pipeline stage)
3. Encrypt it with conversation keys derived from shared invite material
4. Sign the ciphertext with Ed25519
5. POST the CBOR envelope to the relay

The receiver (handoff_receiver.py) subscribes to the same conversation
and verifies the sender's identity before processing.

Usage:
    # First run: generates identity + conversation, prints invite for Agent B
    python handoff_sender.py

    # Subsequent runs: loads identity + sends a handoff
    python handoff_sender.py

    # Custom relay URL:
    QNTM_RELAY_URL=https://your-relay.example.com python handoff_sender.py

Dependencies:
    pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

import httpx
from nacl.signing import SigningKey

from shared import (
    SEND_ENDPOINT,
    derive_conversation_keys,
    encrypt_message,
    build_envelope,
    create_work_artifact,
    compute_sender_id,
)

# ── Configuration ─────────────────────────────────────────────────────────────

STATE_DIR = os.environ.get("HANDOFF_STATE_DIR", os.path.join(os.path.dirname(__file__), ".state"))
IDENTITY_FILE = os.path.join(STATE_DIR, "sender_identity.json")
CONVERSATION_FILE = os.path.join(STATE_DIR, "conversation.json")


# ── Identity Management ──────────────────────────────────────────────────────

def load_or_create_identity() -> SigningKey:
    """Load existing Ed25519 identity or generate a new one."""
    os.makedirs(STATE_DIR, exist_ok=True)

    if os.path.exists(IDENTITY_FILE):
        with open(IDENTITY_FILE) as f:
            data = json.load(f)
        sk = SigningKey(bytes.fromhex(data["signing_key_hex"]))
        print(f"  Loaded identity: {data['sender_id']}")
        return sk

    sk = SigningKey.generate()
    sender_id = compute_sender_id(bytes(sk.verify_key)).hex()

    with open(IDENTITY_FILE, "w") as f:
        json.dump({
            "signing_key_hex": sk.encode().hex(),
            "public_key_hex": bytes(sk.verify_key).hex(),
            "sender_id": sender_id,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, f, indent=2)

    print(f"  Generated new identity: {sender_id}")
    return sk


def load_or_create_conversation() -> tuple[bytes, bytes, bytes, bytes]:
    """Load existing conversation or create a new one with fresh invite material.

    Returns:
        Tuple of (conv_id, invite_secret, invite_salt, aead_key, nonce_key)
        packed as (conv_id, aead_key, nonce_key, invite_info_for_receiver).
    """
    os.makedirs(STATE_DIR, exist_ok=True)

    if os.path.exists(CONVERSATION_FILE):
        with open(CONVERSATION_FILE) as f:
            data = json.load(f)
        conv_id = bytes.fromhex(data["conv_id"])
        aead_key = bytes.fromhex(data["aead_key"])
        nonce_key = bytes.fromhex(data["nonce_key"])
        print(f"  Loaded conversation: {data['conv_id']}")
        return conv_id, aead_key, nonce_key

    # Generate fresh conversation material
    conv_id = os.urandom(16)
    invite_secret = os.urandom(32)
    invite_salt = os.urandom(32)

    _, aead_key, nonce_key = derive_conversation_keys(
        invite_secret, invite_salt, conv_id
    )

    with open(CONVERSATION_FILE, "w") as f:
        json.dump({
            "conv_id": conv_id.hex(),
            "invite_secret": invite_secret.hex(),
            "invite_salt": invite_salt.hex(),
            "aead_key": aead_key.hex(),
            "nonce_key": nonce_key.hex(),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, f, indent=2)

    # Print invite info for the receiver
    print(f"\n  ┌─────────────────────────────────────────────────────────")
    print(f"  │ NEW CONVERSATION — Share this with Agent B (receiver):")
    print(f"  │")
    print(f"  │   conv_id:       {conv_id.hex()}")
    print(f"  │   invite_secret: {invite_secret.hex()}")
    print(f"  │   invite_salt:   {invite_salt.hex()}")
    print(f"  │")
    print(f"  │ Set these as env vars on the receiver host:")
    print(f"  │   export HANDOFF_CONV_ID={conv_id.hex()}")
    print(f"  │   export HANDOFF_INVITE_SECRET={invite_secret.hex()}")
    print(f"  │   export HANDOFF_INVITE_SALT={invite_salt.hex()}")
    print(f"  └─────────────────────────────────────────────────────────\n")

    return conv_id, aead_key, nonce_key


# ── Sequence Counter ─────────────────────────────────────────────────────────

def next_sequence() -> int:
    """Get and increment the monotonic sequence counter."""
    seq_file = os.path.join(STATE_DIR, "sender_seq.txt")
    seq = 1
    if os.path.exists(seq_file):
        with open(seq_file) as f:
            seq = int(f.read().strip()) + 1
    with open(seq_file, "w") as f:
        f.write(str(seq))
    return seq


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Relay Handoff — Sender (Copywriter Agent)")
    print("=" * 70)
    print()

    # ── Step 1: Identity ──
    print("[1] Loading identity ...")
    signing_key = load_or_create_identity()
    sender_id = compute_sender_id(bytes(signing_key.verify_key)).hex()
    print()

    # ── Step 2: Conversation ──
    print("[2] Loading conversation ...")
    conv_id, aead_key, nonce_key = load_or_create_conversation()
    print()

    # ── Step 3: Create work artifact ──
    print("[3] Creating work artifact ...")

    # ──────────────────────────────────────────────────────────────────
    # CUSTOMIZE THIS: Replace with your actual pipeline output.
    # This example simulates a Copywriter agent handing off to Messenger.
    # ──────────────────────────────────────────────────────────────────
    artifact = create_work_artifact(
        artifact_type="copywriter_output",
        source_agent="copywriter-agent-01",
        target_agent="messenger-agent-01",
        payload={
            "lead_id": "lead_acme_corp_2026Q1",
            "country": "Germany",
            "language": "de",
            "subject": "Partnerschaft mit ACME Corp",
            "body": (
                "Sehr geehrte Frau Mueller,\n\n"
                "vielen Dank für Ihr Interesse an unserer Plattform. "
                "Basierend auf der Analyse Ihres Unternehmens haben wir "
                "ein maßgeschneidertes Angebot vorbereitet.\n\n"
                "Mit freundlichen Grüßen,\n"
                "Ihr Sales Team"
            ),
            "channel": "whatsapp",
            "recipient_phone": "+49151XXXXXXXX",
            "urgency": "normal",
            "approval_status": "auto_approved",
        },
        metadata={
            "pipeline_run_id": f"run_{int(time.time())}",
            "copywriter_version": "2.1.0",
            "confidence_score": 0.92,
            "word_count": 47,
        },
    )

    print(f"  Artifact size: {len(artifact)} bytes")
    print(f"  Type: copywriter_output → messenger-agent-01")
    print()

    # ── Step 4: Encrypt ──
    print("[4] Encrypting with XChaCha20-Poly1305 ...")
    msg_id, nonce, ciphertext = encrypt_message(
        artifact, aead_key, nonce_key, conv_id
    )
    print(f"  msg_id: {msg_id.hex()}")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print()

    # ── Step 5: Build signed envelope ──
    print("[5] Building signed CBOR envelope ...")
    seq = next_sequence()

    # Optional: set expiry 5 minutes from now
    expiry_ts = int(time.time() * 1000) + (5 * 60 * 1000)

    envelope_bytes = build_envelope(
        signing_key=signing_key,
        conv_id=conv_id,
        msg_id=msg_id,
        nonce=nonce,
        ciphertext=ciphertext,
        seq=seq,
        expiry_ts=expiry_ts,
    )
    envelope_b64 = base64.b64encode(envelope_bytes).decode("ascii")
    print(f"  Sequence: {seq}")
    print(f"  Expiry: {expiry_ts} (5 min from now)")
    print(f"  Envelope: {len(envelope_bytes)} bytes CBOR → {len(envelope_b64)} chars base64")
    print()

    # ── Step 6: Send to relay ──
    print(f"[6] Sending to relay ({SEND_ENDPOINT}) ...")
    body = {
        "conv_id": conv_id.hex(),
        "envelope_b64": envelope_b64,
    }

    try:
        resp = httpx.post(SEND_ENDPOINT, json=body, timeout=15)
        print(f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    print()
    if 200 <= resp.status_code < 300:
        print("  ✅ Handoff sent successfully!")
        print(f"     Sender:       {sender_id}")
        print(f"     Conversation: {conv_id.hex()}")
        print(f"     Sequence:     {seq}")
        print(f"     The relay cannot read the work artifact.")
        print(f"     Only agents with the conversation keys can decrypt.")
    else:
        print(f"  ❌ Relay returned {resp.status_code}")
        print(f"     Check relay health: curl {SEND_ENDPOINT.replace('/send', '/healthz')}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
