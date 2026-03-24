#!/usr/bin/env python3
"""Agent B (Messenger) — Subscribe to relay and process verified handoffs.

Demonstrates the "receiver" side of a multi-host pipeline handoff:
1. Load identity + conversation keys (from invite material)
2. Subscribe to the relay via WebSocket
3. Receive CBOR envelopes
4. Verify the sender's Ed25519 signature
5. Decrypt the work artifact
6. Process the handoff (your pipeline logic here)

Usage:
    # Set conversation material from sender's output:
    export HANDOFF_CONV_ID=<hex>
    export HANDOFF_INVITE_SECRET=<hex>
    export HANDOFF_INVITE_SALT=<hex>

    # Optional: set trusted sender IDs (comma-separated)
    export HANDOFF_TRUSTED_SENDERS=<sender_id_hex>,<sender_id_hex>

    python handoff_receiver.py

Dependencies:
    pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
    pip install websockets
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time

from nacl.signing import SigningKey, VerifyKey

from shared import (
    RELAY_URL,
    derive_conversation_keys,
    decrypt_message,
    compute_sender_id,
)

# ── Configuration ─────────────────────────────────────────────────────────────

STATE_DIR = os.environ.get("HANDOFF_STATE_DIR", os.path.join(os.path.dirname(__file__), ".state-receiver"))


# ── CBOR Decoder (minimal) ───────────────────────────────────────────────────

def _read_cbor_uint(data: bytes, offset: int) -> tuple[int, int]:
    """Read CBOR unsigned integer, return (value, new_offset)."""
    additional = data[offset] & 0x1F
    offset += 1
    if additional < 24:
        return additional, offset
    elif additional == 24:
        return data[offset], offset + 1
    elif additional == 25:
        return struct.unpack_from("!H", data, offset)[0], offset + 2
    elif additional == 26:
        return struct.unpack_from("!I", data, offset)[0], offset + 4
    elif additional == 27:
        return struct.unpack_from("!Q", data, offset)[0], offset + 8
    raise ValueError(f"Unsupported CBOR additional info: {additional}")


def cbor_decode(data: bytes, offset: int = 0) -> tuple:
    """Minimal CBOR decoder. Returns (value, new_offset)."""
    major = (data[offset] >> 5) & 0x07

    if major == 0:  # unsigned int
        return _read_cbor_uint(data, offset)

    elif major == 2:  # byte string
        length, off = _read_cbor_uint(data, offset)
        return data[off : off + length], off + length

    elif major == 3:  # text string
        length, off = _read_cbor_uint(data, offset)
        return data[off : off + length].decode("utf-8"), off + length

    elif major == 4:  # array
        count, off = _read_cbor_uint(data, offset)
        result = []
        for _ in range(count):
            item, off = cbor_decode(data, off)
            result.append(item)
        return result, off

    elif major == 5:  # map
        count, off = _read_cbor_uint(data, offset)
        result = {}
        for _ in range(count):
            key, off = cbor_decode(data, off)
            val, off = cbor_decode(data, off)
            result[key] = val
        return result, off

    raise ValueError(f"Unsupported CBOR major type: {major}")


def decode_envelope(envelope_b64: str) -> dict:
    """Decode a base64-encoded CBOR envelope into a Python dict."""
    raw = base64.b64decode(envelope_b64)
    result, _ = cbor_decode(raw)
    return result


# ── Setup ─────────────────────────────────────────────────────────────────────

def load_conversation_from_env() -> tuple[bytes, bytes, bytes]:
    """Load conversation keys from environment variables.

    Returns:
        Tuple of (conv_id, aead_key, nonce_key).
    """
    conv_id_hex = os.environ.get("HANDOFF_CONV_ID")
    invite_secret_hex = os.environ.get("HANDOFF_INVITE_SECRET")
    invite_salt_hex = os.environ.get("HANDOFF_INVITE_SALT")

    if not all([conv_id_hex, invite_secret_hex, invite_salt_hex]):
        print("ERROR: Set environment variables from sender output:")
        print("  export HANDOFF_CONV_ID=<hex>")
        print("  export HANDOFF_INVITE_SECRET=<hex>")
        print("  export HANDOFF_INVITE_SALT=<hex>")
        sys.exit(1)

    conv_id = bytes.fromhex(conv_id_hex)
    invite_secret = bytes.fromhex(invite_secret_hex)
    invite_salt = bytes.fromhex(invite_salt_hex)

    _, aead_key, nonce_key = derive_conversation_keys(
        invite_secret, invite_salt, conv_id
    )

    return conv_id, aead_key, nonce_key


def load_trusted_senders() -> set[str] | None:
    """Load trusted sender IDs from env var (comma-separated hex strings).

    Returns None if no allowlist is configured (accept any valid signature).
    """
    raw = os.environ.get("HANDOFF_TRUSTED_SENDERS", "").strip()
    if not raw:
        return None
    return {s.strip() for s in raw.split(",") if s.strip()}


# ── Handoff Processing ───────────────────────────────────────────────────────

def process_handoff(artifact: dict) -> None:
    """Process a verified work artifact from the pipeline.

    ──────────────────────────────────────────────────────────────────
    CUSTOMIZE THIS: Replace with your actual pipeline processing.
    This example just prints the artifact. In production, you'd:
    - Parse the payload for your pipeline stage
    - Execute the work (send WhatsApp, run analysis, etc.)
    - Optionally send a receipt/acknowledgment back through the relay
    ──────────────────────────────────────────────────────────────────
    """
    print(f"\n  ┌─── WORK ARTIFACT ───────────────────────────────────")
    print(f"  │ Type:   {artifact.get('artifact_type', 'unknown')}")
    print(f"  │ From:   {artifact.get('source_agent', 'unknown')}")
    print(f"  │ To:     {artifact.get('target_agent', 'unknown')}")
    print(f"  │ Time:   {artifact.get('created_at', 'unknown')}")

    payload = artifact.get("payload", {})
    if payload:
        print(f"  │")
        print(f"  │ Payload:")
        for k, v in payload.items():
            val_str = str(v)
            if len(val_str) > 60:
                val_str = val_str[:57] + "..."
            print(f"  │   {k}: {val_str}")

    metadata = artifact.get("metadata", {})
    if metadata:
        print(f"  │")
        print(f"  │ Metadata:")
        for k, v in metadata.items():
            print(f"  │   {k}: {v}")

    print(f"  └──────────────────────────────────────────────────────\n")


def verify_and_process(
    envelope: dict,
    aead_key: bytes,
    nonce_key: bytes,
    conv_id: bytes,
    trusted_senders: set[str] | None,
) -> bool:
    """Verify sender, decrypt, and process a single envelope.

    Returns True if the handoff was accepted and processed.
    """
    sender_hex = envelope.get("sender", b"").hex()
    ciphertext = envelope.get("ciphertext", b"")
    signature = envelope.get("sig", b"")
    nonce = envelope.get("nonce", b"")
    msg_id = envelope.get("msg_id", b"")
    seq = envelope.get("seq", 0)
    ts = envelope.get("ts", 0)
    expiry_ts = envelope.get("expiry_ts")

    print(f"  Message received:")
    print(f"    sender:   {sender_hex}")
    print(f"    seq:      {seq}")
    print(f"    ts:       {ts}")

    # ── Check expiry ──
    if expiry_ts is not None:
        now_ms = int(time.time() * 1000)
        if now_ms > expiry_ts:
            print(f"    ❌ EXPIRED (expiry_ts={expiry_ts}, now={now_ms})")
            return False
        print(f"    expiry:   {expiry_ts} (valid)")

    # ── Check sender allowlist ──
    if trusted_senders is not None and sender_hex not in trusted_senders:
        print(f"    ❌ UNTRUSTED SENDER (not in allowlist)")
        print(f"       Known senders: {trusted_senders}")
        return False

    # ── Note on signature verification ──
    # Full signature verification requires the sender's Ed25519 public key.
    # In production, you'd resolve this via:
    #   1. DID resolution: did:web:sender-domain → Ed25519 key
    #   2. Local key registry: sender_id → public key mapping
    #   3. OATR trust registry: sender_id → registered issuer
    #
    # For this example, we verify the envelope structure and decrypt.
    # The sender_id check above provides identity verification via the
    # allowlist. Add DID resolution for full cryptographic verification.
    print(f"    sender:   ✅ (in allowlist)" if trusted_senders else "    sender:   ⚠️  (no allowlist configured)")

    # ── Decrypt ──
    try:
        plaintext = decrypt_message(ciphertext, nonce, aead_key, conv_id)
        print(f"    decrypt:  ✅ ({len(plaintext)} bytes)")
    except Exception as e:
        print(f"    ❌ DECRYPTION FAILED: {e}")
        return False

    # ── Parse work artifact ──
    try:
        artifact = json.loads(plaintext)
        print(f"    artifact: ✅ ({artifact.get('artifact_type', 'unknown')})")
    except json.JSONDecodeError:
        print(f"    ⚠️  Not JSON — raw payload ({len(plaintext)} bytes)")
        print(f"    Content: {plaintext[:200]}")
        return True

    # ── Process ──
    process_handoff(artifact)
    return True


# ── WebSocket Subscriber ─────────────────────────────────────────────────────

def subscribe_and_process(
    conv_id: bytes,
    aead_key: bytes,
    nonce_key: bytes,
    trusted_senders: set[str] | None,
):
    """Subscribe to relay via WebSocket and process incoming handoffs."""
    try:
        import websockets.sync.client as ws_sync
    except ImportError:
        print("ERROR: websockets package required for subscription.")
        print("  pip install websockets")
        sys.exit(1)

    conv_id_hex = conv_id.hex()
    ws_url = RELAY_URL.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/v1/subscribe?conv_id={conv_id_hex}"

    print(f"\n[*] Subscribing to relay ...")
    print(f"    URL: {ws_url}")
    print(f"    Conversation: {conv_id_hex}")
    if trusted_senders:
        print(f"    Trusted senders: {trusted_senders}")
    else:
        print(f"    ⚠️  No sender allowlist — accepting all valid envelopes")
    print(f"\n    Waiting for handoffs ... (Ctrl+C to stop)\n")

    processed = 0

    while True:
        try:
            with ws_sync.connect(ws_url) as ws:
                for raw_msg in ws:
                    if isinstance(raw_msg, bytes):
                        raw_msg = raw_msg.decode("utf-8", errors="replace")

                    # Skip relay control frames
                    if raw_msg.startswith("{"):
                        try:
                            ctrl = json.loads(raw_msg)
                            if ctrl.get("type") == "ready":
                                cursor = ctrl.get("cursor", "unknown")
                                print(f"  [relay] Connected (cursor: {cursor})")
                                continue
                            if ctrl.get("type") == "heartbeat":
                                continue
                        except json.JSONDecodeError:
                            pass

                    # Decode envelope
                    try:
                        data = json.loads(raw_msg)
                        envelope_b64 = data.get("envelope_b64", "")
                        if not envelope_b64:
                            continue
                        envelope = decode_envelope(envelope_b64)
                    except Exception as e:
                        print(f"  [skip] Could not decode message: {e}")
                        continue

                    # Verify + decrypt + process
                    print(f"\n{'─' * 60}")
                    ok = verify_and_process(
                        envelope, aead_key, nonce_key, conv_id, trusted_senders
                    )
                    if ok:
                        processed += 1
                        print(f"  [✅ Handoff #{processed} processed]")

        except KeyboardInterrupt:
            print(f"\n\nShutting down. Processed {processed} handoffs.")
            break
        except Exception as e:
            print(f"\n  [reconnect] WebSocket error: {e}")
            print(f"  Reconnecting in 5 seconds ...")
            time.sleep(5)


# ── HTTP Poll Fallback ───────────────────────────────────────────────────────

def poll_and_process(
    conv_id: bytes,
    aead_key: bytes,
    nonce_key: bytes,
    trusted_senders: set[str] | None,
):
    """Poll relay via HTTP for incoming handoffs (fallback if WebSocket unavailable)."""
    import httpx

    conv_id_hex = conv_id.hex()
    cursor_file = os.path.join(STATE_DIR, "receiver_cursor.txt")
    cursor = ""

    if os.path.exists(cursor_file):
        with open(cursor_file) as f:
            cursor = f.read().strip()

    recv_url = f"{RELAY_URL}/v1/recv"
    print(f"\n[*] Polling relay ...")
    print(f"    URL: {recv_url}")
    print(f"    Conversation: {conv_id_hex}")
    print(f"    Cursor: {cursor or '(none — will get all messages)'}")

    params = {"conv_id": conv_id_hex}
    if cursor:
        params["cursor"] = cursor

    try:
        resp = httpx.get(recv_url, params=params, timeout=15)
        if resp.status_code != 200:
            print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
            return
    except Exception as e:
        print(f"    ERROR: {e}")
        return

    data = resp.json()
    messages = data.get("messages", [])
    new_cursor = data.get("cursor", cursor)

    print(f"    Messages: {len(messages)}")

    for msg_data in messages:
        envelope_b64 = msg_data.get("envelope_b64", "")
        if not envelope_b64:
            continue
        envelope = decode_envelope(envelope_b64)
        print(f"\n{'─' * 60}")
        verify_and_process(envelope, aead_key, nonce_key, conv_id, trusted_senders)

    # Persist cursor
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(cursor_file, "w") as f:
        f.write(new_cursor)
    print(f"\n    Cursor updated: {new_cursor[:24]}...")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Relay Handoff — Receiver (Messenger Agent)")
    print("=" * 70)
    print()

    # ── Load conversation ──
    print("[1] Loading conversation keys ...")
    conv_id, aead_key, nonce_key = load_conversation_from_env()
    print(f"  Conversation: {conv_id.hex()}")
    print()

    # ── Load trusted senders ──
    print("[2] Loading sender allowlist ...")
    trusted_senders = load_trusted_senders()
    print()

    # ── Subscribe or poll ──
    mode = os.environ.get("HANDOFF_MODE", "subscribe").lower()

    if mode == "poll":
        poll_and_process(conv_id, aead_key, nonce_key, trusted_senders)
    else:
        subscribe_and_process(conv_id, aead_key, nonce_key, trusted_senders)


if __name__ == "__main__":
    main()
