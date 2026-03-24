#!/usr/bin/env python3
"""qntm Echo Bot — proves encrypted messaging works in real-time.

Run: python3 echo-bot/bot.py
Or:  QNTM_HOME=echo-bot/.qntm python3 echo-bot/bot.py

Anyone who joins with the invite token can exchange encrypted messages.
The bot echoes back every message it receives, proving E2E encryption works.
"""

import json
import os
import subprocess
import sys
import time

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".qntm")
CONVO_ID = "43949472072a829bc12c19db0d8f5525"
POLL_INTERVAL = 5  # seconds


def qntm(*args: str) -> dict:
    """Run a qntm CLI command and return parsed JSON output."""
    cmd = ["uvx", "qntm", "--config-dir", CONFIG_DIR, *args]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr.strip()}
        return json.loads(result.stdout)
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": str(e)}


def get_my_kid() -> str:
    """Get our own key_id so we can skip our own messages."""
    result = qntm("identity", "show")
    if result.get("ok"):
        return result["data"]["key_id"]
    raise RuntimeError(f"Cannot read identity: {result}")


def recv_messages() -> list[dict]:
    """Receive new messages from the echo bot conversation."""
    result = qntm("recv", CONVO_ID)
    if not result.get("ok"):
        return []
    return result.get("data", {}).get("messages", [])


def send_message(text: str) -> bool:
    """Send a message to the echo bot conversation."""
    result = qntm("send", CONVO_ID, text)
    return result.get("ok", False)


def main():
    print("🔒 qntm echo bot starting...")
    print(f"   Config: {CONFIG_DIR}")
    print(f"   Conversation: {CONVO_ID}")
    print(f"   Polling every {POLL_INTERVAL}s")
    print()

    my_kid = get_my_kid()
    print(f"   My key_id: {my_kid}")
    print()
    print("🤖 Listening for messages...")
    print()

    consecutive_errors = 0
    max_errors = 10

    while True:
        try:
            messages = recv_messages()
            consecutive_errors = 0  # reset on success

            for msg in messages:
                sender_kid = msg.get("sender_kid", "")
                body = msg.get("unsafe_body", msg.get("body", ""))

                # Skip our own messages
                if my_kid in sender_kid or sender_kid.startswith(my_kid):
                    continue

                # Skip empty
                if not body or not body.strip():
                    continue

                sender_short = sender_kid[:8] if sender_kid else "unknown"
                print(f"📩 [{sender_short}...] {body}")

                # Echo it back
                echo_text = f"🔒 echo: {body}"
                if send_message(echo_text):
                    print(f"📤 {echo_text}")
                else:
                    print(f"❌ Failed to echo: {body}")

        except KeyboardInterrupt:
            print("\n👋 Echo bot shutting down.")
            sys.exit(0)
        except Exception as e:
            consecutive_errors += 1
            print(f"⚠️  Error ({consecutive_errors}/{max_errors}): {e}")
            if consecutive_errors >= max_errors:
                print("💀 Too many consecutive errors, shutting down.")
                sys.exit(1)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
