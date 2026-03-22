#!/usr/bin/env python3
"""Two agents exchanging E2E encrypted messages — pure Python, no server needed.

This example demonstrates qntm's core protocol:
1. Generate cryptographic identities for two agents
2. Create an encrypted conversation
3. Send and receive messages with full E2E encryption
4. Verify the relay only sees opaque ciphertext

Usage:
    pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
    python two_agents.py
"""

import qntm


def main():
    # ── Step 1: Each agent generates a persistent cryptographic identity ──
    alice = qntm.generate_identity()
    bob = qntm.generate_identity()

    alice_id = qntm.key_id_to_string(alice["keyID"])
    bob_id = qntm.key_id_to_string(bob["keyID"])

    print("=== qntm: E2E Encrypted Agent Messaging ===\n")
    print(f"Agent Alice: {alice_id[:24]}...")
    print(f"Agent Bob:   {bob_id[:24]}...")

    # ── Step 2: Alice creates a conversation and invites Bob ──
    invite = qntm.create_invite(alice, conv_type="direct")
    keys = qntm.derive_conversation_keys(invite)
    conv = qntm.create_conversation(invite, keys)
    qntm.add_participant(conv, bob["publicKey"])

    conv_id = conv["id"].hex()[:16]
    print(f"\nConversation: {conv_id}...")
    print(f"Participants: Alice + Bob")

    # ── Step 3: Alice sends an encrypted message ──
    plaintext = b"Deploy v2.1 to production. All tests green."

    msg = qntm.create_message(
        sender_identity=alice,
        conversation=conv,
        body_type="text",
        body=plaintext,
    )

    # Serialize to wire format — this is what travels through the relay
    envelope_bytes = qntm.serialize_envelope(msg)

    print(f"\n--- What the relay sees (opaque ciphertext) ---")
    print(f"Envelope size: {len(envelope_bytes)} bytes")
    print(f"Raw bytes: {envelope_bytes[:48].hex()}...")
    print(f"The relay CANNOT read the message content.")

    # ── Step 4: Bob decrypts the message ──
    recovered = qntm.deserialize_envelope(envelope_bytes)
    decrypted = qntm.decrypt_message(recovered, conv)

    print(f"\n--- What Bob sees (decrypted) ---")
    print(f"Body: {decrypted['inner']['body'].decode()}")
    print(f"Verified signature: {decrypted['verified']}")
    print(f"Sender: {qntm.key_id_to_string(decrypted['inner']['sender_kid'])[:24]}...")

    # ── Step 5: Verify correctness ──
    assert decrypted["inner"]["body"] == plaintext
    assert decrypted["verified"] is True
    assert decrypted["inner"]["body_type"] == "text"

    print(f"\n✅ Full E2E encryption roundtrip verified!")
    print(f"   - Ed25519 identity keys")
    print(f"   - X25519 key agreement")
    print(f"   - AEAD encryption (XChaCha20-Poly1305)")
    print(f"   - Relay sees only ciphertext — zero knowledge of content")
    print(f"\nTo use with a live relay: qntm send <conv_id> 'message'")
    print(f"Docs: https://github.com/corpollc/qntm/blob/main/docs/getting-started.md")


if __name__ == "__main__":
    main()
