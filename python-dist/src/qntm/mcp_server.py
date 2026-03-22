"""qntm MCP Server — End-to-end encrypted messaging for AI agents.

Exposes qntm messaging operations as MCP tools so any MCP-compatible
AI agent (Claude Desktop, Cursor, OpenClaw, etc.) can send and receive
encrypted messages through the qntm protocol.

Run:
    python -m qntm.mcp                          # stdio transport (default)
    python -m qntm.mcp --transport streamable-http  # HTTP transport

Environment:
    QNTM_CONFIG_DIR  — config directory (default: ~/.qntm)
    QNTM_RELAY_URL   — relay URL (default: https://inbox.qntm.corpo.llc)
"""

from __future__ import annotations

import base64
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

from . import (
    __version__,
    generate_identity,
    key_id_to_string,
    public_key_to_string,
    create_invite,
    derive_conversation_keys,
    create_conversation,
    add_participant,
    create_message,
    serialize_envelope,
    deserialize_envelope,
    decrypt_message,
    invite_to_token,
    invite_from_url,
)
from .cli import (
    _load_identity,
    _save_identity,
    _load_conversations,
    _save_conversations,
    _load_cursors,
    _save_cursors,
    _load_seen,
    _save_seen,
    _load_history,
    _save_history,
    _ensure_config_dir,
    _conv_to_crypto,
    _resolve_conversation,
    _http_send,
    _recv_once,
    default_ttl,
)

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "qntm",
    instructions=(
        "End-to-end encrypted messaging for AI agents. "
        "Send and receive encrypted messages with cryptographic identity, "
        "E2E encryption (X25519 + XChaCha20-Poly1305), and zero-knowledge relay."
    ),
)

DEFAULT_RELAY = "https://inbox.qntm.corpo.llc"


def _config_dir() -> str:
    return os.environ.get("QNTM_CONFIG_DIR", os.path.expanduser("~/.qntm"))


def _relay_url() -> str:
    return os.environ.get("QNTM_RELAY_URL", DEFAULT_RELAY)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def identity_generate() -> dict:
    """Generate a new Ed25519 cryptographic identity for this agent.

    Creates a persistent keypair stored in the config directory.
    The identity is used to sign and encrypt all messages.
    If an identity already exists, returns the existing one.
    """
    config_dir = _config_dir()
    _ensure_config_dir(config_dir)

    existing = _load_identity(config_dir)
    if existing:
        kid_hex = key_id_to_string(existing["keyID"])
        pub_hex = public_key_to_string(existing["publicKey"])
        return {
            "status": "exists",
            "key_id": kid_hex,
            "public_key": pub_hex,
            "config_dir": config_dir,
        }

    identity = generate_identity()
    _save_identity(config_dir, identity)
    kid_hex = key_id_to_string(identity["keyID"])
    pub_hex = public_key_to_string(identity["publicKey"])
    return {
        "status": "created",
        "key_id": kid_hex,
        "public_key": pub_hex,
        "config_dir": config_dir,
    }


@mcp.tool()
def identity_show() -> dict:
    """Show the current agent's cryptographic identity (key ID and public key)."""
    config_dir = _config_dir()
    identity = _load_identity(config_dir)
    if not identity:
        return {"error": "No identity found. Call identity_generate first."}
    kid_hex = key_id_to_string(identity["keyID"])
    pub_hex = public_key_to_string(identity["publicKey"])
    return {
        "key_id": kid_hex,
        "public_key": pub_hex,
        "config_dir": config_dir,
    }


@mcp.tool()
def conversation_list() -> list[dict]:
    """List all conversations this agent is part of.

    Returns conversation IDs, names, types, and participant counts.
    """
    config_dir = _config_dir()
    conversations = _load_conversations(config_dir)
    result = []
    for c in conversations:
        result.append({
            "id": c["id"],
            "name": c.get("name", ""),
            "type": c.get("type", "direct"),
            "participants": len(c.get("participants", [])),
        })
    return result


@mcp.tool()
def conversation_create(name: str = "") -> dict:
    """Create a new encrypted conversation and get an invite token.

    Args:
        name: Optional display name for the conversation.

    Returns the conversation ID and an invite token that other agents
    can use to join the conversation.
    """
    config_dir = _config_dir()
    _ensure_config_dir(config_dir)

    identity = _load_identity(config_dir)
    if not identity:
        return {"error": "No identity found. Call identity_generate first."}

    invite = create_invite(identity, conv_type="direct")
    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)

    conv_id_hex = conv["id"].hex() if isinstance(conv["id"], (bytes, bytearray)) else conv["id"]

    # Build record for local storage
    record = {
        "id": conv_id_hex,
        "name": name,
        "type": "direct",
        "keys": {
            "root": conv["keys"]["root"].hex() if isinstance(conv["keys"]["root"], (bytes, bytearray)) else conv["keys"]["root"],
            "aead_key": conv["keys"]["aead_key"].hex() if isinstance(conv["keys"]["aead_key"], (bytes, bytearray)) else conv["keys"]["aead_key"],
            "nonce_key": conv["keys"]["nonce_key"].hex() if isinstance(conv["keys"]["nonce_key"], (bytes, bytearray)) else conv["keys"]["nonce_key"],
        },
        "participants": [key_id_to_string(identity["keyID"])],
        "current_epoch": 0,
    }

    conversations = _load_conversations(config_dir)
    conversations.append(record)
    _save_conversations(config_dir, conversations)

    # Generate invite token
    token = invite_to_token(invite, _relay_url())

    return {
        "conversation_id": conv_id_hex,
        "name": name,
        "invite_token": token,
        "relay": _relay_url(),
    }


@mcp.tool()
def conversation_join(invite_token: str, name: str = "") -> dict:
    """Join an existing conversation using an invite token.

    Args:
        invite_token: The invite token received from the conversation creator.
        name: Optional display name for the conversation.
    """
    config_dir = _config_dir()
    _ensure_config_dir(config_dir)

    identity = _load_identity(config_dir)
    if not identity:
        return {"error": "No identity found. Call identity_generate first."}

    try:
        invite = invite_from_url(invite_token)
    except Exception as e:
        return {"error": f"Invalid invite token: {e}"}

    keys = derive_conversation_keys(invite)
    conv = create_conversation(invite, keys)
    add_participant(conv, identity["publicKey"])

    conv_id_hex = conv["id"].hex() if isinstance(conv["id"], (bytes, bytearray)) else conv["id"]

    record = {
        "id": conv_id_hex,
        "name": name,
        "type": "direct",
        "keys": {
            "root": conv["keys"]["root"].hex() if isinstance(conv["keys"]["root"], (bytes, bytearray)) else conv["keys"]["root"],
            "aead_key": conv["keys"]["aead_key"].hex() if isinstance(conv["keys"]["aead_key"], (bytes, bytearray)) else conv["keys"]["aead_key"],
            "nonce_key": conv["keys"]["nonce_key"].hex() if isinstance(conv["keys"]["nonce_key"], (bytes, bytearray)) else conv["keys"]["nonce_key"],
        },
        "participants": [key_id_to_string(identity["keyID"])],
        "current_epoch": 0,
    }

    conversations = _load_conversations(config_dir)
    # Avoid duplicates
    if not any(c["id"] == conv_id_hex for c in conversations):
        conversations.append(record)
        _save_conversations(config_dir, conversations)

    return {
        "conversation_id": conv_id_hex,
        "name": name,
        "status": "joined",
    }


@mcp.tool()
def send_message(conversation: str, message: str) -> dict:
    """Send an E2E encrypted message to a conversation.

    Args:
        conversation: Conversation ID (full or prefix) or name.
        message: The plaintext message to send (will be encrypted before transit).

    The message is encrypted with XChaCha20-Poly1305 and signed with
    your Ed25519 key before being sent through the relay. The relay
    only sees opaque ciphertext.
    """
    config_dir = _config_dir()
    relay = _relay_url()

    identity = _load_identity(config_dir)
    if not identity:
        return {"error": "No identity found. Call identity_generate first."}

    conversations = _load_conversations(config_dir)
    conv_record = _resolve_conversation(conversations, conversation)
    if not conv_record:
        return {"error": f"Conversation '{conversation}' not found. Use conversation_list to see available conversations."}

    conv_id_hex = conv_record["id"]
    conv_crypto = _conv_to_crypto(conv_record)

    body = message.encode("utf-8")
    envelope = create_message(identity, conv_crypto, "text", body, None, default_ttl())
    envelope_bytes = serialize_envelope(envelope)

    try:
        result = _http_send(relay, conv_id_hex, envelope_bytes)
    except Exception as e:
        return {"error": f"Failed to send: {e}"}

    seq = result.get("seq", 0)
    msg_id_hex = envelope["msg_id"].hex()

    # Save to local history
    history = _load_history(config_dir, conv_id_hex)
    history.append({
        "msg_id": msg_id_hex,
        "direction": "outgoing",
        "body_type": "text",
        "body": message,
        "created_ts": envelope["created_ts"],
    })
    _save_history(config_dir, conv_id_hex, history)

    return {
        "status": "sent",
        "conversation_id": conv_id_hex,
        "message_id": msg_id_hex,
        "sequence": seq,
    }


@mcp.tool()
def receive_messages(conversation: str) -> dict:
    """Receive and decrypt new messages from a conversation.

    Args:
        conversation: Conversation ID (full or prefix) or name.

    Returns decrypted messages received since the last check.
    Messages are decrypted locally — the relay never sees plaintext.
    """
    config_dir = _config_dir()
    relay = _relay_url()

    identity = _load_identity(config_dir)
    if not identity:
        return {"error": "No identity found. Call identity_generate first."}

    conversations = _load_conversations(config_dir)
    conv_record = _resolve_conversation(conversations, conversation)
    if not conv_record:
        return {"error": f"Conversation '{conversation}' not found."}

    conv_id_hex = conv_record["id"]
    conv_crypto = _conv_to_crypto(conv_record)

    cursors = _load_cursors(config_dir)
    from_seq = cursors.get(conv_id_hex, 0)

    seen = _load_seen(config_dir)
    conv_seen = seen.setdefault(conv_id_hex, {})

    try:
        raw_messages, up_to_seq = _recv_once(relay, conv_id_hex, from_seq)
    except Exception as e:
        return {"error": f"Failed to receive: {e}"}

    history = _load_history(config_dir, conv_id_hex)
    output_messages = []

    for raw_msg in raw_messages:
        try:
            envelope_bytes = base64.b64decode(raw_msg["envelope_b64"])
            envelope = deserialize_envelope(envelope_bytes)
        except Exception:
            continue

        msg_id_hex = bytes(envelope["msg_id"]).hex()
        if conv_seen.get(msg_id_hex):
            continue

        try:
            msg = decrypt_message(envelope, conv_crypto)
        except Exception:
            continue

        conv_seen[msg_id_hex] = True
        inner = msg["inner"]
        body_type = inner.get("body_type", "text")
        body_text = ""
        if body_type == "text" and isinstance(inner.get("body"), (bytes, bytearray)):
            body_text = inner["body"].decode("utf-8", errors="replace")
        elif body_type == "text" and isinstance(inner.get("body"), str):
            body_text = inner["body"]

        sender_kid = key_id_to_string(inner["sender_kid"]) if "sender_kid" in inner else "unknown"

        record = {
            "msg_id": msg_id_hex,
            "sender": sender_kid,
            "body_type": body_type,
            "body": body_text,
            "verified": msg.get("verified", False),
            "created_ts": inner.get("created_ts", 0),
        }
        output_messages.append(record)

        history.append({
            "msg_id": msg_id_hex,
            "direction": "incoming",
            "sender": sender_kid,
            "body_type": body_type,
            "body": body_text,
            "created_ts": inner.get("created_ts", 0),
        })

    # Save state
    cursors[conv_id_hex] = up_to_seq
    _save_cursors(config_dir, cursors)
    _save_seen(config_dir, seen)
    _save_history(config_dir, conv_id_hex, history)

    return {
        "conversation_id": conv_id_hex,
        "messages": output_messages,
        "count": len(output_messages),
        "cursor": up_to_seq,
    }


@mcp.tool()
def conversation_history(conversation: str, limit: int = 20) -> dict:
    """Get local message history for a conversation.

    Args:
        conversation: Conversation ID (full or prefix) or name.
        limit: Maximum number of messages to return (default 20, most recent).
    """
    config_dir = _config_dir()
    conversations = _load_conversations(config_dir)
    conv_record = _resolve_conversation(conversations, conversation)
    if not conv_record:
        return {"error": f"Conversation '{conversation}' not found."}

    conv_id_hex = conv_record["id"]
    history = _load_history(config_dir, conv_id_hex)
    recent = history[-limit:] if len(history) > limit else history

    return {
        "conversation_id": conv_id_hex,
        "name": conv_record.get("name", ""),
        "messages": recent,
        "total": len(history),
        "showing": len(recent),
    }


@mcp.tool()
def protocol_info() -> dict:
    """Get information about the qntm protocol and this server.

    Returns version, relay URL, identity status, and protocol details.
    Useful for understanding the encryption and security guarantees.
    """
    config_dir = _config_dir()
    identity = _load_identity(config_dir)
    conversations = _load_conversations(config_dir)

    return {
        "version": __version__,
        "protocol": "QSP v1.1 (qntm Secure Protocol)",
        "relay": _relay_url(),
        "encryption": {
            "key_agreement": "X25519 (Curve25519 Diffie-Hellman)",
            "cipher": "XChaCha20-Poly1305 (AEAD)",
            "signatures": "Ed25519",
            "identity": "Persistent Ed25519 keypair per agent",
        },
        "zero_knowledge": (
            "The relay only stores and forwards opaque ciphertext. "
            "It cannot read message content, verify sender identity, "
            "or determine conversation membership."
        ),
        "has_identity": identity is not None,
        "conversation_count": len(conversations),
        "config_dir": config_dir,
        "docs": "https://github.com/corpollc/qntm",
        "getting_started": "https://github.com/corpollc/qntm/blob/main/docs/getting-started.md",
    }


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("qntm://identity")
def resource_identity() -> str:
    """Current agent identity information."""
    config_dir = _config_dir()
    identity = _load_identity(config_dir)
    if not identity:
        return json.dumps({"status": "no identity", "action": "call identity_generate"})
    return json.dumps({
        "key_id": key_id_to_string(identity["keyID"]),
        "public_key": public_key_to_string(identity["publicKey"]),
    })


@mcp.resource("qntm://conversations")
def resource_conversations() -> str:
    """List of all conversations."""
    config_dir = _config_dir()
    conversations = _load_conversations(config_dir)
    result = []
    for c in conversations:
        result.append({
            "id": c["id"],
            "name": c.get("name", ""),
            "type": c.get("type", "direct"),
            "participants": len(c.get("participants", [])),
        })
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

@mcp.prompt()
def setup_agent_messaging() -> str:
    """Guide for setting up E2E encrypted messaging between agents."""
    return """To set up encrypted agent-to-agent messaging with qntm:

1. Generate an identity: call `identity_generate`
   - Creates an Ed25519 keypair for signing and encryption
   - Persisted locally — survives restarts

2. Create a conversation: call `conversation_create`
   - Returns an invite token to share with other agents
   - All messages are E2E encrypted with XChaCha20-Poly1305

3. Share the invite token with the other agent
   - They call `conversation_join` with your token
   - Both agents now share a secure channel

4. Send messages: call `send_message`
   - Messages are encrypted locally, relay sees only ciphertext
   - Signed with your Ed25519 key for authentication

5. Receive messages: call `receive_messages`
   - Fetches and decrypts new messages since last check
   - Verifies sender signatures automatically

The relay (inbox.qntm.corpo.llc) is zero-knowledge:
- Cannot read message content
- Cannot verify sender identity
- Cannot determine conversation membership
- Only stores and forwards opaque ciphertext

Protocol: QSP v1.1 | Docs: https://github.com/corpollc/qntm
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the qntm MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
