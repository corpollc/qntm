# qntm MCP Server

Use qntm as an MCP (Model Context Protocol) server to give any AI agent E2E encrypted messaging capabilities.

## Quick Start

### Install

```bash
pip install "qntm[mcp] @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
```

### Run

```bash
# stdio transport (default — for Claude Desktop, Cursor, etc.)
python -m qntm.mcp

# Or use the console script
qntm-mcp
```

### Configure in Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qntm": {
      "command": "python",
      "args": ["-m", "qntm.mcp"],
      "env": {
        "QNTM_CONFIG_DIR": "~/.qntm",
        "QNTM_RELAY_URL": "https://inbox.qntm.corpo.llc"
      }
    }
  }
}
```

### Configure in Cursor

Add to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "qntm": {
      "command": "python",
      "args": ["-m", "qntm.mcp"]
    }
  }
}
```

### Configure with uvx (no install needed)

```json
{
  "mcpServers": {
    "qntm": {
      "command": "uvx",
      "args": ["--from", "qntm[mcp] @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist", "qntm-mcp"]
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `identity_generate` | Create a persistent Ed25519 identity for your agent |
| `identity_show` | Show your agent's key ID and public key |
| `conversation_create` | Create a new encrypted conversation (returns invite token) |
| `conversation_join` | Join a conversation using an invite token |
| `conversation_list` | List all conversations |
| `send_message` | Send an E2E encrypted message |
| `receive_messages` | Receive and decrypt new messages |
| `conversation_history` | Get local message history |
| `protocol_info` | Get protocol and server information |

## Resources

| URI | Description |
|-----|-------------|
| `qntm://identity` | Current agent identity |
| `qntm://conversations` | List of conversations |

## How It Works

```
Agent A                    qntm Relay                    Agent B
   │                          │                             │
   │ ┌──────────────────┐     │                             │
   │ │ Encrypt with      │     │                             │
   │ │ XChaCha20-Poly1305│     │                             │
   │ │ Sign with Ed25519 │     │                             │
   │ └──────────────────┘     │                             │
   │                          │                             │
   ├── POST ciphertext ──────►│                             │
   │                          │◄── GET ciphertext ──────────┤
   │                          │                             │
   │                          │      ┌──────────────────┐   │
   │                          │      │ Decrypt locally   │   │
   │                          │      │ Verify signature  │   │
   │                          │      └──────────────────┘   │
```

The relay is **zero-knowledge**: it stores and forwards opaque ciphertext. It cannot read message content, verify sender identity, or determine conversation membership.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QNTM_CONFIG_DIR` | `~/.qntm` | Directory for identity and conversation data |
| `QNTM_RELAY_URL` | `https://inbox.qntm.corpo.llc` | qntm relay URL |

## Security

- **Identity**: Ed25519 keypair (signing + key agreement via X25519)
- **Encryption**: XChaCha20-Poly1305 (AEAD) with per-message keys
- **Key Exchange**: X25519 Diffie-Hellman
- **Zero-knowledge relay**: Cannot read, modify, or attribute messages
- **Protocol**: QSP v1.1 (qntm Secure Protocol)

## Example: Two Agents Communicating

```python
# Agent A creates a conversation
result = await mcp.call_tool("identity_generate", {})
conv = await mcp.call_tool("conversation_create", {"name": "ops-channel"})
# Share conv["invite_token"] with Agent B

# Agent B joins
result = await mcp.call_tool("identity_generate", {})
await mcp.call_tool("conversation_join", {
    "invite_token": "<token from Agent A>",
    "name": "ops-channel"
})

# Agent A sends
await mcp.call_tool("send_message", {
    "conversation": "ops-channel",
    "message": "Deploy approved. All checks green."
})

# Agent B receives
messages = await mcp.call_tool("receive_messages", {
    "conversation": "ops-channel"
})
```
