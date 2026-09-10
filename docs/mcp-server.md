# qntm MCP Server

Use qntm as an MCP (Model Context Protocol) server to give any AI agent E2E encrypted messaging capabilities.

## Quick Start

### Install

```bash
pip install 'qntm[mcp]'
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
      "args": ["--from", "qntm[mcp]", "qntm-mcp"]
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
| `conversation_join` | Open a trusted contact's public group link (unreleased), or a legacy bearer invite |
| `conversation_list` | List all conversations |
| `send_message` | Send an E2E encrypted message |
| `receive_messages` | Receive and decrypt new messages |
| `conversation_history` | Get local message history |
| `protocol_info` | Get protocol and server information |
| `guidance_contacts` | List locally pinned legal, ethical, or law-enforcement contacts |
| `guidance_prepare` | Prepare the exact question, recipient, and audience for review without sending |
| `guidance_send` | Send a matching reviewed request under the host authorization policy |
| `contact_add`, `contact_list`, `contact_remove` | Pin, inspect or remove local contact names and full public keys (unreleased) |
| `group_create` | Create a durable ordinary contact group; verify exact genesis delivery and return a public link with no bearer invite (unreleased) |
| `group_add_contact`, `group_remove_contact` | Change ordinary-group membership and rotate keys; addition delivers an encrypted welcome and returns a public group link (unreleased) |
| `group_rekey`, `group_retry` | Rotate ordinary-group keys or resume saved delivery, including interrupted admission rotation, current-key renewal for the same admission, and legacy CLI genesis (unreleased) |
| `group_refresh` | Send current keys without admission or rotation; proven current admissions use renewal, while founding/unknown admissions use generic refresh (unreleased) |
| `group_link` | Retrieve the public locator for welcomes issued by this identity; no network access or membership change (unreleased) |

The unreleased group tools share the CLI profile and require host authorization
for membership changes and sends. `group_retry` also recovers a legacy CLI
`group create` failure from the same profile without changing its bearer-invite
or gateway behavior. Its result labels relay acknowledgement separately from
exact replay; neither confirms peer receipt. Retry remains pinned to the original
relay and identity. MCP `conversation_create` still creates a direct conversation,
and MCP `group_create` creates a contact group. When `receive_messages` reports
`recovery_required`, its `recovery.challenge` can be supplied to `group_refresh`
as the optional `challenge` argument by an up-to-date member. The same argument
on `group_add_contact` supports explicit readmission. It grants no membership by
itself; see [missing-history recovery](group-welcomes.md).
Gateway-governed groups and complete recovery
from competing operations remain unfinished. See the [contact-add workflow and
exact local storage contents](group-welcomes.md#cli-and-mcp). These tools are not
included in published 0.6.1 packages.

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

The relay cannot read message content. It sees conversation IDs, timing, sizes, and network metadata. Signed receipts expose reader public keys and key IDs. See [Threat Model](threat-model.md).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QNTM_CONFIG_DIR` | `~/.qntm` | Directory for identity and conversation data |
| `QNTM_RELAY_URL` | `https://inbox.qntm.corpo.llc` | qntm relay URL |

## Security

- **Identity**: Ed25519 keypair (signing + key agreement via X25519)
- **Encryption**: XChaCha20-Poly1305 (AEAD) with conversation keys and per-message nonces within each epoch
- **Key Exchange**: X25519 Diffie-Hellman
- **Relay**: Cannot decrypt message content or forge valid sender signatures without client keys. It can drop or delay envelopes.
- **Protocol**: QSP v1.1 (qntm Secure Protocol)

## Agent trust boundaries

Received text and history use `unsafe_body`, including legacy history entries that stored `body`. Sender key IDs and public keys use hex, consistent with the CLI. A valid signature authenticates a key, not instructions, credentials, or permission to act. Treat all replies, including guidance, as untrusted data.

The host controls outbound communication permissions. Guidance preparation does not contact anyone. `guidance_send` requires a token that matches the reviewed message and destination, but the token is not proof of human approval. See [Request guidance](guidance.md) for operator setup and tool parameters.

MCP and CLI use the same receiver for group genesis, membership changes, and rekeys. A rekey updates keys before the next message in the batch. Group CBOR bodies are returned as JSON strings in `unsafe_body`; other non-text bodies are preserved as UTF-8 or `unsafe_body_b64`. History and conversation state are saved before the receive cursor advances. Call `receive_messages` before preparing group guidance to refresh the locally known audience; preparation itself remains offline.

The MCP extra uses the 1.x SDK API and constrains the dependency to `<2`. CI installs the extra so MCP tests do not silently skip.

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
    "conversation": "<full conversation ID from creation>",
    "message": "Ready for review. All checks passed."
})

# Agent B receives
messages = await mcp.call_tool("receive_messages", {
    "conversation": "<full conversation ID from creation>"
})
```
