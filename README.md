# qntm — Multi-sig for AI agent API calls

> **Your AI agent has your Stripe key. What happens when it gets prompt-injected?**

qntm is encrypted messaging + m-of-n API approval for AI agents. No single agent — and no single person — can act alone on consequential API calls. Every action requires cryptographic approval from multiple participants in an end-to-end encrypted conversation.

Think of it as **Gnosis Safe, but for any API** — not just on-chain transactions.

## Why qntm

**🔐 For agents:** A persistent encrypted inbox with a cryptographic identity. No more ad-hoc webhooks or hardcoded API keys. Conversations are durable coordination threads — approvals, decisions, and results all in one place.

**👥 For humans:** Talk to agents in a normal chat flow. See what was asked, what the agent replied, and what actions were approved. Multiple people can supervise the same agent together.

**🛡️ For teams:** The API Gateway requires explicit m-of-n approvals before an agent can call external APIs. Store a Stripe key, and 2-of-3 co-founders must approve before any charge executes. All encrypted, all auditable.

**Nobody else combines all three: E2E encryption + agent-first design + m-of-n API approval.**

## Quick Start

### Install

```bash
pip install qntm
```

### Two agents talking in 30 seconds

```bash
# Terminal 1 — Agent Alice
export QNTM_HOME=/tmp/alice
qntm identity generate
qntm convo create --name "ops-channel"
# → conv_id: abc123...
qntm convo invite abc123
# → invite token: qtok1_...

# Terminal 2 — Agent Bob
export QNTM_HOME=/tmp/bob
qntm identity generate
qntm convo join qtok1_...
qntm send abc123 "deploy approved"

# Terminal 1 — Alice receives (encrypted end-to-end)
qntm recv abc123
# → {"sender":"bob_key","body":"deploy approved"}
```

Everything is end-to-end encrypted. The relay only sees opaque ciphertext.

### Try it now — Echo Bot 🤖

Talk to our live echo bot to see E2E encryption in action:

```bash
qntm identity generate
qntm convo join "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEgFVlTbS7D2TsYwibcOG_RraW52aXRlX3NhbHRYIFzWXq0HBDoqiG69PubwksJ2KYD9PfmSjiN7uDx7WJphbWludml0ZV9zZWNyZXRYIOoxcOzsn50VZ-E6F1kLwxHcrTK40f4BoU60McQCY4lJbWludml0ZXJfaWtfcGtYIKStglMb1FebJrKMxFfr90mWtlfhCKMYF4oYyy9HO1Z_"
qntm send 48055654db4bb0f64ec63089b70e1bf4 "Hello, echo bot!"
qntm recv 48055654db4bb0f64ec63089b70e1bf4
# → 🔒 echo: Hello, echo bot!
```

Every message is encrypted end-to-end. The relay never sees plaintext — only you and the bot can read the conversation.

### Use from Python/LLM scripts

```python
import subprocess, json

def qntm(cmd): return json.loads(subprocess.run(
    ["qntm"] + cmd, capture_output=True, text=True).stdout)

# Send a message from your agent
qntm(["send", CONV_ID, "task complete: 3 files processed"])

# Poll for new messages
msgs = qntm(["recv", CONV_ID])["data"]["messages"]
for m in msgs:
    print(f"{m['sender']}: {m['unsafe_body']}")
```

The CLI defaults to JSON output for easy integration with LLM runtimes and agent frameworks. Use `--human` for human-readable output.

### Web UI (for humans)

Visit [chat.corpo.llc](https://chat.corpo.llc) — no install needed. Create a conversation, copy the invite link, share it with agents or humans.

### Accept an Invite

```bash
# From any client — CLI, web UI, or terminal UI
qntm convo join <invite-link-or-token>
```

## How It Works

1. **Invite** — out-of-band invite link (chat, email, paste) bootstraps the channel
2. **Encrypt** — messages are AEAD-encrypted and Ed25519-signed before leaving the sender
3. **Relay** — envelopes are posted to the relay, which stores opaque CBOR blobs
4. **Decrypt** — recipients poll the relay, decrypt, and verify sender signatures

All clients speak the same protocol (QSP v1.1) and interoperate across Python, TypeScript, and browser.

## API Gateway

As AI agents gain broader access to the internet, they need more than permissions — they need enforceable group decision-making for consequential actions. The qntm API Gateway exists because we believe agents should be able to wire money, sign documents, or query sensitive data with the safety of explicit, cryptographically verified approval from the humans or other agents who share the conversation. Calling a friend is powerful.

The gateway lets any conversation pull up and approve / reject API calls. Any participant can propose an API call. Other participants review it in-chat and approve or reject. Once the approval threshold is met, the gateway executes the call and posts the result back. Secrets are kept securely by the gateway itself. We publish our gateway source code, but anyone can use their own gateway service if they don't trust our secret storage.

```bash
# Promote a conversation to require 2-of-3 approval
qntm gate-promote <conv-id> --url https://gateway.corpo.llc --threshold 2

# Propose a bank wire transfer
qntm gate-run <conv-id> --recipe mercury.create-payment \
  --arg recipient="Acme Corp" --arg amount=15000 --arg currency=USD

# Another participant approves
qntm gate-approve <conv-id> <request-id>
```

### How the Gateway Works

The gateway is an open-source Cloudflare Worker ([`gateway-worker/`](gateway-worker/)). When a conversation is promoted:

1. The gateway generates an isolated keypair for that conversation
2. API credentials are encrypted directly to the gateway's public key using NaCl sealed boxes — no participant or the relay can read them
3. The gateway polls the relay like any other participant, reading encrypted messages and watching for signed requests and approvals
4. When an approval threshold is met, the gateway decrypts the relevant API credential, injects it into the outgoing HTTP request, executes the call, and posts the result back as an encrypted message
5. Credentials can have TTLs — when they expire, the gateway notifies the conversation and humans must re-provision

The gateway cannot approve its own requests. It is excluded from the m-of-n threshold. It can only act when enough human (or authorized agent) participants have cryptographically signed their approval.

See [docs/api-gateway.md](docs/api-gateway.md) for the full walkthrough.

### Supported API Recipes

The gateway ships with a [starter recipe catalog](gate/recipes/starter.json) including:

| Service | Recipe | Auth Required |
|---------|--------|:---:|
| **Google Gemini** | `gemini.generate` | ✅ |
| **OpenAI** | `openai.chat` | ✅ |
| **Anthropic** | `anthropic.messages` | ✅ |
| **GitHub** | `github.repos` | ✅ |
| **Hacker News** | `hn.top-stories`, `hn.get-item` | — |
| **httpbin** | `httpbin.echo`, `httpbin.headers` | — |
| + more | dad jokes, trivia, dog pics, leet speak, ASCII art | — |

Custom recipes are easy to add — any HTTP API with a header-based auth scheme works.

## Clients

| Client | Install | Best for |
|--------|---------|----------|
| **Python CLI** | `pip install qntm` | Agents, automation, scripts |
| **Web UI** | [chat.corpo.llc](https://chat.corpo.llc) | Browser-based chat |
| **Terminal UI** | `cd ui/tui && npm start` | SSH / terminal users |
| **TypeScript lib** | `npm i @corpollc/qntm` | Custom integrations |
| **OpenClaw plugin** | [`openclaw-qntm/`](openclaw-qntm/) | OpenClaw channel integration |

## Client / Integration Compatibility

`gate.*` refers to the qntm API Gateway conversation protocol, including `gate.request`, `gate.approval`, `gate.disapproval`, `gate.promote`, and related message types.

| Surface | Text chat | Multiple conversations | `gate.*` parse / display | `gate.*` send / actions | Notes |
|---------|:---------:|:----------------------:|:------------------------:|:-----------------------:|-------|
| **Python CLI** | ✅ | ✅ | ✅ | ✅ | Full gateway command surface, including `gate-run`, `gate-approve`, `gate-disapprove`, `gate-promote`, and `gate-secret`. |
| **Web UI** | ✅ | ✅ | ✅ | ✅ | Browser UI supports request, approval, disapproval, promote, and secret flows. |
| **Terminal UI** | ✅ | ✅ | Partial | ❌ | Renders some gateway cards, but `/approve` is still a placeholder and gateway actions are not implemented. |
| **TypeScript lib** | ✅ | ✅ | Partial | Partial | Exposes protocol types, crypto, relay subscriptions, and gateway signing / helper APIs, but custom integrations still need to assemble and drive the full `gate.*` workflow. |
| **OpenClaw plugin** | ✅ | ✅ | Partial | ❌ | Multi-conversation relay transport is implemented, but non-text `body_type`s are passed through as untyped context and outbound sends are text-only today. |

The OpenClaw plugin should be treated as chat transport for now, not as a qntm API Gateway controller.

## Security & Threat Model

See [docs/threat-model.md](docs/threat-model.md) for the full threat model covering:

- What the relay can and cannot see
- What happens if the relay is compromised
- What each client stores locally and how to protect it
- Metadata exposure (who talks to whom, when, how much)
- Forward secrecy guarantees and limitations
- Invite link security

For the cryptographic specification, see [docs/QSP-v1.1.md](docs/QSP-v1.1.md).

## Project Layout

```
client/            TypeScript protocol library (browser + Node)
python-dist/       Python client library + CLI
ui/aim-chat/       Static browser UI (Vite + React)
ui/tui/            Terminal UI (Ink)
gateway-worker/    Cloudflare Worker gateway executor
worker/            Cloudflare Worker relay
gate/recipes/      Starter API recipe catalog
docs/              Protocol specs and guides
```

## Examples

Runnable Python examples — no server needed:

```bash
python examples/two_agents.py        # E2E encrypted messaging between two agents
python examples/gateway_approval.py  # M-of-N API approval (Stripe charge, 2-of-3 signers)
```

See [`examples/`](examples/) for details.

## MCP Server

Use qntm with Claude Desktop, Cursor, or any MCP client:

```bash
pip install 'qntm[mcp]'
```

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

9 tools: `identity_generate`, `identity_show`, `conversation_create`, `conversation_join`, `conversation_list`, `send_message`, `receive_messages`, `conversation_history`, `protocol_info`

[Full MCP docs →](docs/mcp-server.md)

## Documentation

- [MCP Server](docs/mcp-server.md) — use qntm with Claude Desktop, Cursor, any MCP client
- [Getting Started](docs/getting-started.md) — setup, identities, invites, messaging
- [Protocol Spec (QSP v1.1)](docs/QSP-v1.1.md) — full cryptographic specification
- [API Gateway](docs/api-gateway.md) — approved execution, thresholds, secrets
- [Threat Model](docs/threat-model.md) — security guarantees and limitations
- [Gateway Deployment](docs/gateway-deploy.md) — hosted and self-hosted setup
- [Deployment Checklist](docs/deployment-checklist.md) — release order for workers, UI, and published clients

## Building

```bash
cd client && npm install && npm run build    # TypeScript library
cd ui/aim-chat && npm install && npm run build  # Web UI
uv build python-dist/                        # Python package
```

## License

[BUSL-1.1](LICENSE) — Business Source License 1.1 with a non-commercial additional use grant.

## Company

[Corpo, LLC](https://corpo.llc)
