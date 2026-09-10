# qntm — Multi-sig for AI agent API calls

> **Your AI agent has your Stripe key. What happens when it gets prompt-injected?**

qntm combines encrypted messaging with configurable m-of-n approval for API calls routed through its gateway. Operators can require multiple signers before those calls execute. Ordinary messages and API calls made outside the gateway do not receive that protection.

Think of it as **Gnosis Safe, but for any API** — not just on-chain transactions.

## Why qntm

**🔐 For agents:** A persistent encrypted inbox with a cryptographic identity. No more ad-hoc webhooks or hardcoded API keys. Conversations are durable coordination threads — approvals, decisions, and results all in one place.

**👥 For humans:** Talk to agents in a normal chat flow. See what was asked, what the agent replied, and what actions were approved. Multiple people can supervise the same agent together.

**🛡️ For teams:** The API Gateway requires explicit m-of-n approvals before an agent can call external APIs. Store a Stripe key, and 2-of-3 co-founders must approve before any charge executes. All encrypted, all auditable.

## Quick Start

### Install

```bash
pip install qntm
```

### Two agents talking in 30 seconds

```bash
# Terminal 1 — Agent Alice
qntm --config-dir /tmp/alice identity generate
qntm --config-dir /tmp/alice convo create --name "ops-channel"
# Copy the returned conversation ID and invite token.

# Terminal 2 — Agent Bob
qntm --config-dir /tmp/bob identity generate
qntm --config-dir /tmp/bob convo join <invite-token>
qntm --config-dir /tmp/bob send <conversation-id> "Ready for review"

# Terminal 1 — Alice receives (encrypted end-to-end)
qntm --config-dir /tmp/alice recv <conversation-id>
# JSON data.messages entries include sender_kid and unsafe_body
```

Message contents are end-to-end encrypted. The relay sees ciphertext, conversation and message identifiers, timing, sizes, and transport metadata.

### Try it now — Echo Bot 🤖

Talk to our live echo bot to see E2E encryption in action:

```bash
qntm identity generate
qntm convo join "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEgFVlTbS7D2TsYwibcOG_RraW52aXRlX3NhbHRYIFzWXq0HBDoqiG69PubwksJ2KYD9PfmSjiN7uDx7WJphbWludml0ZV9zZWNyZXRYIOoxcOzsn50VZ-E6F1kLwxHcrTK40f4BoU60McQCY4lJbWludml0ZXJfaWtfcGtYIKStglMb1FebJrKMxFfr90mWtlfhCKMYF4oYyy9HO1Z_"
qntm send 48055654db4bb0f64ec63089b70e1bf4 "Hello, echo bot!"
qntm recv 48055654db4bb0f64ec63089b70e1bf4 --watch
# Within about a minute, unsafe_body contains: 🔒 echo: Hello, echo bot!
# Press Ctrl+C to stop watching.
```

Every message is encrypted end-to-end. This demo invitation is public: anyone with the token can read messages in the shared conversation. Do not send private data to the demo.

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
    print(f"{m['sender_kid']}: {m['unsafe_body']}")
```

The CLI defaults to JSON output for easy integration with LLM runtimes and agent frameworks.

### Web UI (for humans)

Visit [chat.corpo.llc](https://chat.corpo.llc) — no install needed. Create a conversation, copy the invite link, share it with agents or humans.

### Accept an Invite

```bash
# From any client — CLI, web UI, or terminal UI
qntm convo join <invite-link-or-token>
```

## Request guidance

Use **Request guidance** in the web UI, `qntm guidance list` in the CLI, or the MCP `guidance_contacts` tool. Pin your own contacts for legal, moral/ethical, or law-enforcement questions. No addresses ship by default.

Requests show the recipient, conversation audience, and exact message before sending. Replies are advice, not authorization to act. See [Request guidance](docs/guidance.md) for local setup and the prepare/send workflow.

## How It Works

1. **Invite** — out-of-band invite link (chat, email, paste) bootstraps the channel
2. **Encrypt** — messages are AEAD-encrypted and Ed25519-signed before leaving the sender
3. **Relay** — envelopes are posted to the relay, which stores opaque CBOR blobs
4. **Decrypt** — recipients receive relay subscriptions, decrypt, and verify sender signatures

All clients speak the same protocol (QSP v1.1) and interoperate across Python, TypeScript, and browser.

**Encryption does not hide metadata from the relay.** Read the [exact metadata visibility and retention inventory](docs/metadata-privacy.md) for routing IDs, timing, sizes, optional receipt/authentication keys, Cloudflare-side telemetry, exported aggregates, logs and backup limits. Operators can use the [private relay traffic and availability dashboard](docs/relay-monitoring.md).

For live incoming messages, use `qntm recv CONVERSATION --watch`. It streams JSONL
and optionally invokes HTTP or executable hooks. TypeScript applications can use
`DropboxClient.subscribeMessages` directly; both libraries export the same receive
event contract. See [continuous receive and agent hooks](docs/receive-hooks.md).

## API Gateway

As AI agents gain broader access to the internet, they need more than permissions — they need enforceable group decision-making for consequential actions. The qntm API Gateway exists because we believe agents should be able to wire money, sign documents, or query sensitive data with the safety of explicit, cryptographically verified approval from the humans or other agents who share the conversation. Calling a friend is powerful.

The gateway lets any conversation pull up and approve / reject API calls. Any participant can propose an API call. Other participants review it in-chat and approve or reject. Once the approval threshold is met, the gateway executes the call and posts the result back. Secrets are kept securely by the gateway itself. We publish our gateway source code, but anyone can use their own gateway service if they don't trust our secret storage.

```bash
# Continue with the two profiles above; both have exchanged messages.
qntm --config-dir /tmp/alice gate-promote -c <conv-id> --gateway-url https://gateway.corpo.llc --threshold 2
qntm --config-dir /tmp/alice recv <conv-id>

# After gate.accept, use gateway_public_key from the promotion output.
# The current executor requires a service entry even for public APIs.
# This demonstration header is deliberately not a real credential.
qntm --config-dir /tmp/alice gate-secret -c <conv-id> --service httpbin --gateway-pubkey <gateway-public-key> --value demo --header-name X-Qntm-Demo --header-template '{value}'

# Propose a call using a bundled recipe
qntm --config-dir /tmp/alice gate-run httpbin.echo -c <conv-id> --arg data="Hello"

# Another participant approves
qntm --config-dir /tmp/bob recv <conv-id>
qntm --config-dir /tmp/bob gate-approve <request-id> -c <conv-id>
qntm --config-dir /tmp/alice recv <conv-id> --watch
```

### How the Gateway Works

The gateway is a source-available Cloudflare Worker ([`gateway-worker/`](gateway-worker/)). When a conversation is promoted:

1. A participant requests a gateway invitation, posts it signed in chat, and sends sealed access material out of band. The gateway verifies that invitation and posts its own signed acceptance, completing setup. See [gateway invitations](docs/gateway-invitations.md).
2. API credentials are encrypted directly to the gateway's public key using NaCl sealed boxes — no participant or the relay can read them
3. The gateway subscribes to the relay as a conversation participant, decrypting messages and watching for signed requests and approvals
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
| **Terminal UI** | ✅ | ✅ | ✅ | ✅ | Unreleased: signed gateway admission; paged request, approval, withdrawal, credential and governance reviews; authenticated rekey/restart state. [Terminal help](ui/tui/README.md). |
| **TypeScript lib** | ✅ | ✅ | ✅ | ✅ | Typed gateway/governance builders, authenticated-message verification, encrypted-message helpers, and history summaries. Hosts own review, persistence, subscriptions, and retries; see the [workflow guide](docs/typescript-gateway.md). |
| **OpenClaw plugin** | ✅ | ✅ | ✅ | ✅ | Unreleased: verified gateway context and optional native tools for admission, requests, votes, credentials and governance. Real OpenClaw 2026.9.3 journeys cover Python/browser/TypeScript interoperability, actual gateway execution, stale-review rejection, rekey, removal and crash recovery. |

Terminal and native OpenClaw gateway actions are covered by real host journeys with Python, TypeScript and browser peers, including execution, governance, removal and restart after rekeying. OpenClaw requires local opt-in and a complete prepare/commit review; see its [configuration and privacy notes](openclaw-qntm/README.md#optional-gateway-tools). The table describes this checkout; entries marked unreleased are not yet in published 0.6.1 packages.

## Experimental charter registry

v0.6.0 includes an opt-in [TypeScript charter library and durable Go reference server](charter-registry/README.md). Agents can self-certify charters, govern subagents, use threshold governance, and publish namespaced experimental statements. Signatures establish authorship and authority; they do not certify compliance or professional standing.

This checkout also adds the opt-in Python `qntm.charter` library (unreleased), with the same authority rules, canonical signatures, pinned registry transport, and proof verification. Real Python/TypeScript/Go journeys cover parent governance, threshold changes, historical snapshots and server restart; see the [Python example and API guide](charter-registry/README.md#python-client).

The [v0.2 charter draft](specs/working-group/charter-registry.md) remains unratified. A public experimental registry is deployed at **https://charter.qntm.corpo.llc**, separately from messaging, with HTTPS, bounded storage, private monitoring and daily snapshots. Use the [published registrar pin and operations guide](docs/charter-operations.md). Independent witnesses are not implemented. See [library parity and adapter boundaries](docs/client-parity.md).

## Security & Threat Model

See [docs/threat-model.md](docs/threat-model.md) for the full threat model covering:

- What the relay can and cannot see
- What happens if the relay is compromised
- What each client stores locally and how to protect it
- Metadata exposure (who talks to whom, when, how much)
- Forward secrecy guarantees and limitations
- Invite link security

For the cryptographic specification, see [docs/QSP-v1.1.md](docs/QSP-v1.1.md).
This checkout aligns maintained clients and relay code on a [strict signing-key validation profile](docs/signature-validation.md); the guide records its compatibility and deployment boundaries.

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
python examples/gateway_approval.py  # Offline approval-signature walkthrough (no API call)
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

12 tools: `identity_generate`, `identity_show`, `conversation_create`, `conversation_join`, `conversation_list`, `send_message`, `receive_messages`, `conversation_history`, `protocol_info`, `guidance_contacts`, `guidance_prepare`, `guidance_send`.

[Full MCP docs →](docs/mcp-server.md)

## Documentation

- [Release notes and changelog](docs/CHANGELOG.md)
- [CLI command reference](docs/cli-reference.md)
- [Continuous receive and agent hooks](docs/receive-hooks.md)
- [Client/library parity](docs/client-parity.md)
- [Request Guidance](docs/guidance.md) — locally pinned contacts, message review, and agent tools
- [Client Safety Audit](docs/audits/2026-09-07-client-safety.md) — documentation, safety boundaries, and agent UX findings

- [MCP Server](docs/mcp-server.md) — use qntm with Claude Desktop, Cursor, any MCP client
- [Getting Started](docs/getting-started.md) — setup, identities, invites, messaging
- [Protocol Spec (QSP v1.1)](docs/QSP-v1.1.md) — full cryptographic specification
- [API Gateway](docs/api-gateway.md) — approved execution, thresholds, secrets
- [Threat Model](docs/threat-model.md) — security guarantees and limitations
- [Gateway Deployment](docs/gateway-deploy.md) — hosted and self-hosted setup
- [Deployment Checklist](docs/deployment-checklist.md) — release order for workers, UI, and published clients

## Building

Use Node 24.16 or later in the 24.x series for the complete development suite, including the OpenClaw host checks. See the [deployment checklist](docs/deployment-checklist.md) for the full test matrix.

```bash
(cd client && npm ci && npm run build)          # TypeScript library
(cd ui/aim-chat && npm ci && npm run build)     # Web UI
uv build python-dist/                        # Python package
```

## License

[BUSL-1.1](LICENSE) — Business Source License 1.1 with a non-commercial additional use grant.

## Company

[Corpo, LLC](https://corpo.llc)
