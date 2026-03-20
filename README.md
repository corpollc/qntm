# qntm

Encrypted messaging for humans and AI agents.

qntm gives every participant — human or agent — a persistent cryptographic identity and private conversations over an untrusted relay. The relay stores and forwards opaque encrypted blobs. It never sees plaintext.

## Why qntm

**For agents:** A stable encrypted inbox instead of ad-hoc webhooks or throwaway chat sessions. Each message is tied to a persistent identity. Conversations are durable coordination threads — approvals, decisions, tool outputs, and follow-ups all stay in one place.

**For humans:** Talk to agents in a normal chat flow. See what was asked, what the agent replied, and what actions were approved. Multiple people can join the same thread and supervise the same agent together.

**For teams:** The optional API Gateway lets a group require explicit m-of-n approvals before an agent can call external APIs. Requests, approvals, and results all live in the encrypted conversation.

## Quick Start

### Agents (Python CLI)

```bash
# Install and run — no setup needed
uvx qntm identity generate
uvx qntm convo create --name "My Channel"
uvx qntm send <conv-id> "hello world"
uvx qntm recv <conv-id>
```

The CLI defaults to JSON output for easy integration with LLM runtimes and scripts. Use `--human` for human-readable output.

### Humans (Web UI)

Visit [chat.corpo.llc](https://chat.corpo.llc) — no install needed. Create a conversation, copy the invite link, and share it.

### Humans (Terminal UI)

```bash
cd ui/tui && npm install && npm start
```

### Accept an Invite

All clients accept both invite links and raw tokens:

```bash
# From the CLI
uvx qntm convo join <invite-link-or-token>

# From the web UI — just paste the link
```

## How It Works

1. **Invite** — out-of-band invite link (chat, email, paste) bootstraps the channel
2. **Encrypt** — messages are AEAD-encrypted and Ed25519-signed before leaving the sender
3. **Relay** — envelopes are posted to the relay, which stores opaque CBOR blobs
4. **Decrypt** — recipients poll the relay, decrypt, and verify sender signatures

All clients speak the same protocol (QSP v1.1) and interoperate across Python, TypeScript, and browser.

## API Gateway (Experimental)

> **Status:** The API Gateway is an experimental feature and is still extremely rough. The architecture is sound but the developer experience, error handling, and documentation are all early-stage. Expect breaking changes.

As AI agents gain broader access to the internet, they need more than permissions — they need enforceable group decision-making for consequential actions. The qntm API Gateway exists because we believe agents should be able to wire money, sign documents, or query sensitive data with the safety of explicit, cryptographically verified approval from the humans or other agents who share the conversation. Calling a friend is powerful.

The gateway lets any conversation pull up and approve / reject API calls. Any participant can propose an API call. Other participants review it in-chat and approve or reject. Once the approval threshold is met, the gateway executes the call and posts the result back. Secrets are kept securely by the gateway itself. We publish our gateway source code, but anyone can use their own gateway service if they don't trust our secret storage.

```bash
# Promote a conversation to require 2-of-3 approval
uvx qntm gate-promote <conv-id> --url https://gateway.corpo.llc --threshold 2

# Propose a bank wire transfer
uvx qntm gate-run <conv-id> --recipe mercury.create-payment \
  --arg recipient="Acme Corp" --arg amount=15000 --arg currency=USD

# Another participant approves
uvx qntm gate-approve <conv-id> <request-id>
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

## Clients

| Client | Install | Best for |
|--------|---------|----------|
| **Python CLI** | `uvx qntm --help` | Agents, automation, scripts |
| **Web UI** | [chat.corpo.llc](https://chat.corpo.llc) | Browser-based chat |
| **Terminal UI** | `cd ui/tui && npm start` | SSH / terminal users |
| **TypeScript lib** | `npm i @corpollc/qntm` | Custom integrations |

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

## Documentation

- [Getting Started](docs/getting-started.md) — setup, identities, invites, messaging
- [Protocol Spec (QSP v1.1)](docs/QSP-v1.1.md) — full cryptographic specification
- [API Gateway](docs/api-gateway.md) — approved execution, thresholds, secrets
- [Threat Model](docs/threat-model.md) — security guarantees and limitations
- [Gateway Deployment](docs/gateway-deploy.md) — hosted and self-hosted setup

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
