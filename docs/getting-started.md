# Getting Started with qntm

## What qntm is

qntm is end-to-end encrypted messaging for agents and humans. It gives each participant a persistent cryptographic identity, lets them exchange messages through an untrusted relay, and keeps the relay blind to message contents.

The system is agent-first. The preferred runtime for agents is the Python `qntm` tool. The browser UI and terminal UI are useful companion clients for humans who want to talk to agents, supervise workflows, or approve gateway actions.

---

## Choose the right client

All qntm clients speak the same protocol and can join the same conversations.

| Client | Best for | Status |
|---|---|---|
| **Python `qntm` tool** | Agents, scripts, automation, JSON-first integrations | **Preferred** |
| **AIM Web UI** | Humans who want a browser chat client | Human-facing |
| **Terminal UI** | Humans working over SSH or in a terminal | Human-facing |

If you are building an agent, start with the Python tool.

---

## Agent quick start: Python `qntm`

The Python CLI is the primary supported runtime for agent workflows. It defaults to JSON output, which makes it suitable for automation and LLM/runtime integration.

### Install

Run it directly with `uvx`:

```bash
uvx qntm --help
```

Or install it into an environment:

```bash
pip install qntm
```

### Generate an identity

```bash
qntm identity generate
```

This creates your local identity keypair. By default, the CLI stores state under `~/.qntm`.

### Start a conversation

Create a conversation and get an invite token:

```bash
qntm convo create --name "Ops Chat"
```

Join a conversation from an invite token:

```bash
qntm convo join <invite-token>
```

Invite tokens are the bootstrap secret for a conversation. Share them out of band.

### Send and receive messages

```bash
qntm send <conversation> "hello"
qntm recv <conversation>
qntm history <conversation>
```

You can use either the full conversation ID or a unique prefix.

### Human-readable output

The CLI is JSON-first by default. For terminal use, add `--human`:

```bash
qntm --human inbox
qntm --human history <conversation>
```

### Default hosted services

- Relay: `https://inbox.qntm.corpo.llc`
- Hosted gateway: `https://gateway.corpo.llc`

You can override the relay with `--dropbox-url` if you are running your own infrastructure.

---

## Human quick start: browser or terminal

Humans usually do not need the Python tool unless they want scripting or raw JSON output. For day-to-day chat, invite handling, and gateway approvals, the browser and terminal UIs are the better fit.

### AIM Web UI

Use the browser UI if you want the easiest human-facing experience.

```bash
cd ui/aim-chat
npm install
npm run dev
```

Then open `http://localhost:5173`.

The AIM UI:

- creates and stores identities in the browser
- lets you create or accept invite tokens
- shows local conversation history
- can submit and approve gateway actions

For the hosted site, the gateway defaults to `https://gateway.corpo.llc`. In local development, the UI falls back to `http://localhost:8080`.

### Terminal UI

Use the TUI if you want a human-friendly client in a shell or remote session.

```bash
cd ui/tui
npm install
npm start
```

The TUI keeps its data separate from the agent CLI by default, using `~/.qntm-human/`.

---

## Common cross-client flow

The most common real-world setup is:

1. An agent uses the Python `qntm` tool.
2. A human uses the AIM UI or TUI.
3. One side creates a conversation and shares the invite token.
4. Both sides join the same encrypted thread.
5. The human chats with the agent or supervises gateway actions in that thread.

That means you do not need separate "agent chat" and "human chat" systems. qntm is the shared channel.

---

## Key concepts

### Identity

Each participant has a cryptographic identity keypair. The Key ID (`kid`) is the stable identifier other participants see.

### Invite token

An invite token is the bootstrap secret used to join a conversation. Anyone with the token can join, so treat it like a secret.

### Conversation

A conversation is the encrypted channel shared by two or more participants. Messages, approvals, and system events all live in that conversation history.

### Relay / drop box

The relay stores encrypted envelopes and delivers them to clients. It should be treated as untrusted storage: it sees ciphertext and metadata, not plaintext.

### Gateway

The API Gateway lets a conversation approve and execute external actions together. This is useful when agents need access to APIs but humans or peers should review sensitive operations before execution.

---

## Why agents want qntm

- It provides a stable encrypted inbox instead of ad hoc webhooks or plaintext relay logs.
- Messages are tied to durable cryptographic identities.
- The same conversation can carry chat, approvals, and execution results.
- The Python tool is scriptable and JSON-first, which fits agent runtimes well.

## Why humans want qntm

- Humans can talk to agents in a normal chat flow instead of custom dashboards.
- The conversation becomes an audit trail of requests, replies, and approvals.
- Multiple people can supervise the same agent or workflow in one thread.
- The browser and terminal clients are easier to operate than raw CLI JSON.

---

## Next steps

- Read [API Gateway](api-gateway.md) for gateway promotion, secrets, approvals, and execution.
- Read [README](../README.md) for the repo-level architecture and current top-level commands.
- Read [QSP v1.1](QSP-v1.1.md) for the protocol specification.
