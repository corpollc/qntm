# Client and library parity

The TypeScript library is a first-class qntm client. Python and TypeScript share QSP v1.1 envelopes, cryptography, group controls, and encrypted interoperability fixtures. Host process management and tool interfaces sit above that protocol.

| Capability | Python | TypeScript | Go |
| --- | --- | --- | --- |
| Identity, invite, signed encrypted messages | Library and CLI | Library, browser and Node | Old messaging implementation is archived in `attic/` |
| Persistent relay subscription | `recv --watch` owns reconnect and durable profile state | `DropboxClient.subscribeMessages` owns reconnect; application owns durable state | No maintained messaging client |
| Portable receive event | `ReceiveEvent`, `create_receive_event` | `ReceiveEvent`, `createReceiveEvent` | Not implemented |
| Webhook or executable delivery | CLI hook runner with independent retries | Application-owned; the Claude channel has a durable MCP outbox | Not implemented |
| Gateway and governance | Full CLI workflows | Protocol/signing helpers and browser workflows; no equivalent all-in-one library controller | Gateway is TypeScript |
| Guidance contacts | CLI and MCP local configuration/review/send | Browser local configuration/review/send | Not implemented |
| Experimental charter v0.2 | Not implemented | Opt-in `@corpollc/qntm/charter` library | Durable reference registrar in `charter-registry/` |

The CLI's hook runner is client behavior: it needs no new relay endpoint. Muse and other hosts can consume the continuous JSONL subscription directly. Codex, Claude, Grok, or another harness can consume the same event through a local adapter; qntm does not ship or claim tested native insertion adapters for every harness. The Claude channel is the included MCP bridge. OpenClaw and NanoClaw ship separate chat transport integrations.

Tests cover shared encrypted receive fixtures, Python 3.10/3.12, TypeScript crypto and subscriptions, the Go/TypeScript charter boundary, browser/CLI/gateway journeys, terminal PTY input, and adapter contracts. Adapter tests do not establish compatibility with every independently updated agent host. See [release checks](deployment-checklist.md) and [receive hooks](receive-hooks.md).
