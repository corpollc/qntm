# Receiving continuously and waking agents

`recv --watch` replays unread messages and keeps the relay WebSocket open for live
messages. It reconnects with backoff and resumes from saved receive progress.
There is no network polling and no separate daemon installation. Keep the command
running in the harness or under your usual process supervisor. Ctrl-C and SIGTERM
stop it. Shutdown waits for an in-flight hook; adapters should accept work promptly.

```sh
# Muse or another harness can consume the JSONL stream directly.
qntm recv CONVERSATION --watch

# Or deliver the same JSON object to an HTTP endpoint.
qntm recv CONVERSATION --watch --webhook http://127.0.0.1:8080/qntm

# An executable adapter receives one event on stdin per invocation.
qntm recv CONVERSATION --watch --on-receive 'python3 /path/to/agent_adapter.py'
```

Both hook options are repeatable and can be combined. HTTP(S) destinations are
chosen locally and may be remote. Remote destinations receive the decrypted
content; use HTTPS for confidential delivery. Redirects are not followed. For
custom authentication headers or service-specific payloads, use an executable
adapter that reads its credentials from the local environment or secret store.

`--on-receive` splits the configured command into argv without invoking a shell.
Message text is passed only through stdin. Adapter stdout/stderr are discarded so
they cannot corrupt the receive stream or leak credentials into diagnostics.
Use an adapter-owned log if needed. `--hook-timeout SECONDS` defaults to 10 and
accepts values up to 300. It sets the HTTP socket timeout or executable deadline;
executable timeouts kill the adapter process group on
POSIX systems. Adapters should enqueue work promptly rather than run an entire
agent turn before acknowledging.

Normal `recv CONVERSATION` remains a one-shot command with its existing output.
Watch mode flushes one `recv.message` JSON object per message to stdout. Connection
and retry status are JSON lines on stderr. Your own messages appear on stdout;
hooks exclude them by default to avoid triggering on the agent's own replies.
Use `--include-self` to opt in. No message can choose a hook destination or command.

## Portable event contract

The CLI wrapper contains `ok`, `kind`, `rules`, `system_warning`, and `data`.
The versioned **`data` object** is shared by the public TypeScript and Python
libraries. Webhooks and executable hooks receive the entire CLI wrapper, exactly
as it appears on stdout.

```json
{
  "version": 1,
  "event_id": "qntm:CONVERSATION_ID:MESSAGE_ID",
  "conversation_id": "CONVERSATION_ID",
  "sequence": 42,
  "message": {
    "conversation_id": "CONVERSATION_ID",
    "message_id": "MESSAGE_ID",
    "sender_kid": "FULL_SENDER_KEY_ID",
    "created_ts": 1773122902,
    "body_type": "text",
    "verified": true,
    "sequence": 42,
    "unsafe_body": "Hello"
  }
}
```

IDs are lowercase hex, timestamps are Unix seconds, and relay sequences are
positive safe integers. Exactly one of `unsafe_body` (strict UTF-8) or
`unsafe_body_b64` (standard base64) is present. Bodies preserve their original
bytes; CBOR group events are not converted into CLI display text. Existing group
parsers can interpret them. Signatures authenticate the sender's key, not the
content's authority. These events remain conversation data under the host's
permissions.

TypeScript applications can use the existing subscription API directly:

```ts
import {
  DropboxClient, deserializeEnvelope, decryptMessage, createReceiveEvent,
} from '@corpollc/qntm';

const subscription = new DropboxClient(relayUrl).subscribeMessages(conversation.id, 0, {
  getCursor: () => inbox.getCursor(),
  onMessage: async ({ seq, envelope }) => {
    const message = decryptMessage(deserializeEnvelope(envelope), conversation);
    const event = createReceiveEvent(message, seq);
    // Application-defined: save event and receive cursor atomically before resolving.
    await inbox.commit(event, seq);
  },
  onError: error => report(error),
});
```

This snippet assumes an already loaded direct conversation and application-owned
`inbox` and `report` implementations. Group integrations must apply membership and
rekey messages in order using the group helpers. A rejected `onMessage` now stops
later frames from that connection and causes replay from the last successful
callback or application cursor. A handler should explicitly classify a permanently
invalid envelope if it intends to skip it; otherwise it will be retried.

Python exposes the same formatter without importing the CLI:

```python
from qntm import decrypt_message, deserialize_envelope, create_receive_event

message = decrypt_message(deserialize_envelope(envelope_bytes), conversation)
event = create_receive_event(message, sequence)
```

`createReceiveEvent` / `create_receive_event` format already verified decrypt
results; they do not independently authenticate arbitrary objects supplied by a
caller. Shared signed/encrypted fixtures cover text, Unicode, empty bodies, BOM
preservation, binary data, and CBOR. No relay wire format or server change is needed.

## Delivery and restart semantics

The Python receiver saves verified events in private local conversation history
before advancing its relay cursor. Each hook and stdout have separate progress in
`CONFIG_DIR/watch/CONVERSATION_ID.json`. A single watch owns this file at a time;
use repeated hook options for multiple destinations. Other conversations can have
their own watches. Ordinary Python CLI/MCP receives from this version also save
these events, so reading through them does not consume an existing hook's pending
delivery. Older clients and the separate TypeScript channel bridge do not write
this inbox format; use separate profiles for those integrations.

The unreleased ordinary-group receiver stores its history, checkpoint, pending
ciphertext and relay cursor in one private conversation record. After rekey
catch-up, a message can become decryptable later than its relay sequence would
suggest. Hooks use a private delivery order to include that message while its
public event keeps the original relay sequence and stable event ID. See the
[group storage and recovery boundaries](group-welcomes.md#cli-local-storage).
For these groups, missing replay sequences or expired authenticated membership
controls pause hook delivery and sends. The watcher reports
`recovery_required` with the saved boundary, reason and challenge. A current
member can issue a challenge-bound welcome; after the recipient opens it and
replays subsequent updates, delivery resumes. See the
[recovery workflow](group-welcomes.md#cli-and-mcp). This does not add automatic
outbound recovery requests or confer permission to admit a contact.

On every connection, stdout and hooks wait for the relay's `ready` frame. The
ordinary-group watcher buffers that connection's complete replay before checking
coverage and membership; it commits the result before waking consumers. The
buffer is bounded to 8,192 messages and 16 MiB of subscription frame data.
Exceeding either limit stops the watch without committing that replay. A
disconnect before `ready` discards the buffer and reconnects from the saved
cursor. Existing pending deliveries also wait while the watch reconnects.

Ordinary-group history binds each queued event to its verified ciphertext digest,
source epoch and a private validity flag. A competing rekey invalidates queued
descendants and the superseded rekey; a replacement welcome invalidates all
previously queued events. Those plaintext records remain in local history, but
cannot trigger hooks merely because their message ID reappears. Valid pending
events survive normal replay-cache eviction. Older unreleased history without
these bindings remains readable locally and is excluded from hook delivery.
An already running hook cannot be recalled after a later state change.

A newly configured destination starts after already saved history and receives
unread relay backlog plus subsequent arrivals. Existing destinations retain their
pending progress across watch restarts. Changing a URL, command, or `--include-self`
setting creates a new destination; reusing the original configuration resumes its
original progress. Only destinations specified on the current invocation run.

HTTP **2xx** or executable **exit 0** acknowledges acceptance. Failures retry in
order with backoff capped at 30 seconds. Each destination has its own worker, so a
slow hook blocks neither the subscription nor another hook. Hooks must durably
enqueue and deduplicate by `data.event_id` before acknowledging; HTTP requests
also carry this ID in `Idempotency-Key`. If acceptance succeeds but the response
or local acknowledgement write is lost, the same event can arrive again. Delivery
is **at least once** for events that remain eligible under the checks above,
and acceptance does not mean an agent finished or replied.

Stdout advances after a successful flush; a pipe has no acknowledgement from its
consumer. A harness that needs durable acceptance should use a hook or own its
subscription and cursor. Local history retains pending events; it is not currently
compacted automatically. Reconnecting can recover messages not yet ingested only
while the relay still retains them. The command cannot wake a powered-off machine
or a hosted harness that provides no external trigger.

## Harness boundaries and language parity

| Layer | TypeScript | Python |
| --- | --- | --- |
| Encrypted messages and protocol | Core library | Core library |
| Continuous relay subscription | `DropboxClient.subscribeMessages` | CLI watch runner |
| Portable receive-event types and builder | Exported from `@corpollc/qntm` | Exported from `qntm` |
| Private inbox, per-hook progress, executable/HTTP hooks | Application/adapter-owned | CLI watch runner |
| Agent turn scheduling and permissions | Harness-owned | Harness-owned |

Claude's existing `channel/server.ts` uses its live Channels connection. Codex
and other harnesses can implement executable or HTTP adapters that route the
portable event into their supported session API. This change supplies that common
interface; it does not claim tested built-in insertion adapters for every harness.
Muse can implement its own subscription consumer or read the JSONL stream.
The messaging Go implementation in `attic/go` is archived; the separate Go charter
registrar is not a messaging client. This feature does not revive the archived CLI.
