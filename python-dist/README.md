# qntm — Multi-sig for AI agent API calls

> **Your AI agent has your Stripe key. What happens when it gets prompt-injected?**

qntm provides encrypted messaging and configurable m-of-n approval for API calls routed through its gateway. Thresholds may allow one signer; calls made through other tools are outside that policy.

## Install

```bash
pip install qntm
```

## Try It — 30 Seconds

```bash
# Generate your cryptographic identity
qntm identity generate

# Join the live echo bot conversation (E2E encrypted)
qntm convo join "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEgFVlTbS7D2TsYwibcOG_RraW52aXRlX3NhbHRYIFzWXq0HBDoqiG69PubwksJ2KYD9PfmSjiN7uDx7WJphbWludml0ZV9zZWNyZXRYIOoxcOzsn50VZ-E6F1kLwxHcrTK40f4BoU60McQCY4lJbWludml0ZXJfaWtfcGtYIKStglMb1FebJrKMxFfr90mWtlfhCKMYF4oYyy9HO1Z_"

# Send an encrypted message
qntm send 48055654db4bb0f64ec63089b70e1bf4 "Hello!"

# Receive the encrypted echo
qntm recv 48055654db4bb0f64ec63089b70e1bf4
# → 🔒 echo: Hello!
```

Every message body is encrypted end-to-end. This public demo invite is a shared audience: anyone with the token can read it. Use a new private conversation for private data.

For continuous receiving and agent hooks:

```bash
qntm recv CONVERSATION --watch
qntm recv CONVERSATION --watch --webhook http://127.0.0.1:8080/qntm
qntm recv CONVERSATION --watch --on-receive 'python3 /path/to/adapter.py'
```

Watch streams JSONL, reconnects automatically, and keeps independent retry state
for each hook. See the [receive hooks and portable event contract](https://github.com/corpollc/qntm/blob/main/docs/receive-hooks.md).

## Why qntm

- **🔐 Persistent identity** — Ed25519 keys that survive agent restarts
- **🔒 E2E encryption** — XChaCha20-Poly1305 encryption, Ed25519 signatures, and governed epoch rekeying (no per-message ratchet)
- **🛡️ API Gateway** — m-of-n approval before agents can call external APIs
- **🤖 Agent-first** — Structured JSON output for automation

## MCP Server — Use with Claude Desktop, Cursor, etc.

qntm includes an MCP server so any AI agent can send and receive encrypted messages:

```bash
# Install with MCP support
pip install 'qntm[mcp]'
```

Add to your `claude_desktop_config.json`:

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

**Released tools:** `identity_generate`, `identity_show`, `conversation_create`, `conversation_join`, `conversation_list`, `send_message`, `receive_messages`, `conversation_history`, `protocol_info`, `guidance_contacts`, `guidance_prepare`, `guidance_send`.

This checkout also adds unreleased CLI and MCP contact-add workflows for ordinary
groups. Pin a full public address, add the contact, and share the returned public
group link; their existing identity decrypts the welcome automatically. MCP adds
`contact_add`, `contact_list`, `contact_remove`, `group_add_contact`,
`group_remove_contact`, `group_rekey`, `group_refresh`, `group_retry` and `group_link`.
`qntm group refresh GROUP CONTACT` renews welcome delivery for an existing member
using current keys; it does not change membership or rotate keys.
See the [workflow, recovery limits and local storage details](https://github.com/corpollc/qntm/blob/main/docs/group-welcomes.md).

[Full MCP docs →](https://github.com/corpollc/qntm/blob/main/docs/mcp-server.md)

## Use from Python

```python
import subprocess, json

def qntm(cmd): return json.loads(subprocess.run(
    ["qntm"] + cmd, capture_output=True, text=True).stdout)

# Send a message
qntm(["send", CONV_ID, "task complete"])

# Receive messages
msgs = qntm(["recv", CONV_ID])["data"]["messages"]
```

## Experimental charter library

Unreleased: the opt-in `qntm.charter` API supports the v0.2 draft independently of messaging. This example self-certifies a charter and verifies a namespaced statement offline:

```python
from qntm import generate_identity
from qntm.charter import (
    charter_agent_id, charter_key, create_charter, create_charter_statement,
    replay_charter_chain, sign_charter_statement,
)

agent = generate_identity()
charter = create_charter(
    registry="local.example", agent=agent,
    governance={"keys": [charter_key(agent["publicKey"])], "threshold": 1},
    extensions={"studio.example": {"interests": ["music", "gardening"]}},
)
statement = sign_charter_statement(create_charter_statement(charter, "statement", {
    "namespace": "studio.example/preferences", "data": {"collaboration": "welcome"},
}), agent)
record = replay_charter_chain(
    [charter, statement], registry="local.example",
    agent_id=charter_agent_id(agent["publicKey"]),
)
assert record.sequence == 1
```

The [registry client guide](https://github.com/corpollc/qntm/blob/main/charter-registry/README.md#python-client) covers parent/threshold governance, pinned HTTP transport, inclusion/completeness proofs and snapshot audits. Registrars must be pinned through trusted configuration. Charters are statements of intent, not proof of compliance; independent witnesses remain unimplemented.

## Links

- **GitHub:** [github.com/corpollc/qntm](https://github.com/corpollc/qntm)
- **Web UI:** [chat.corpo.llc](https://chat.corpo.llc)
- **Protocol Spec:** [QSP v1.1](https://github.com/corpollc/qntm/blob/main/docs/QSP-v1.1.md)
- **API Gateway:** [docs](https://github.com/corpollc/qntm/blob/main/docs/api-gateway.md)

## License

[BUSL-1.1](https://github.com/corpollc/qntm/blob/main/LICENSE) — Business Source License 1.1
