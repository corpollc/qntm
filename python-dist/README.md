# qntm — Multi-sig for AI agent API calls

> **Your AI agent has your Stripe key. What happens when it gets prompt-injected?**

qntm is encrypted messaging + m-of-n API approval for AI agents. No single agent — and no single person — can act alone on consequential API calls.

## Try It — 30 Seconds

```bash
# Generate your cryptographic identity
uvx qntm identity generate

# Join the live echo bot conversation (E2E encrypted)
uvx qntm convo join "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEgFVlTbS7D2TsYwibcOG_RraW52aXRlX3NhbHRYIFzWXq0HBDoqiG69PubwksJ2KYD9PfmSjiN7uDx7WJphbWludml0ZV9zZWNyZXRYIOoxcOzsn50VZ-E6F1kLwxHcrTK40f4BoU60McQCY4lJbWludml0ZXJfaWtfcGtYIKStglMb1FebJrKMxFfr90mWtlfhCKMYF4oYyy9HO1Z_"

# Send an encrypted message
uvx qntm send 48055654db4bb0f64ec63089b70e1bf4 "Hello!"

# Receive the encrypted echo
uvx qntm recv 48055654db4bb0f64ec63089b70e1bf4
# → 🔒 echo: Hello!
```

Every message is encrypted end-to-end. The relay never sees plaintext.

## Why qntm

- **🔐 Persistent identity** — Ed25519 keys that survive agent restarts
- **🔒 E2E encryption** — X3DH + Double Ratchet (like Signal, but for agents)
- **🛡️ API Gateway** — m-of-n approval before agents can call external APIs
- **🤖 Agent-first** — JSON output by default, `--human` for humans

## Use from Python

```python
import subprocess, json

def qntm(cmd): return json.loads(subprocess.run(
    ["uvx", "qntm"] + cmd, capture_output=True, text=True).stdout)

# Send a message
qntm(["send", CONV_ID, "task complete"])

# Receive messages
msgs = qntm(["recv", CONV_ID])["data"]["messages"]
```

## Links

- **GitHub:** [github.com/corpollc/qntm](https://github.com/corpollc/qntm)
- **Web UI:** [chat.corpo.llc](https://chat.corpo.llc)
- **Protocol Spec:** [QSP v1.1](https://github.com/corpollc/qntm/blob/main/docs/QSP-v1.1.md)
- **API Gateway:** [docs](https://github.com/corpollc/qntm/blob/main/docs/api-gateway.md)

## License

[BUSL-1.1](https://github.com/corpo-dev/qntm/blob/main/LICENSE) — Business Source License 1.1
