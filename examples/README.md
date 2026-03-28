# qntm Examples

Runnable examples demonstrating the qntm protocol. No server or relay needed — these run entirely locally.

## Setup

```bash
pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
```

## Examples

### `two_agents.py` — E2E Encrypted Messaging

Two agents generate identities, create a conversation, and exchange encrypted messages. Shows the full encrypt → serialize → deserialize → decrypt roundtrip.

```bash
python examples/two_agents.py
```

### `gateway_approval.py` — M-of-N API Approval

Three signers set up a 2-of-3 approval threshold for a Stripe API call. Demonstrates the API Gateway — no single agent can execute a consequential API call alone.

```bash
python examples/gateway_approval.py
```

## What These Demonstrate

| Feature | Example |
|---------|---------|
| Ed25519 identity generation | Both |
| E2E encrypted messaging | `two_agents.py` |
| AEAD envelope serialization | `two_agents.py` |
| M-of-N approval signatures | `gateway_approval.py` |
| Threshold rule enforcement | `gateway_approval.py` |
| Cryptographic audit trail | `gateway_approval.py` |

## Next Steps

- **Talk to the echo bot:** `qntm convo join <token>` (see main README)
- **Deploy your own gateway:** [Gateway Deployment](../docs/gateway-deploy.md)
- **Full API docs:** [API Gateway](../docs/api-gateway.md)
- **Protocol spec:** [QSP v1.1](../docs/QSP-v1.1.md)
