# Draft v2: A2A Issue #1575 Comment
# Status: READY TO POST

The identity and delegation work here is strong — especially the cross-engine verification results showing Ed25519 interop between APS, AIP, and Kanoniv.

One gap I want to flag: all of these systems assume the transport between agents is secure. A2A itself doesn't provide E2E encryption — messages, delegation artifacts, and enforcement receipts travel in plaintext through whatever relay or intermediary handles routing.

This matters for the specific patterns discussed here:

- **Delegation chains** contain scope definitions and spending limits. If Agent A delegates to Agent B over an A2A channel, any relay in the path can read the delegation.
- **Cascade revocation** (@aeoess) depends on revocation callbacks reaching all downstream agents. A compromised relay could selectively suppress revocation messages, creating exactly the propagation window @chorghemaruti64-creator identified.
- **Decision artifacts** with trust context contain the reasoning behind permit/deny verdicts. Leaking these to intermediaries reveals the policy model.

We've been working on this transport layer with [qntm](https://github.com/corpollc/qntm) — E2E encrypted messaging for agents using X3DH key agreement + Double Ratchet (same model as Signal). Ed25519 identity, forward secrecy per message, relay stores only ciphertext.

The identity alignment is direct: qntm uses Ed25519 keypairs, same as APS/AIP/Kanoniv. An agent's identity key in any of those systems could also be its qntm messaging key — no separate identity layer.

We also have an API Gateway with m-of-n cryptographic approval for external API calls, which maps to the ProxyGateway enforcement pattern — but approvals happen over encrypted channels.

The layering: A2A defines message format, APS/AIP/Kanoniv handle identity + delegation + enforcement, qntm handles encrypted transport. Each layer does one thing.

Repo: https://github.com/corpollc/qntm (TypeScript + Python, Cloudflare relay, [465 tests passing])
