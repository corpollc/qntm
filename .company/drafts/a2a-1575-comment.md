# Draft: A2A Issue #1575 Comment
# Status: DRAFT — review before posting

The identity, delegation, and enforcement work in this thread is strong. One gap I want to highlight: all these systems assume the channel between agents is already secure. A2A itself has no E2E encryption — Red Hat explicitly noted "A2A does not include any specific security control against cross-agent prompt injection."

I've been working on this specific layer: **encrypted transport for agent-to-agent messaging** — [qntm](https://github.com/corpollc/qntm).

## The transport gap

The 3-signature enforcement chain @aeoess described (intent → policy → receipt) is excellent. But those signed artifacts travel over A2A channels that are:

- **Plaintext by default** — A2A task messages aren't encrypted end-to-end
- **Relay-visible** — any intermediary can read message contents
- **No forward secrecy** — if a key is compromised, past messages are exposed

If Agent A delegates scope to Agent B and sends a signed delegation, any relay or intermediary that handles that A2A message can read the delegation chain, the scope, the spending limits — the entire enforcement context.

## What qntm provides

qntm is an E2E encrypted messaging protocol designed for agents:

- **Ed25519 identity** — same primitive used in APS, AIP, and Kanoniv (interop surface)
- **X3DH key agreement + Double Ratchet** — forward secrecy for every message, same cryptographic model as Signal
- **Persistent conversations** — agents maintain encrypted channels that survive restarts
- **Relay sees only ciphertext** — the relay stores and forwards encrypted blobs, can't read content

Getting started is fast:

```bash
uvx qntm         # generates Ed25519 identity
qntm send <conv> "message"   # E2E encrypted
```

## Where this intersects with the identity work here

1. **Ed25519 identity alignment** — qntm identities use the same keypairs that APS/AIP/Kanoniv use for signing. An agent's qntm identity key IS its passport key. No separate identity layer needed.

2. **Delegation artifacts over encrypted channels** — when Agent A delegates to Agent B, that delegation message is encrypted end-to-end. The relay never sees the scope, the spending limits, or the delegation chain.

3. **API Gateway with m-of-n approval** — qntm includes a gateway where sensitive API calls (external service calls, financial operations) require m-of-n cryptographic approvals from conversation participants before execution. This maps directly to the ProxyGateway enforcement pattern @aeoess described — but the approval happens over encrypted channels.

4. **Revocation over encrypted channels** — cascade revocation callbacks (@aeoess's `cascadeRevoke()`) travel over encrypted channels, so a compromised relay can't selectively suppress revocation messages to create the propagation window @chorghemaruti64-creator identified.

## Concrete integration

An A2A agent card could include a qntm conversation ID alongside the endpoint URL. When Agent A wants to send a delegated task to Agent B:

1. Resolve Agent B's card → get endpoint + qntm conversation ID
2. Send the A2A task message over the qntm encrypted channel (not plaintext HTTP)
3. The delegation chain, enforcement artifacts, and receipts travel encrypted
4. m-of-n gateway approval for any external API calls the task requires

The identity layer stays in APS/AIP/Kanoniv. The transport layer uses qntm. The A2A spec defines the message format. Each layer does what it's good at.

Repo: https://github.com/corpollc/qntm (TypeScript client, Python CLI, Cloudflare relay)
Protocol: X3DH + Double Ratchet, Ed25519 identity, AES-256-GCM AEAD

Happy to discuss integration approaches — especially how qntm conversation keys could be bootstrapped from APS delegation chains.
