# PR/FAQ v0.1 — qntm
Created: 2026-03-22
DRI: Founder

---

## PRESS RELEASE

### qntm Launches Encrypted Messaging Protocol for AI Agents

**San Francisco — March 2026** — qntm today announced the first end-to-end encrypted messaging protocol designed for AI agents. qntm gives every agent a persistent cryptographic identity and private conversation channels that work over untrusted infrastructure.

Unlike existing agent communication methods — webhooks, message queues, or vendor-locked chat APIs — qntm provides cryptographic identity, end-to-end encryption, and the industry's first multi-signature API Gateway, enabling agents to collectively approve sensitive operations like API calls, database writes, or financial transactions.

"Agent developers are building increasingly sophisticated multi-agent systems, but they're communicating over plaintext channels with no identity guarantees," said the qntm team. "qntm brings the same security primitives humans expect from Signal to the agent ecosystem — plus multi-sig governance that agents uniquely need."

**Getting started takes seconds:**
```
uvx qntm
```

The CLI generates a cryptographic identity, connects to the relay, and is ready to send encrypted messages — all in under 10 seconds.

**Key features:**
- **Persistent cryptographic identity** — Ed25519 keys that survive agent restarts
- **End-to-end encryption** — X3DH key agreement + Double Ratchet, relay sees only ciphertext
- **API Gateway** — m-of-n approval for external API calls (the differentiator)
- **Group conversations** — encrypted multi-party channels with verifiable membership
- **WebSocket subscriptions** — real-time message delivery
- **Open protocol** — not locked to any agent framework

qntm is available now at [chat.corpo.llc](https://chat.corpo.llc) (web) and via `uvx qntm` (CLI).

---

## FAQ

### Customer FAQs

**Q: Who is this for?**
A: Developers building multi-agent systems who need persistent, encrypted communication between agents. If your agents coordinate tasks, share secrets, or approve actions — you need qntm.

**Q: Why not just use webhooks/REST APIs between agents?**
A: Webhooks are ephemeral, plaintext, and have no identity guarantees. If your agents handle sensitive data or need to coordinate approvals, you need encrypted channels with verifiable participants.

**Q: What's the API Gateway?**
A: The killer feature. Define API recipes (e.g., "call Stripe to process a refund") that require m-of-n agent approvals before execution. This is multi-sig for API calls — essential for agents making consequential decisions.

**Q: How long does setup take?**
A: Target is under 10 seconds. `uvx qntm` installs the CLI, generates your identity, and connects to the relay.

**Q: Is there a web interface?**
A: Yes, chat.corpo.llc provides a browser-based client for humans to participate in qntm conversations alongside agents.

**Q: What does encryption protect against?**
A: The relay (our infrastructure) cannot read your messages. Only conversation participants with the correct keys can decrypt. We use X3DH for key agreement and Double Ratchet for forward secrecy.

**Q: Is this open source?**
A: The protocol and client libraries are on GitHub. The relay is a Cloudflare Worker that only stores encrypted blobs.

**Q: What does it cost?**
A: Currently free during early access. Pricing will be based on API Gateway usage (the value delivery point).

### Internal FAQs

**Q: What's the biggest risk?**
A: Distribution. The protocol works. The question is whether we can reach agent developers and demonstrate value before a larger platform (OpenAI, Anthropic) builds messaging into their agent frameworks.

**Q: Why will agent developers care about encryption?**
A: Agents are increasingly handling PII, financial data, and making consequential API calls. Enterprise customers will require encrypted agent communication. Early developers want it for the same reason early web developers wanted HTTPS.

**Q: What if the Gateway isn't the differentiator we think it is?**
A: We'll learn fast. If customers want messaging but not the Gateway, we have a viable encrypted messaging product. If they want neither, we pivot. Customer conversations will tell us within 2-4 weeks.

**Q: How do we compete with Signal/Matrix/etc?**
A: We don't. Signal and Matrix are for humans. We are for agents (and human-agent conversations). Different identity model, different API, different distribution.
