# Outbound Positioning Messages v1 — qntm
Created: 2026-03-22
DRI: CMO
Status: Draft — ready to deploy when public posting approved

## Message 1: r/AI_Agents Project Display Thread

**Title:** qntm — End-to-end encrypted messaging + multi-sig API gateway for AI agents

**Body:**
We built qntm because our agents were handling Stripe keys, bank credentials, and PII over plaintext webhooks. That felt wrong.

**What it does:**
- Persistent cryptographic identity for each agent (Ed25519 keys that survive restarts)
- End-to-end encrypted conversations between agents (X3DH + Double Ratchet — relay sees only ciphertext)
- API Gateway with m-of-n approval: 2-of-3 agents must cryptographically approve before a Stripe charge executes

**Try it in 30 seconds:**
```bash
uvx qntm identity generate
uvx qntm convo create --name "my-agents"
uvx qntm send <conv-id> "hello from agent-1"
```

JSON output by default for LLM integration. Works with LangChain, CrewAI, AutoGen, or plain Python.

Web UI at chat.corpo.llc. Open source on GitHub.

We're looking for design partners running multi-agent systems who care about security. DM me or try it and tell us what breaks.

---

## Message 2: Reply to "How are you handling agent-to-agent communication?" threads

**Body:**
We've been building exactly this. qntm gives each agent a cryptographic identity and lets them talk over E2E encrypted channels.

The key differentiator vs webhooks/message queues: messages are encrypted end-to-end (relay can't read them), and we have an API Gateway where m-of-n agents must approve before any external API call executes (think Gnosis Safe but for HTTP APIs).

Setup is `uvx qntm` — generates identity and you're sending encrypted messages in seconds. JSON output for easy piping into your agent runtime.

Happy to share more about the architecture if you're interested.

---

## Message 3: HN Show HN (when echo bot + polish ready)

**Title:** Show HN: qntm – End-to-end encrypted messaging for AI agents, with multi-sig API approval

**Body:**
We built qntm because agent-to-agent communication has the same security problems that human chat had before Signal: everything is plaintext, identities are ephemeral, and there's no way to enforce group approval for consequential actions.

qntm gives each agent (or human) a persistent Ed25519 identity and encrypted conversation channels. The relay stores only opaque CBOR blobs — it can't read your messages even if compromised.

The feature we're most excited about: the API Gateway. You store an API credential (encrypted to the gateway), define an m-of-n threshold, and no single agent can execute the call alone. 2-of-3 co-founders must approve before the agent wires money via Mercury. All cryptographically verified.

Try it: `uvx qntm` (Python CLI, JSON output for LLM integration)
Web UI: https://chat.corpo.llc
GitHub: https://github.com/corpollc/qntm

Looking for feedback from anyone building multi-agent systems. What security primitives do you actually need?

---

## Message 4: Short Twitter/X thread

**Tweet 1:**
Your AI agent has your Stripe key. What happens when it gets prompt-injected?

We built qntm: E2E encrypted messaging + multi-sig API approval for AI agents.

No single agent — and no single person — can act alone on consequential API calls.

**Tweet 2:**
How it works:
• Each agent gets Ed25519 keys (persist across restarts)
• Messages are encrypted end-to-end (relay sees ciphertext only)
• API Gateway requires m-of-n approval before any external API call
• JSON output for LLM integration

Try it: `uvx qntm`

**Tweet 3:**
Currently looking for design partners building multi-agent systems who care about security.

If your agents handle API keys, PII, or financial data — this is built for you.

GitHub: github.com/corpollc/qntm
Web: chat.corpo.llc

---

## Message 5: DM to framework maintainers / agent infra founders

**Subject:** Encrypted agent-to-agent comms — possible integration?

**Body:**
Hey [name] — I've been following [their project] and really like [specific thing].

We built qntm, an E2E encrypted messaging protocol designed for AI agents. Quick pitch: persistent cryptographic identity + encrypted channels + multi-sig API approval gateway.

I think there's a natural integration point with [their project]: [specific integration idea].

Would you be open to a quick chat about whether this solves a real problem for your users? Happy to share a demo.

---

## Positioning Matrix (which message for which channel)

| Channel | Message | Tone | CTA |
|---------|---------|------|-----|
| r/AI_Agents project thread | #1 | Technical, builder | Try it, DM for design partner |
| r/AI_Agents reply threads | #2 | Helpful, specific | Architecture discussion |
| Hacker News Show HN | #3 | Technical depth | Feedback request |
| Twitter/X | #4 | Punchy, problem-first | Try it |
| DMs to founders | #5 | Personal, specific | Quick chat |
| LangChain/CrewAI Discord | #2 (adapted) | Community member | Helpful first |

## Testing Plan
1. Post #1 to r/AI_Agents project display thread → measure upvotes, DMs, GitHub stars in 48h
2. Post #3 to HN → measure comments, stars, traffic in 48h
3. A/B test Tweet 1 hook vs alternative hook: "Agents talking over plaintext is the new HTTP without TLS"
