# Show HN Draft v2
Created: 2026-03-22
DRI: Founder
Status: DRAFT — awaiting posting permission (AUTONOMY: any-public-post DENIED)
Updated from v1: Added ecosystem context (A2A, identity projects), integration story, updated metrics.

---

## Title Options (pick one)
1. Show HN: qntm – E2E encrypted messaging for AI agents, with multi-sig API approval
2. Show HN: qntm – Your AI agents talk over plaintext. Here's Signal-grade encryption for them.
3. Show HN: qntm – Encrypted transport layer for the A2A agent ecosystem

**Recommended:** Option 2 — punchy, frames the problem, implies the solution.

---

## Post Body

Hi HN,

AI agents are coordinating across services — but they communicate over plaintext webhooks with hardcoded API keys. If an agent gets prompt-injected, it can call any API it has credentials for with no approval step.

I built qntm to fix two things:
1. **Agents need encrypted channels** — not just for privacy, but because the relay operator shouldn't be a trust assumption.
2. **Agents need multi-sig for dangerous API calls** — "2-of-3 agents must approve before hitting Stripe" shouldn't require custom infrastructure.

**What it does:**
- Every agent gets a persistent Ed25519 identity (survives restarts, unique per agent)
- Messages are E2E encrypted (X3DH key agreement + Double Ratchet — same primitives as Signal)
- The relay is untrusted — it only stores opaque ciphertext with a TTL
- The API Gateway requires m-of-n cryptographic approvals before executing any API call

**Try it:**
```bash
uvx qntm identity generate
uvx qntm convo join "p2F2AWR0eXBl..."  # echo bot invite
uvx qntm send <conv-id> "Hello!"
uvx qntm recv <conv-id>
# → 🔒 echo: Hello!
```

That's a live echo bot running full E2E encryption on Cloudflare Workers. Install → identity → encrypted conversation in ~2 seconds.

**Why now:** Google's A2A protocol launched with no encryption. The A2A community is actively discussing agent identity (#1575), trust signals (#1628), and data handling (#1606) — but nobody has shipped encrypted transport. Five A2A ecosystem projects are building Ed25519 identity and delegation systems. None provide encrypted channels. qntm fills exactly that gap.

**The differentiator** is the API Gateway: define "recipes" that require 2-of-3 (or any m-of-n) participant approvals before the gateway injects credentials and executes an HTTP call. Think Gnosis Safe, but for any API.

Tech: Python CLI (`uvx qntm`), TypeScript client lib, web UI, CF Workers relay. Protocol: QSP v1.1 (X3DH, Ed25519, NaCl sealed boxes for gateway secrets).

- Code: https://github.com/corpollc/qntm
- PyPI: https://pypi.org/project/qntm/
- Web UI: https://chat.corpo.llc

Feedback I'd love:
1. Does multi-sig API approval resonate? What APIs would you protect first?
2. Agent-to-agent coordination or human-in-the-loop approval — which use case matters more?
3. We're exploring integration with agent identity specs (agent-passport-system, ADHP). What standards would make you actually adopt this?

---

## Changes from v1
- Added A2A ecosystem context (5 identity projects, none with encryption)
- Reframed "why now" around competitive timing
- Added integration question (standards adoption)
- Tightened the opening hook
- Removed internal metrics (2K downloads) — let the product speak

## Expected Discussion Points
- "Why not Signal/Matrix?" → Those are for humans. qntm outputs JSON, has no UI requirement, identity keys are file-based for agent use, and the API Gateway has no equivalent in any chat protocol.
- "Why not MPC/threshold crypto?" → m-of-n approval (each party signs, gateway acts) is simpler and works with any HTTP API without custom crypto per endpoint.
- "Is the relay centralized?" → Currently one CF Worker relay, but the protocol is relay-agnostic. Anyone can self-host.
- "BUSL license?" → Business Source License. Free for non-commercial. Converts to OSS after 4 years.
- "A2A already handles this?" → A2A explicitly does NOT include encryption. Red Hat's own comment: "A2A does not include any specific security control against cross-agent prompt injection."

## Timing
- Best: weekday morning US Pacific (Tue-Thu 8-10am)
- Avoid: weekends, holidays

## Posting Prerequisite
- AUTONOMY.md `any-public-post: DENIED` must be changed to ALLOWED
- Escalated waves 4-10. No chairman response on this specific permission.
