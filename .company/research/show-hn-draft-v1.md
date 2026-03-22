# Show HN Draft v1
Created: 2026-03-22
DRI: Founder
Status: DRAFT — awaiting posting permission (AUTONOMY: any-public-post DENIED)

---

## Title Options (pick one)
1. Show HN: qntm – Multi-sig for AI agent API calls (E2E encrypted)
2. Show HN: qntm – Encrypted messaging + m-of-n approval for AI agents  
3. Show HN: qntm – Your AI agent has your Stripe key. What if it gets prompt-injected?
4. Show HN: qntm – Signal for AI agents, plus multi-sig for API calls

**Recommended:** Option 1 — concise, names the unique capability, implies security.

---

## Post Body

Hi HN,

I built qntm because I wanted my AI agents to have encrypted conversations — and to require multi-party approval before touching real APIs.

**The problem:** Agents today communicate over plaintext webhooks with hardcoded API keys. If an agent gets prompt-injected or goes rogue, it can call any API it has credentials for. There's no "approve this transaction" step.

**What qntm does:**
- Every agent gets a persistent Ed25519 identity
- Messages are E2E encrypted (X3DH + Double Ratchet — similar to Signal)
- The API Gateway requires m-of-n cryptographic approvals before executing API calls
- The relay is untrusted — it only stores opaque ciphertext

**Try it in 30 seconds:**
```bash
uvx qntm identity generate
uvx qntm convo join "p2F2AWR0eXBl..."  # (truncated invite token)
uvx qntm send 480556... "Hello!"
uvx qntm recv 480556...
# → 🔒 echo: Hello!
```

That's a live echo bot running E2E encryption. Install → identity → encrypted conversation in ~2 seconds.

**The differentiator** is the API Gateway: define API "recipes" that require 2-of-3 (or any m-of-n) participant approvals before the gateway will inject credentials and execute the HTTP call. Think Gnosis Safe, but for any API — not just on-chain transactions.

Tech: Python CLI (installable via `uvx`), TypeScript client library, web UI, Cloudflare Workers relay. Protocol spec: QSP v1.1 (X3DH key agreement, Ed25519 signatures, NaCl sealed boxes for gateway secrets).

Code: https://github.com/corpollc/qntm
Web UI: https://chat.corpo.llc
PyPI: https://pypi.org/project/qntm/

Would love feedback on:
1. Does the m-of-n API approval concept resonate?
2. What APIs would you most want multi-sig protection on?
3. Would you use this for agent-to-agent coordination, or more human-in-the-loop approval flows?

---

## Why This Is Ready
- TTFM: 1.2 seconds (install → first encrypted message)
- Echo bot live 24/7 (launchd persistent)
- 465 tests passing
- Both CLI and web UI operational
- Real organic traction: 2K+ PyPI downloads with zero marketing
- Full protocol spec published

## Expected Discussion Points
- "Why not just use Signal/Matrix?" → Those are for humans. We're API-first with JSON output for agent integration.
- "Why not MPC/threshold crypto?" → We chose m-of-n approval (sign, then gateway acts) over threshold key shares. Simpler, auditable, works with any HTTP API.
- "Is the relay centralized?" → Yes currently (CF Worker), but protocol is designed to be relay-agnostic. Anyone can run their own.
- "BUSL license?" → Business Source License. Free for non-commercial. We'll convert to OSS after 4 years per the license terms.

## Timing
- Best: weekday morning US Pacific (Tue-Thu 8-10am)
- Avoid: weekends, holidays
