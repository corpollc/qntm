# Wave 19 — First External Replies + Subscribe Auth + Interop Vectors
Started: 2026-03-22T22:39:00Z
Campaign: 4 (Waves 16-22) — Convert or Pivot

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **FIRST EXTERNAL REPLIES IN 18 WAVES.**
   - aeoess (Agent Passport System) replied to integration proposal #5 with a detailed technical response. They have E2E encryption (Module 19) but explicitly say qntm fills their relay/transport gap. Proposed a concrete 5-layer integration stack.
   - The-Nexus-Guard (AIP) replied on A2A #1667 with detailed code review of our relay. Read `worker/src/index.ts`. Called qntm "exactly the kind of concrete reference implementation this discussion needs." Asked about identity-authenticated subscribe.
   - aeoess also replied on A2A #1575 AND #1606 — treating qntm as legitimate infrastructure.
   - Peter (Chairman) engaged directly with aeoess on #1575 about legal entity binding via Corpo.
   - Tests: 221 pass (MCP tests back). Relay operational.

2. **Single biggest bottleneck?**
   - **Conversion.** We have first engagement. The bottleneck shifts from "distribution" to "convert technical discussion into design partnership." Respond fast, demonstrate engineering quality, propose concrete next steps.

3. **Bottleneck category?**
   - Customer acquisition. The distribution channel (GitHub issues/A2A threads) is producing signal. Now we need to convert.

4. **Evidence?**
   - aeoess: 969 tests, active development, 22 repos. Their Module 19 does encryption but not transport. They explicitly say "qntm fills exactly that gap." This is complementary, not competitive.
   - The-Nexus-Guard: runs AIP service on Fly.dev. Detailed code review shows serious evaluation. Asked specific architectural question about subscribe auth — this means they're thinking about using it.

5. **Highest-impact action?**
   - Respond to both developers TODAY with substance, not marketing. Propose concrete technical next steps (test vectors, spec work). Ship the subscribe auth they asked for.

6. **Customer conversation avoiding?**
   - None right now. These ARE customer conversations. Engage fully.

7. **Manual work that teaches faster?**
   - Reading their code to understand compatibility. Generating interop test vectors manually.

8. **Pretending-is-progress?**
   - Building more features without engaging the two developers who showed interest would be avoidance. Direct engagement is the priority.

9. **Write down today?**
   - Response details. Subscribe auth decision memo. Interop test vectors. Updated truth register entries.

10. **Escalation needed?**
    - MCP marketplace ruling still pending (3rd wave asking).
    - NanoClaw credential proxy bug still blocking.

## Wave 19 Top 5 (force ranked)

1. ✅ **Respond to aeoess on #5** — detailed technical response, propose shared test vectors
2. ✅ **Respond to The-Nexus-Guard on #1667** — answer subscribe auth question, propose spec
3. ✅ **Ship subscribe authentication** — Ed25519 challenge-response on /v1/subscribe, deployed
4. ✅ **Create interop test vectors** — Ed25519→X25519 known-answer tests for aeoess compatibility
5. ✅ **Send Chairman Morning Briefing** — comprehensive 2-page briefing via qntm

## Execution Log

### #1 — Responded to aeoess on #5 ✅
Detailed technical response covering:
- Confirmed their 5-layer integration stack is right
- Explained X3DH pre-key bundle approach with APS-derived keys
- Discussed Double Ratchet vs per-message ephemeral trade-offs
- Proposed concrete next steps: shared test vectors, envelope format alignment, relay identity binding
- Mentioned The-Nexus-Guard's subscribe auth feedback as related work
- Asked if they're open to test vector exchange as starting point
Posted: https://github.com/aeoess/agent-passport-system/issues/5#issuecomment-4107138847

### #2 — Responded to The-Nexus-Guard on #1667 ✅
Answered their specific question about subscribe auth:
- Acknowledged the gap honestly
- Described the challenge-response approach being implemented
- Addressed their relay comparison observations (cursor vs mark-read, WebSocket vs HTTP)
- Connected to A2A spec need for relay abstraction
- Referenced APS key derivation as compatible approach
Posted: https://github.com/a2aproject/A2A/issues/1667#issuecomment-4107139595

### #3 — Subscribe Authentication Shipped ✅
Implemented Ed25519 challenge-response on `/v1/subscribe`:
- Optional `pub_key` parameter triggers auth flow
- 32-byte random challenge sent via WebSocket
- Client signs challenge, relay verifies before streaming
- Backwards compatible (no pub_key = unauthenticated)
- Clean TypeScript compile, deployed to production
- Commit: c0104a0
- Bead: qntm-o1at (CLOSED)
- Worker version: d69d6763

### #4 — Interop Test Vectors Created ✅
- 5 known-answer test vectors for Ed25519→X25519 key derivation
- 9 pytest tests (deterministic, uniqueness, validity, size)
- VECTORS.md with printable hex values for cross-project verification
- Targets aeoess/agent-passport-system `createEncryptionKeypair()` interop
- Committed: 4d711cf
- All 230 tests pass

### #5 — Chairman Briefing Sent ✅
Comprehensive 2-page briefing covering first replies, response plan, blockers.
Sent via qntm conv 2d0d (seq 9).

### #6 — Decision Memo Written ✅
`.company/decisions/2026-03-22-subscribe-auth.md`
- Problem, options, recommendation, expected effect, review date
- Recommended Option A (challenge-response) with 0.85 confidence
- Reversible, backwards compatible

## Metrics This Wave
- Tests: 230 pass (221 + 9 interop), 0 failures ✅
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (10 active conversations, version d69d6763)
- Active conversations (7-day relay): 10 (mostly internal)
- qntm-only active conversations: 1 (echo bot)
- **External engagements: 9 (same) — 2 REPLIES (aeoess + The-Nexus-Guard) 🎉**
- Direct integration proposals: 6 — **1 reply (aeoess)**, 5 pending
- PyPI: v0.4.20 LIVE ✅
- GitHub: 1 star, 0 forks, 0 external issues
- GitHub traffic (Mar 20-21): 24 views/10 uniques, 710 clones/163 uniques
- **First external technical engagement: wave 19 (after 18 waves)**
- NanoClaw integration: unchanged (blocked on credential proxy)
- MCP marketplace: still blocked (AUTONOMY ruling pending)
- Campaigns completed: 3 (Campaign 4 active)
- Total waves: 19

## Assessment

**This is a breakthrough wave.** After 18 waves of zero replies, two developers independently engaged with our work in the same day:

1. **aeoess** is the strongest design partner lead. Their Module 19 (encryption) + our relay = complete stack. They proposed the integration architecture themselves. The test vector exchange is the next concrete step. If they run the vectors and confirm interop, we're in a real integration conversation.

2. **The-Nexus-Guard** represents the broader A2A community's interest in relay infrastructure. Their code review and technical question demonstrate serious evaluation. Shipping subscribe auth within hours of their feedback demonstrates engineering velocity.

**Key insight:** GitHub issues work as a distribution channel — but with multi-day response cadence, not hours. Waves 10-18 felt like failure (0 replies). The responses came on a Sunday, after 2-12 days. **Patience was correct. The channel works.**

**Two signals that matter:**
- aeoess said "qntm fills exactly that gap" (transport/relay for identity infrastructure)
- The-Nexus-Guard read our source code and compared architectures in detail

**What's different now:** We're no longer broadcasting into the void. We have two technical contacts who understand what we do and have specific integration ideas. The bottleneck shifts from distribution to conversion.

**Next wave priorities:**
1. Monitor for aeoess response to our test vector proposal
2. Monitor for The-Nexus-Guard response to our subscribe auth discussion
3. Monitor remaining 5 proposals for responses (Monday business hours)
4. If aeoess engages: push toward test vector exchange + shared interop repo
5. Get MCP marketplace AUTONOMY ruling (4th wave asking)
