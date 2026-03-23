# Founder State — qntm
Updated: 2026-03-23T00:50:00Z
Wave: 21 (COMPLETE) — Expanded Engagement + Competitive Intelligence

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 4 Status (Waves 16-22, extended)
**Theme: Convert or Pivot**

Wave 16: ✅ MCP server built and shipped. New distribution channel.
Wave 17: ✅ PyPI P0 resolved. Install path clean. MCP marketplace materials ready. NanoClaw integration discovered.
Wave 18: ✅ 3 new integration proposals (nono, clawdstrike, mcp-gateway). Joined All-Hands. NanoClaw live test confirmed. Clone spike analyzed.
Wave 19: ✅ **FIRST EXTERNAL REPLIES.** aeoess + The-Nexus-Guard engaged. Subscribe auth shipped. Interop test vectors created. Responded to both.
Wave 20: ✅ **VECTOR EXCHANGE ACTIVATED.** aeoess explicitly accepted 3-step interop plan. Responded with vectors + compatibility analysis. APS source code reviewed — genuine complement, not competitor. Peter engaging directly with aeoess on Corpo.
Wave 21: ✅ **EXPANDED ENGAGEMENT.** Commented on A2A #1672 (agent identity verification). Competitive analysis: leyline launched same day with same thesis (P2P, Ed25519, XChaCha20). Relay stats surging (10→16). All threads monitored.
Wave 22: Final campaign assessment. Convert or pivot decision.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🟢 P0 RESOLVED: PyPI publishing works!** v0.4.20 live. `uvx qntm` and `pip install qntm` both work.
2. **🟡 P1: MCP marketplace listing.** Materials ready (LobeHub manifest + Smithery config). Smithery requires active submission (no auto-indexing). RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post" under AUTONOMY.md? **6th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 10 outbound engagements active but all via GitHub. HN would 10x reach.
4. **🟢 P1: Distribution producing signal.** First external replies after 18 waves. aeoess engagement deepening. 10 total engagements now.

## What We Accomplished Wave 21
- **COMMENTED ON A2A #1672** — agent identity verification proposal. Compared CA-issued (ECDSA P-256) vs self-sovereign (Ed25519) identity models. Referenced APS, AIM, qntm as prior art. Raised identity→encrypted-transport gap. 10th engagement.
- **COMPETITIVE ANALYSIS: LEYLINE** — MissyLabs/leyline launched TODAY. Same thesis (Ed25519, encrypted agent messaging, XChaCha20). But P2P not relay, no store-and-forward, no Double Ratchet. Architecturally different. Threat: LOW-MEDIUM.
- **COMPETITIVE ANALYSIS: HUINET** — decentralized A2A networking. Too early. Watching.
- **RELAY STATS: 10→16** — 6 new active conversations in ~1 hour. Likely corpo/NanoClaw internal.
- **ALL 10 ENGAGEMENTS MONITORED** — aeoess waiting (Sunday night expected). 5 proposals still pending. Monday is the test.
- **230 TESTS PASS** — 221 python-dist + 9 interop, 0 failures

## aeoess Engagement Timeline (Design Partner #1)
- Wave 10: Integration proposal posted (APS#5)
- Wave 19: First reply — detailed 5-layer integration stack proposed
- Wave 19: We responded with X3DH details + test vector proposal
- Wave 19-20: aeoess accepted vector exchange with 3-step plan
- Wave 20: We posted vectors + compatibility analysis + TypeScript runner
- Wave 21: No new activity (Sunday night — expected)
- Across threads: aeoess engaged on APS#5, A2A#1575, A2A#1606, A2A#1667
- Peter engaged directly on A2A#1575 (Corpo legal entity binding)
- **Status:** PENDING aeoess running vectors against their derivation function (step 2)

## Metrics
- Tests: 230 pass, 0 failures ✅
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (up from 10 — mostly internal)
- Active conversations (qntm-only): 1 (echo bot)
- Design partners: 0 formal → **aeoess at proto-design-partner stage**
- External users who've ever messaged: 0
- **External engagements: 10** — **2 REPLIES (aeoess deepening, The-Nexus-Guard stable)**, 8 no reply
- **Direct integration proposals: 6** — **1 active (aeoess)**, 5 pending
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues
- **GitHub traffic (Mar 21):** 1 view/1 unique, 150 clones/29 uniques (Sunday normal)
- **Competitors (March 2026):** 9+ new projects (leyline added today)
- **Campaigns completed:** 3 (Campaign 4 active, wave 6/7)
- **Total waves:** 21
- **NanoClaw integration:** live relay round-trip confirmed, blocked on credential proxy bug
- **Subscribe auth:** SHIPPED (c0104a0, deployed)
- **Interop tests:** 9 pass (Ed25519→X25519 vectors)
- **Vector exchange:** ACCEPTED by aeoess, pending their results

## Ops Log
- Wave 1-20: [see wave logs for full history]
- Wave 21: **EXPANDED ENGAGEMENT.** Commented on A2A #1672 (10th engagement). Competitive analysis: leyline (P2P, Ed25519, XChaCha20, launched today — threat LOW-MEDIUM). Relay active conversations 10→16 (internal). All threads monitored. aeoess quiet (Sunday night). 5 proposals pending (Monday).

## Resolved Blockers
- ~~CF token invalid~~ — RESOLVED Wave 2
- ~~Relay poll broken (500/1101)~~ — RESOLVED Wave 2
- ~~TUI vi.hoisted test~~ — RESOLVED Wave 2
- ~~No activation path for new users~~ — RESOLVED Wave 3 (echo bot)
- ~~Echo bot dies on reboot~~ — RESOLVED Wave 4 (launchd plist)
- ~~Echo bot depends on Peter's Mac~~ — RESOLVED Wave 5 (CF Worker)
- ~~Echo bot broken by relay migration~~ — RESOLVED Wave 6 (rebuilt with WebSocket)
- ~~Test regression from relay migration~~ — RESOLVED Wave 7 (TestRelayServer missing `ready` frame)
- ~~Dead URLs in integration proposals~~ — RESOLVED Wave 13 (nichochar → corpollc)
- ~~Broken install in README~~ — RESOLVED Wave 13 (uvx → pip from git)
- ~~Broken install in docs pages~~ — RESOLVED Wave 14 (getting-started, tutorial, PyPI README)
- ~~conversations.json v0.3 format incompatibility~~ — RESOLVED Wave 15 (auto-migration function)
- ~~No MCP distribution channel~~ — RESOLVED Wave 16 (MCP server built and shipped)
- ~~PyPI CLI broken (v0.3, 11-wave escalation)~~ — RESOLVED Wave 17 (v0.4.20 published by chairman)
- ~~Subscribe has no identity verification~~ — RESOLVED Wave 19 (Ed25519 challenge-response, optional)
