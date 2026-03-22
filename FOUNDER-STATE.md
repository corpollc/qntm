# Founder State — qntm
Updated: 2026-03-22T22:50:00Z
Wave: 19 (COMPLETE) — First External Replies + Subscribe Auth + Interop Vectors

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — IN PROGRESS (aeoess is closest — proposed integration, test vectors proposed as next step)
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
Wave 20: Monitor all responses. Push aeoess toward test vector exchange. If more replies come, engage immediately.
Wave 21-22: Convert engagement to design partner. If no further responses, evaluate pivot.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🟢 P0 RESOLVED: PyPI publishing works!** v0.4.20 live. `uvx qntm` and `pip install qntm` both work.
2. **🟡 P1: MCP marketplace listing.** Materials ready (LobeHub manifest + Smithery config). Smithery requires active submission (no auto-indexing). RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post" under AUTONOMY.md? **4th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 9 outbound engagements active but all via GitHub. HN would 10x reach.
4. **🟢 P1: Distribution producing signal.** First external replies after 18 waves. GitHub issues channel works — just slower than expected (days, not hours).

## What We Accomplished Wave 19
- **FIRST EXTERNAL REPLIES IN 18 WAVES** 🎉
  - aeoess replied to integration proposal #5 with detailed technical response. Proposed 5-layer integration stack. Said "qntm fills exactly that gap" (transport/relay).
  - The-Nexus-Guard replied on A2A #1667 with code review of our relay. Read worker/src/index.ts. Asked about identity-authenticated subscribe.
  - aeoess also replied on A2A #1575 + #1606 (3 threads total).
- **RESPONDED TO BOTH** with substance:
  - aeoess: confirmed integration stack, proposed shared test vectors, discussed Double Ratchet vs per-message trade-offs
  - The-Nexus-Guard: acknowledged subscribe auth gap, proposed Ed25519 challenge-response, connected to APS work
- **SUBSCRIBE AUTHENTICATION SHIPPED** — Ed25519 challenge-response on /v1/subscribe. Optional, backwards compatible. Deployed to production (c0104a0).
- **INTEROP TEST VECTORS CREATED** — 5 known-answer vectors for Ed25519→X25519 derivation. 9 pytest tests. VECTORS.md for cross-project use.
- **CHAIRMAN BRIEFING SENT** via qntm (seq 9)
- **DECISION MEMO WRITTEN** — subscribe auth (Option A, 0.85 confidence)
- **230 TESTS PASS** — 221 python-dist + 9 interop, 0 failures

## Metrics
- Tests: 230 pass, 0 failures ✅
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): 10 (mostly internal)
- Active conversations (qntm-only): 1 (echo bot)
- Design partners: 0 (aeoess closest — in technical discussion)
- External users who've ever messaged: 0
- **External engagements: 9** — **2 REPLIES (aeoess, The-Nexus-Guard)**, 7 no reply
- **Direct integration proposals: 6** — **1 reply (aeoess)**, 5 pending
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues
- **GitHub traffic (14 days):** 26 views/11 uniques, 2,929 clones/401 uniques
- **Clone spike (Mar 20):** 560 clones / 134 uniques (v0.4.20 release effect)
- **Competitors (March 2026):** 8+ new projects
- **Campaigns completed:** 3 (Campaign 4 active)
- **Total waves:** 19
- **NanoClaw integration:** live relay round-trip confirmed, blocked on credential proxy bug
- **Subscribe auth:** SHIPPED (c0104a0, deployed)
- **Interop tests:** 9 pass (Ed25519→X25519 vectors)

## Ops Log
- Wave 1: Full relaunch. All Day One docs. TTFM 1.2s. Distribution + competitive research. CF token blocker escalated.
- Wave 2: Fixed relay poll (KV→SQLite). CF deploy working. 465 tests green. Quick-start, outbound msgs, tutorial, truth register. Public posting remains only blocker.
- Wave 3: Echo bot LIVE. First active conversation. PyPI analysis: 823 real downloads with 0 marketing = organic pull. README activation path. DO quota assessed (safe for now).
- Wave 4: Echo bot persistent (launchd). Diagnosed PyPI README as #1 activation bottleneck. Rewrote PyPI README. Show HN draft v1. Decision memo on persistence strategy. Two new blockers escalated: PyPI publish + public posting.
- Wave 5: **CF Worker echo bot deployed (24/7, global, no host dep).** Campaign 1 review: 4/5 done, 0 customer contact. Mapped competitive landscape. Zero external traces of qntm. Hard truth: 5 waves, 0 users.
- Wave 6: **FIRST EXTERNAL ENGAGEMENT** — A2A GitHub #1575 comment. Fixed echo bot (relay removed polling, rebuilt with WebSocket). Discovered published CLI is broken (P0). Test regression: 47 tests failing.
- Wave 7: **TEST REGRESSION FIXED** (287 pass, 0 failures). **SECOND EXTERNAL ENGAGEMENT** — A2A#1667 (relay for heartbeat agents). Monitored #1575 (no replies yet).
- Wave 8: **PRIMARY METRIC INSTRUMENTED** — `/v1/stats` endpoint live. Active conversations now tracked automatically. KV list() daily limit discovered and worked around. A2A engagements monitored (no replies yet).
- Wave 9: **THIRD A2A ENGAGEMENT** — #1606 (data handling declarations). Stats clarified: 3 convos but 2 corpo internal. 0 external users.
- Wave 10: **CAMPAIGN 2 FINAL.** First direct integration proposal: aeoess#5. Campaign review: 2/5. Horizon goals revised. Campaign 3 planned.
- Wave 11: **SECOND INTEGRATION PROPOSAL** — ADHP#12. Show HN draft v2 completed.
- Wave 12: **THIRD INTEGRATION PROPOSAL — CAMPAIGN 3 TARGET HIT (3/3).** AIM#92. 6 total engagements, 0 replies.
- Wave 13: **CRITICAL CONVERSION FUNNEL FIX.** All proposals had dead URLs (404). Fixed. README install fixed.
- Wave 14: **DOCS INSTALL FIX + TRAFFIC INTELLIGENCE.** Found 11 unique GitHub visitors reading deep docs. 7+ new competitors in March 2026.
- Wave 15: **CAMPAIGN 3 FINAL + MIGRATION FIX.** Chairman briefing sent. v0.3→v0.4.2 migration function shipped. Campaign 3 scored 2.5/5.
- Wave 16: **MCP SERVER SHIPPED.** 9 tools, 2 resources, 1 prompt. Works with Claude Desktop, Cursor, any MCP client. DeadDrop competitive intel. Both READMEs updated. Decision memo written. Relay activity spike (4→8 active convos). 221 tests pass.
- Wave 17: **PyPI P0 RESOLVED + NANOCLAW DISCOVERY.** v0.4.20 live on PyPI. Install path clean. MCP marketplace materials ready. Smithery requires active submission. Relay investigation: 8 convos, all internal. Chairman building NanoClaw qntm integration (significant product validation). 221 tests pass.
- Wave 18: **NEW OUTREACH EXPANSION.** 3 new integration proposals to bigger repos: nono (1,190★), Clawdstrike (255★), MCP-Gateway (360★). Joined All-Hands. NanoClaw live test confirmed (conv 2211d8d9). Clone spike analyzed: v0.4.20 release drove 134 unique cloners. Total engagements: 9. Total proposals: 6. Still 0 replies.
- Wave 19: **🎉 FIRST EXTERNAL REPLIES.** aeoess (APS) replied to #5 with integration proposal. The-Nexus-Guard (AIP) replied on A2A #1667 with code review. Both responded to. Subscribe auth shipped (Ed25519 challenge-response). Interop test vectors created (9 tests). 230 total tests pass. Deployed to production. Horizon Goal #1 ACHIEVED.

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
