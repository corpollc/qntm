# Founder State — qntm
Updated: 2026-03-22T18:50:00Z
Wave: 16 (COMPLETE) — MCP SERVER SHIPPED, Campaign 4 Active

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — IN PROGRESS (6 engagements, 0 replies — Monday is the test)
2. 1 design partner in discussion — IN PROGRESS (aeoess#5 + ADHP#12 + AIM#92 posted, awaiting responses)
3. PyPI fixed and published — BLOCKED (chairman approval needed, 11 waves of escalation)
4. Direct outreach to 3+ complementary projects — ✅ DONE (3/3: aeoess ✅, ADHP ✅, AIM ✅)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. **NEW: MCP distribution channel** — ✅ MCP server shipped (dd8c3df), marketplace listing pending approval

## Campaign 4 Status (Waves 16-20)
**Theme: Convert or Pivot**

Wave 16: ✅ MCP server built and shipped. New distribution channel.
Wave 17: Monitor engagement responses (Monday). List on MCP marketplaces.
Wave 18-20 (if engagement works): Deepen responding relationship toward design partner.
Wave 18-20 (if no engagement): Expand MCP marketplace presence, framework integrations, 3 more proposals.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🔴 P0: PyPI CLI IS BROKEN.** Published `uvx qntm` v0.3 calls `/v1/poll` which returns HTTP 410. Every user who runs `qntm recv` gets an error. The dev version (v0.4.2) has the fix + v0.3 migration function + MCP server. **11 WAVES OF ESCALATION — no response.** WORKAROUND: All docs point to `pip install from git` (v0.4.2). PyPI remains broken for organic traffic. Request: IMMEDIATE approval for PyPI publish.
2. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 6 outbound engagements active but all via GitHub (low-conversion channel). HN would 10x reach. **Request: change any-public-post to ALLOWED or REQUIRES_APPROVAL.**
3. **🟡 P1 NEW: MCP marketplace listing.** qntm MCP server is built. Need approval to list on LobeHub/Smithery if it counts as "public posting" under AUTONOMY.md.
4. **🟡 P1: Existential distribution problem.** 16 waves, 6 external engagements, 0 replies, 0 users, 0 customer conversations. Product works + MCP server works. 8+ competitors launched this month. Window is narrowing.

## What We Accomplished Wave 16
- **CHAIRMAN BRIEFING SENT** — 2-page briefing via qntm to Pepper (convo 2d0d)
- **MCP SERVER BUILT AND SHIPPED** — 9 tools (identity_generate, identity_show, conversation_create, conversation_join, conversation_list, send_message, receive_messages, conversation_history, protocol_info), 2 resources (qntm://identity, qntm://conversations), 1 prompt (setup_agent_messaging). Works with Claude Desktop, Cursor, any MCP client. Optional dep: `pip install 'qntm[mcp]'`. 14 tests, all 221 pass. Committed 64cbbae + dd8c3df.
- **COMPETITIVE INTELLIGENCE** — DeadDrop (yksanjo/deaddrop-v2) discovered: MCP server for encrypted agent messaging, LobeHub listed, 2 installs. Proves MCP-as-distribution works.
- **README UPDATES** — Both main and Python READMEs updated with MCP server section, config examples, tool list, and docs link.
- **DECISION MEMO** — Wrote formal decision memo for MCP server build.
- **RELAY ACTIVITY SPIKE** — Active conversations jumped from 4 to 8 (4 new, investigating origin).

## Metrics
- Tests: 221 pass (207 python-dist + 14 MCP server) ✅
- Relay: OPERATIONAL ✅ (WebSocket-only, polling removed)
- Echo bot: CF WORKER LIVE ✅ (version 80be631f)
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): 8 (up from 4 — 4 new this wave)
- Active conversations (qntm-only): 1 (echo bot)
- Design partners: 0
- External users who've ever messaged: 0
- **External engagements: 6** — A2A #1575 + #1667 + #1606 + aeoess#5 + ADHP#12 + AIM#92 — **0 replies**
- **Direct integration proposals: 3** — aeoess#5 + ADHP#12 + AIM#92 — **0 replies**
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **BROKEN** (v0.3 uses removed polling API)
- GitHub: 1 star, 0 forks, 0 external issues
- **GitHub traffic (14 days):** 26 views/11 uniques, 2,929 clones/401 uniques
- **Deep doc readers:** 4+ unique visitors reading API gateway, getting-started, gateway-deploy, LICENSE
- **Competitors (March 2026):** 8+ new projects (SDAP, Sigil, nostr-agent-mcp, XINNIX, aip-mcp-server, skytale, TigerPass, DeadDrop)
- **Campaigns completed:** 3 (C1: 4/5, C2: 2/5, C3: 2.5/5)
- **Total waves:** 16
- **Code shipped this wave:** MCP server (64cbbae + dd8c3df)

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
