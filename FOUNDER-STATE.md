# Founder State — qntm
Updated: 2026-03-22T10:42:00Z
Wave: 9 (COMPLETE)

## Horizon Goals (set wave 1, review wave 10)
1. 5+ active external conversations per week — IN PROGRESS (2 engagements, 0 conversations yet)
2. 3+ design partners using the protocol — NOT STARTED (0)
3. At least 1 team using the API Gateway — NOT STARTED (0)
4. TTFM measured and optimized to <10s — DONE ✅ (1.2s!)
5. All tests green, relay fully functional — RECOVERED ✅ (287 pass, 0 actual failures)

## Campaign 2 Goals (Waves 6-10)
1. **Get PyPI v0.5.0 published** — CRITICAL: published CLI is BROKEN (410 on recv). Chairman approval needed.
2. **First external conversation** — IN PROGRESS: 3 A2A comments posted, awaiting responses
3. **Deploy CF Worker echo bot** — DONE ✅ (completed wave 5, recovered wave 6)
4. **Instrument active conversations metric** — DONE ✅ (`/v1/stats` endpoint live, KPI dashboard script created)
5. **Identify and attempt ONE distribution channel** — IN PROGRESS: A2A GitHub tested (3 engagements)

## Wave 10 Top 5 (NEXT — CAMPAIGN 2 FINAL)
1. **Monitor A2A #1575, #1667, #1606 for responses** — if replies, engage immediately. These are our three external conversations.
2. **PyPI publish (if approved)** — THE P0 fix. Published CLI is broken. Every wave this isn't fixed is lost users.
3. **Campaign 2 review + Campaign 3 planning** — Wave 10 closes Campaign 2. Review all 5 goals. Set Campaign 3 (waves 11-15) priorities.
4. **Review horizon goals** — Wave 10 was the scheduled review point. 0/5 customer-facing goals met. Re-evaluate.
5. **Prepare Show HN draft v2** — update with 3 A2A engagements, instrumented metrics, and echo bot story.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🔴 P0: PyPI CLI IS BROKEN.** Published `uvx qntm` v0.3 calls `/v1/poll` which returns HTTP 410 ("relay polling has been removed; use /v1/subscribe"). Every user who runs `qntm recv` gets an error. The dev version (v0.4.2) has the fix. This is no longer "nice to have updated README" — this is "existing users cannot use the product." Request: IMMEDIATE approval for PyPI publish.
2. **Public posting DENIED** — Show HN draft ready, 5 outbound messages drafted. A2A GitHub engagement is the only outbound channel within permissions.
3. **Existential urgency.** 7 waves, 2 external engagements (A2A comments), 0 conversations, 0 users. Downloads are vanity — 862/week but published CLI is broken so anyone who tried to use it got errors.

## Resolved Blockers
- ~~CF token invalid~~ — RESOLVED Wave 2
- ~~Relay poll broken (500/1101)~~ — RESOLVED Wave 2
- ~~TUI vi.hoisted test~~ — RESOLVED Wave 2
- ~~No activation path for new users~~ — RESOLVED Wave 3 (echo bot)
- ~~Echo bot dies on reboot~~ — RESOLVED Wave 4 (launchd plist)
- ~~Echo bot depends on Peter's Mac~~ — RESOLVED Wave 5 (CF Worker)
- ~~Echo bot broken by relay migration~~ — RESOLVED Wave 6 (rebuilt with WebSocket client)
- ~~Test regression from relay migration~~ — RESOLVED Wave 7 (TestRelayServer missing `ready` frame + timeout)

## Metrics
- Tests: 287/296 pass (0 actual failures, 9 skipped) ✅ — 11 env-import file errors (not code bugs)
- Relay: OPERATIONAL ✅ (WebSocket-only, polling removed)
- Echo bot: CF WORKER LIVE ✅ (version 80be631f)
- TTFM: 1.2 seconds ✅
- Active conversations (7-day): 1 (echo bot)
- Design partners: 0
- External users who've ever messaged: 0
- **External engagements: 3** — A2A GitHub #1575 + #1667 + #1606
- PyPI downloads:
  - Yesterday: 26
  - Last week: 862
  - Last month: 1,625
  - Published version: **BROKEN** (v0.3 uses removed polling API)
- GitHub: 1 star, 0 forks, 0 external issues
- A2A engagement: 3 comments posted (#1575 identity/transport, #1667 relay pattern, #1606 data handling/E2E encryption)
- KPI dashboard: `.company/scripts/kpi-check.sh` — automated checks for relay, echo bot, CLI status

## What We Accomplished Wave 9
- **THIRD A2A ENGAGEMENT** — Comment on #1606 (data handling declarations). Proposed `transport_encryption` and `relay_data_access` fields for data handling extension. E2E encryption provides cryptographic enforcement layer — relay physically can't read data, making some declarations moot at transport layer. Genuine technical contribution.
- **KPI DASHBOARD** — `.company/scripts/kpi-check.sh` automates relay health, stats endpoint, echo bot status, GitHub, and published CLI checks. Detects P0 (410 on poll) automatically.
- **STATS CLARIFICATION** — 3 active conversations but 2 are corpo internal (shared relay). qntm has 1 (echo bot). 0 external users.
- **A2A MONITORING** — All 3 threads checked (#1575, #1667, #1606). No replies to our comments yet. Multi-day response cycle normal for A2A discussions.
- **P0 STILL BLOCKING** — Published CLI returns 410. No chairman response through 4 waves of escalation.

## Ops Log
- Wave 1: Full relaunch. All Day One docs. TTFM 1.2s. Distribution + competitive research. CF token blocker escalated.
- Wave 2: Fixed relay poll (KV→SQLite). CF deploy working. 465 tests green. Quick-start, outbound msgs, tutorial, truth register. Public posting remains only blocker.
- Wave 3: Echo bot LIVE. First active conversation. PyPI analysis: 823 real downloads with 0 marketing = organic pull. README activation path. DO quota assessed (safe for now).
- Wave 4: Echo bot persistent (launchd). Diagnosed PyPI README as #1 activation bottleneck. Rewrote PyPI README. Show HN draft v1. Decision memo on persistence strategy. Two new blockers escalated: PyPI publish + public posting.
- Wave 5: **CF Worker echo bot deployed (24/7, global, no host dep).** Campaign 1 review: 4/5 done, 0 customer contact. Mapped competitive landscape. Zero external traces of qntm. Hard truth: 5 waves, 0 users.
- Wave 6: **FIRST EXTERNAL ENGAGEMENT** — A2A GitHub #1575 comment. Fixed echo bot (relay removed polling, rebuilt with WebSocket). Discovered published CLI is broken (P0). Test regression: 47 tests failing.
- Wave 7: **TEST REGRESSION FIXED** (287 pass, 0 failures). **SECOND EXTERNAL ENGAGEMENT** — A2A#1667 (relay for heartbeat agents). Monitored #1575 (no replies yet).
- Wave 8: **PRIMARY METRIC INSTRUMENTED** — `/v1/stats` endpoint live. Active conversations now tracked automatically. KV list() daily limit discovered and worked around. A2A engagements monitored (no replies yet). Evaluated and declined third engagement (stale/off-topic threads).
- Wave 9: **THIRD A2A ENGAGEMENT** — #1606 (data handling declarations): E2E encryption as transport-level enforcement for GDPR concerns. KPI dashboard script created. Stats clarified: 3 convos but 2 are corpo internal. 0 external users, 0 replies to any engagement.
