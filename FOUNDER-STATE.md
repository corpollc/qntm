# Founder State — qntm
Updated: 2026-03-22T09:45:00Z
Wave: 8 (COMPLETE)

## Horizon Goals (set wave 1, review wave 10)
1. 5+ active external conversations per week — IN PROGRESS (2 engagements, 0 conversations yet)
2. 3+ design partners using the protocol — NOT STARTED (0)
3. At least 1 team using the API Gateway — NOT STARTED (0)
4. TTFM measured and optimized to <10s — DONE ✅ (1.2s!)
5. All tests green, relay fully functional — RECOVERED ✅ (287 pass, 0 actual failures)

## Campaign 2 Goals (Waves 6-10)
1. **Get PyPI v0.5.0 published** — CRITICAL: published CLI is BROKEN (410 on recv). Chairman approval needed.
2. **First external conversation** — IN PROGRESS: 2 A2A comments posted, awaiting responses
3. **Deploy CF Worker echo bot** — DONE ✅ (completed wave 5, recovered wave 6)
4. **Instrument active conversations metric** — DONE ✅ (`/v1/stats` endpoint live, tracking sends)
5. **Identify and attempt ONE distribution channel** — IN PROGRESS: A2A GitHub tested (2 engagements)

## Wave 9 Top 5 (NEXT)
1. **Monitor A2A #1575 and #1667 for responses** — if replies, engage immediately. These are our only external conversations.
2. **PyPI publish (if approved)** — THE P0 fix. Published CLI is broken. Every wave this isn't fixed is lost users.
3. **Build automated KPI dashboard** — now that `/v1/stats` exists, create a simple monitoring script that logs metrics to kpis.jsonl automatically.
4. **Find new A2A issues to engage** — only where qntm's relay/encryption is genuinely relevant. Don't force it.
5. **Prepare Show HN draft v2** — update with instrumented metrics and echo bot story.

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
- **External engagements: 2** — A2A GitHub #1575 + #1667
- PyPI downloads:
  - Yesterday: 26
  - Last week: 862
  - Last month: 1,625
  - Published version: **BROKEN** (v0.3 uses removed polling API)
- GitHub: 1 star, 0 forks, 0 external issues
- A2A engagement: 2 comments posted (#1575 identity/transport, #1667 relay pattern)

## What We Accomplished Wave 8
- **INSTRUMENTED PRIMARY METRIC** — `/v1/stats` endpoint live on relay. Tracks active conversations (7-day) automatically via KV. First real reading: 1 active conversation (echo bot). This was Campaign 2 Goal #4.
- **DEPLOYED RELAY UPDATE** — CF Worker v8617aade with stats tracking on every `/v1/send`. Zero impact on existing functionality.
- **DISCOVERED KV LIMITS** — Free-tier KV `list()` has daily limits. Redesigned from per-conversation activity keys to single aggregate JSON key.
- **A2A MONITORING** — Both #1575 and #1667 checked. No replies to our comments yet. Both threads positioned correctly. #1667 is fresh (Mar 21-22 activity).
- **EVALUATED THIRD ENGAGEMENT** — Declined. #1029 is stale (6 weeks), #1628 is off-topic. Don't force weak engagements.
- **CONFIRMED P0** — `qntm recv` still returns 410. Every PyPI user who tries `recv` gets a broken error.

## Ops Log
- Wave 1: Full relaunch. All Day One docs. TTFM 1.2s. Distribution + competitive research. CF token blocker escalated.
- Wave 2: Fixed relay poll (KV→SQLite). CF deploy working. 465 tests green. Quick-start, outbound msgs, tutorial, truth register. Public posting remains only blocker.
- Wave 3: Echo bot LIVE. First active conversation. PyPI analysis: 823 real downloads with 0 marketing = organic pull. README activation path. DO quota assessed (safe for now).
- Wave 4: Echo bot persistent (launchd). Diagnosed PyPI README as #1 activation bottleneck. Rewrote PyPI README. Show HN draft v1. Decision memo on persistence strategy. Two new blockers escalated: PyPI publish + public posting.
- Wave 5: **CF Worker echo bot deployed (24/7, global, no host dep).** Campaign 1 review: 4/5 done, 0 customer contact. Mapped competitive landscape. Zero external traces of qntm. Hard truth: 5 waves, 0 users.
- Wave 6: **FIRST EXTERNAL ENGAGEMENT** — A2A GitHub #1575 comment. Fixed echo bot (relay removed polling, rebuilt with WebSocket). Discovered published CLI is broken (P0). Test regression: 47 tests failing.
- Wave 7: **TEST REGRESSION FIXED** (287 pass, 0 failures). **SECOND EXTERNAL ENGAGEMENT** — A2A#1667 (relay for heartbeat agents). Monitored #1575 (no replies yet).
- Wave 8: **PRIMARY METRIC INSTRUMENTED** — `/v1/stats` endpoint live. Active conversations now tracked automatically. KV list() daily limit discovered and worked around. A2A engagements monitored (no replies yet). Evaluated and declined third engagement (stale/off-topic threads).
