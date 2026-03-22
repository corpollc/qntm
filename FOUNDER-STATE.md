# Founder State — qntm
Updated: 2026-03-22T07:50:00Z
Wave: 6 (COMPLETE)

## Horizon Goals (set wave 1, review wave 10)
1. 5+ active external conversations per week — IN PROGRESS (1 engagement, 0 conversations yet)
2. 3+ design partners using the protocol — NOT STARTED (0)
3. At least 1 team using the API Gateway — NOT STARTED (0)
4. TTFM measured and optimized to <10s — DONE ✅ (1.2s!)
5. All tests green, relay fully functional — REGRESSED ⚠️ (264/311 pass, relay migration broke tests)

## Campaign 2 Goals (Waves 6-10)
1. **Get PyPI v0.5.0 published** — CRITICAL: published CLI is BROKEN (410 on recv). Chairman approval needed.
2. **First external conversation** — IN PROGRESS: A2A comment posted, awaiting responses
3. **Deploy CF Worker echo bot** — DONE ✅ (completed wave 5, recovered wave 6)
4. **Instrument active conversations metric** — NOT STARTED
5. **Identify and attempt ONE distribution channel** — IN PROGRESS: A2A GitHub tested

## Wave 7 Top 5 (NEXT)
1. **Monitor A2A #1575 for responses** — check for replies, engage thoughtfully. This is our first distribution channel test.
2. **Fix test regression** — 70 tests failing from relay WebSocket migration. Client mock updates needed. Get back to green.
3. **Post on A2A #1140 (Content Integrity)** — relevant to our E2E encryption and signing. Another technical engagement opportunity.
4. **Instrument active conversations metric** — add relay endpoint to count 7-day active conversations. Can deploy (CF deploy ALLOWED).
5. **PyPI publish (if approved)** — THE P0 fix. Published CLI is broken.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🔴 P0: PyPI CLI IS BROKEN.** Published `uvx qntm` v0.3 calls `/v1/poll` which returns HTTP 410 ("relay polling has been removed; use /v1/subscribe"). Every user who runs `qntm recv` gets an error. The dev version (v0.4.2) has the fix. This is no longer "nice to have updated README" — this is "existing users cannot use the product." Request: IMMEDIATE approval for PyPI publish.
2. **Public posting DENIED** — Show HN draft ready, 5 outbound messages drafted. A2A GitHub engagement is the only outbound channel within permissions.
3. **Existential urgency.** 6 waves, 1 external engagement (A2A comment). Downloads are vanity — 862/week but published CLI is broken so anyone who tried to use it got errors.

## Resolved Blockers
- ~~CF token invalid~~ — RESOLVED Wave 2
- ~~Relay poll broken (500/1101)~~ — RESOLVED Wave 2
- ~~TUI vi.hoisted test~~ — RESOLVED Wave 2
- ~~No activation path for new users~~ — RESOLVED Wave 3 (echo bot)
- ~~Echo bot dies on reboot~~ — RESOLVED Wave 4 (launchd plist)
- ~~Echo bot depends on Peter's Mac~~ — RESOLVED Wave 5 (CF Worker)
- ~~Echo bot broken by relay migration~~ — RESOLVED Wave 6 (rebuilt with WebSocket client)

## Metrics
- Tests: 264/311 (40 fail, 7 errors) ⚠️ — relay WebSocket migration regression
- Relay: OPERATIONAL ✅ (WebSocket-only, polling removed)
- Echo bot: CF WORKER LIVE ✅ (recovered wave 6, version 80be631f)
- TTFM: 1.2 seconds ✅
- Active conversations (7-day): 1 (echo bot)
- Design partners: 0
- External users who've ever messaged: 0
- **External engagements: 1** — A2A GitHub #1575 comment (FIRST EVER)
- PyPI downloads:
  - Yesterday: 26
  - Last week: 862
  - Last month: 1,625
  - Published version: **BROKEN** (v0.3 uses removed polling API)
- GitHub: 1 star, 0 forks, 0 external issues
- A2A engagement: 1 comment posted on #1575

## What We Accomplished Wave 6
- **FIXED CF Worker echo bot** — relay removed polling API, echo bot was silently failing. Rebuilt client library, reinstalled, redeployed. Echo bot operational again via WebSocket subscribe.
- **FIRST EXTERNAL ENGAGEMENT** — Posted technical comment on a2aproject/A2A#1575 (agent identity/delegation discussion). Positioned qntm as the encrypted transport layer that complements identity work. Genuine technical contribution.
- **Discovered published CLI is broken** — `uvx qntm recv` returns 410 error because v0.3 still uses removed polling API. Elevated to P0 blocker.
- **Documented test regression** — 70 tests failing from relay migration, need mock updates.
- **Identified 5+ projects in A2A ecosystem** building agent identity — APS, AIP, Kanoniv, QHermes, MeshCap. All Ed25519-based, none have encrypted transport.

## Ops Log
- Wave 1: Full relaunch. All Day One docs. TTFM 1.2s. Distribution + competitive research. CF token blocker escalated.
- Wave 2: Fixed relay poll (KV→SQLite). CF deploy working. 465 tests green. Quick-start, outbound msgs, tutorial, truth register. Public posting remains only blocker.
- Wave 3: Echo bot LIVE. First active conversation. PyPI analysis: 823 real downloads with 0 marketing = organic pull. README activation path. DO quota assessed (safe for now).
- Wave 4: Echo bot persistent (launchd). Diagnosed PyPI README as #1 activation bottleneck. Rewrote PyPI README. Show HN draft v1. Decision memo on persistence strategy. Two new blockers escalated: PyPI publish + public posting.
- Wave 5: **CF Worker echo bot deployed (24/7, global, no host dep).** Campaign 1 review: 4/5 done, 0 customer contact. Mapped competitive landscape. Zero external traces of qntm. Hard truth: 5 waves, 0 users.
- Wave 6: **FIRST EXTERNAL ENGAGEMENT** — A2A GitHub #1575 comment. Fixed echo bot (relay removed polling, rebuilt with WebSocket). Discovered published CLI is broken (P0). Test regression: 70 tests failing.
