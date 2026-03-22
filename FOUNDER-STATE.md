# Founder State — qntm
Updated: 2026-03-22T05:50:00Z
Wave: 4 (COMPLETE)

## Horizon Goals (set wave 1, review wave 10)
1. 5+ active external conversations per week — NOT STARTED (1, echo bot only)
2. 3+ design partners using the protocol — NOT STARTED (0)
3. At least 1 team using the API Gateway — NOT STARTED (0)
4. TTFM measured and optimized to <10s — DONE ✅ (1.2s!)
5. All tests green, relay fully functional — DONE ✅ (465 green, relay fixed)

## Campaign Goals (set wave 1, review wave 5)
1. Deploy echo bot — DONE ✅ (live, persistent via launchd)
2. Distribution research — DONE ✅ (20 channels + 5 outbound messages drafted)
3. Write quick-start snippet for README — DONE ✅
4. Start 5 outbound conversations — BLOCKED (public posting DENIED)
5. Fix remaining test compat issue — DONE ✅ (self-resolved, 465/465 green)

## Wave 5 Top 5 (NEXT)
1. **Publish new PyPI release (v0.5.0)** — the single highest-leverage action. Updated README will show echo bot + value prop to 862 weekly downloaders. REQUIRES_APPROVAL for pypi-publish.
2. **Build CF Worker echo bot** — eliminate host dependency. Cron Trigger every 60s. Uses existing TS client library. CF Workers deploy is ALLOWED.
3. **First external conversation** — use qntm messaging to reach out to at least ONE agent developer. Even manual is fine. The echo bot conversation is the channel.
4. **Instrument PyPI → conversation funnel** — add relay endpoint to count conversation participants over time. Need to measure if updated README converts.
5. **Campaign review (wave 5 checkpoint)** — review all campaign goals, set new campaign for waves 6-10.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **Public posting DENIED** — Evidence continues to mount: 862 weekly downloads, 1,625 monthly, ZERO from marketing. All come from organic GitHub/PyPI discovery. Show HN draft ready. 5 outbound messages drafted. Echo bot live with persistence. Request: approve Show HN post OR grant limited posting scope.
2. **PyPI publish REQUIRES_APPROVAL** — The PyPI README is confirmed as the #1 activation bottleneck. 862 weekly downloaders see a bare-bones README with no echo bot, no value prop. Updated README is written and ready. Request: approve v0.5.0 PyPI publish with the updated README.

## Resolved Blockers
- ~~CF token invalid~~ — RESOLVED Wave 2
- ~~Relay poll broken (500/1101)~~ — RESOLVED Wave 2
- ~~TUI vi.hoisted test~~ — RESOLVED Wave 2
- ~~No activation path for new users~~ — RESOLVED Wave 3 (echo bot)
- ~~Echo bot dies on reboot~~ — RESOLVED Wave 4 (launchd plist)

## Metrics
- Tests: 465/465 ✅
- Relay: FULLY OPERATIONAL ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day): 1 (echo bot)
- Design partners: 0
- PyPI downloads:
  - Yesterday: 26
  - Last week: 862
  - Last month: 1,625
  - All-time (35 day window): 2,029+
- Outbound messages drafted: 5 (awaiting posting permission)
- Show HN draft: v1 ready (awaiting posting permission)
- Echo bot: LIVE ✅ (launchd persistent, auto-restart, survives reboots)

## What We Accomplished Wave 4
- Made echo bot persistent via launchd plist (survives reboots, auto-restarts on crash)
- Diagnosed the #1 activation bottleneck: PyPI README shows nothing useful to 862 weekly downloaders
- Rewrote PyPI README with value prop, echo bot demo, Python usage example
- Added next_step hint to identity.generate CLI output
- Drafted Show HN post (v1, ready for review)
- Wrote decision memo on echo bot persistence strategy (3-phase: launchd → CF Worker → WebSocket)
- Verified full first-run flow works with published package (v0.3 Go binary)
- Fixed GitHub URL references (corpollc, not corpo-dev)

## Ops Log
- Wave 1: Full relaunch. All Day One docs. TTFM 1.2s. Distribution + competitive research. CF token blocker escalated.
- Wave 2: Fixed relay poll (KV→SQLite). CF deploy working. 465 tests green. Quick-start, outbound msgs, tutorial, truth register. Public posting remains only blocker.
- Wave 3: Echo bot LIVE. First active conversation. PyPI analysis: 823 real downloads with 0 marketing = organic pull. README activation path. DO quota assessed (safe for now).
- Wave 4: Echo bot persistent (launchd). Diagnosed PyPI README as #1 activation bottleneck. Rewrote PyPI README. Show HN draft v1. Decision memo on persistence strategy. Two new blockers escalated: PyPI publish + public posting.
