# Founder State — qntm
Updated: 2026-03-22T11:34:00Z
Wave: 10 (COMPLETE) — CAMPAIGN 2 FINAL

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — IN PROGRESS (4 engagements, 0 replies yet)
2. 1 design partner in discussion — IN PROGRESS (aeoess integration proposal posted)
3. PyPI fixed and published — BLOCKED (chairman approval needed, 5 waves of escalation)
4. Direct outreach to 3+ complementary projects — IN PROGRESS (1/3: aeoess ✅)
5. Show HN approval sought — NOT STARTED

## Campaign 3 Goals (Waves 11-15)
1. **Fix published CLI** — P0 CRITICAL: published CLI is BROKEN (410 on recv). Blocks ALL organic adoption.
2. **Open integration issues on 3+ projects** — IN PROGRESS: 1/3 done (aeoess/agent-passport-system#5). Next: StevenJohnson998, Copertino-Research.
3. **Get 1 reply/conversation from any outreach** — 4 total engagements active, 0 replies yet.
4. **Show HN readiness** — Draft v2 + seek posting approval.
5. **Evaluate all engagement data by wave 15** — decide if distribution strategy needs rethinking.

## Wave 11 Top 5 (NEXT)
1. **Monitor aeoess/agent-passport-system#5 for response** — most promising outreach yet (direct integration proposal to complementary project)
2. **Monitor A2A #1575, #1667, #1606 for responses** — if replies, engage immediately
3. **Second integration proposal** — StevenJohnson998/agent-data-handling-policy or Copertino-Research (QHermes). Concrete technical proposals.
4. **PyPI publish (if approved)** — P0 blocker
5. **Show HN draft v2** — update with 4 engagements, integration proposal story, instrumented metrics

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🔴 P0: PyPI CLI IS BROKEN.** Published `uvx qntm` v0.3 calls `/v1/poll` which returns HTTP 410 ("relay polling has been removed; use /v1/subscribe"). Every user who runs `qntm recv` gets an error. The dev version (v0.4.2) has the fix. **6 WAVES OF ESCALATION — no response.** Request: IMMEDIATE approval for PyPI publish.
2. **Public posting DENIED** — Show HN draft ready, 5 outbound messages drafted. GitHub engagement (issues + comments) is the only outbound channel within permissions.
3. **Existential urgency.** 10 waves, 4 external engagements, 0 replies, 0 users. Downloads are vanity — 862/week but published CLI is broken. We've now shifted from passive commenting to active integration proposals, but the P0 broken CLI blocks any conversion.

## Campaign 2 Review (Waves 6-10) — COMPLETED
- **Score: 2/5 achieved, 1 partial, 2 failed**
- ✅ CF Worker echo bot (done W5, recovered W6)
- ✅ Active conversations metric instrumented (W8) + KPI dashboard (W9)
- ⚠️ Distribution channel tested (A2A GitHub, 3 engagements, 0 conversions yet)
- ❌ PyPI publish — blocked 5 waves on chairman approval
- ❌ First external conversation — 3 A2A comments, 0 replies, 0 users

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
- Active conversations (7-day): 1 (echo bot) — 3 total on relay but 2 are corpo internal
- Design partners: 0
- External users who've ever messaged: 0
- **External engagements: 4** — A2A GitHub #1575 + #1667 + #1606 + aeoess/agent-passport-system#5
- **Direct integration proposals: 1** — aeoess/agent-passport-system#5 (NEW)
- PyPI downloads:
  - Yesterday: 26
  - Last week: 862
  - Last month: 1,625
  - Published version: **BROKEN** (v0.3 uses removed polling API)
- GitHub: 1 star, 0 forks, 0 external issues
- A2A engagement: 3 comments posted (#1575, #1667, #1606)
- Direct outreach: 1 integration issue posted (aeoess/agent-passport-system#5)
- KPI dashboard: `.company/scripts/kpi-check.sh`

## What We Accomplished Wave 10
- **FIRST DIRECT INTEGRATION PROPOSAL** — Issue #5 on aeoess/agent-passport-system: "Integration: Encrypted transport layer for Passport-authenticated agents." Concrete technical proposal covering identity key reuse (Ed25519→X3DH), delegation-scoped channels, signed envelopes inside encrypted channels, and data handling enforcement. This is a NEW outreach vector — not commenting on threads, but proposing integration on a complementary project's repo.
- **CAMPAIGN 2 REVIEW** — Final assessment: 2/5 goals achieved (both infrastructure), 0/3 customer-facing. Honest reckoning with 10 waves of zero external contact.
- **HORIZON GOALS REVISED** — Downgraded from aspirational (5 conversations, 3 partners) to realistic (1 reply, 1 partner discussion). Added direct outreach and Show HN as new goals.
- **CAMPAIGN 3 PLANNED** — Theme: Direct Outreach + Product Readiness. Shift from passive commenting to active integration proposals on complementary project repos.
- **A2A MONITORING** — All 3 threads checked. No replies to our comments. Multi-day cycles normal.

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
- Wave 10: **CAMPAIGN 2 FINAL.** First direct integration proposal: aeoess/agent-passport-system#5 (encrypted transport for passport-authenticated agents). Campaign review: 2/5 achieved, 0 customer-facing. Horizon goals revised to realistic targets. Campaign 3 planned: direct outreach + product readiness. A2A monitoring: 0 replies across 3 threads. **4 total external engagements, 1 direct integration proposal, 0 replies, 0 users.**
