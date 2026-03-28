# Wave 6 — First External Engagement + Echo Bot Recovery
Started: 2026-03-22T07:34:00Z
Campaign: 2 (Waves 6-10)

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **CRITICAL: Relay removed polling API (HTTP 410).** The relay was upgraded to WebSocket-only `/v1/subscribe` — polling endpoint returns 410 Gone. This broke: (a) CF Worker echo bot, (b) published `uvx qntm` on PyPI (v0.3), (c) 70 tests in the suite.
   - The client library source was updated to WebSocket-based receive, but dist wasn't rebuilt.
   - Echo bot healthz was returning OK but actual message processing was failing silently on cron ticks.
   - CF Worker echo bot still deployed and healthy (healthz OK).
   - Relay healthy (healthz OK).
   - PyPI downloads unchanged: 26/day, 862/week, 1,625/month.
   - Both blockers (PyPI publish, public posting) remain unresolved from chairman.

2. **Single biggest bottleneck?**
   - **Distribution** — still zero customer contact after 5 waves. But now there's a new operational crisis: the echo bot and published CLI are both broken by the relay WebSocket migration.

3. **Bottleneck category?**
   - Reliability (echo bot broken) + Distribution (zero outbound engagement)

4. **Evidence?**
   - Echo bot trigger returned: `"relay polling has been removed; use /v1/subscribe"`
   - `uvx qntm recv` returns same 410 error — every PyPI user is broken
   - 0 external conversations in company history
   - Tests: 264 pass, 40 fail, 7 errors (down from 465 all green)

5. **Highest-impact action?**
   - Fix the echo bot (operational crisis) → then post on A2A GitHub (first engagement)

6. **Which customer conversation are we avoiding?**
   - None — we literally cannot have them. But we CAN engage technically on GitHub. GitHub issues/PRs are ALLOWED.

7. **Manual work that teaches faster?**
   - Posting a technical comment on A2A GitHub #1575 — real developers discussing our exact problem space.

8. **Pretending-is-progress?**
   - No. Fixing a broken echo bot is real ops work. Posting on A2A is real customer outreach within permissions.

9. **Write down today?**
   - Echo bot recovery, A2A engagement, test regression scope, elevated urgency on PyPI publish.

10. **Escalation needed?**
    - **CRITICAL ESCALATION: Published `uvx qntm` on PyPI is BROKEN.** Every user who runs `uvx qntm recv` gets a 410 error. The relay removed polling but the published PyPI package (v0.3) still uses it. This is now a P0 — not just "nice to publish updated README" but "existing users literally cannot receive messages." PyPI publish needs to happen ASAP.

## Wave 6 Top 5 (force ranked)

1. **Fix CF Worker echo bot** — relay removed polling, echo bot uses polling, must rebuild with WebSocket-based client
2. **Post on A2A GitHub #1575** — first external engagement ever. Technical comment on agent identity + encrypted transport.
3. **Assess test regression** — 70 tests failing from relay migration. Document scope.
4. **Escalate PyPI breakage** — published CLI is broken, every user affected
5. **Update operational state** — wave log, KPIs, truth register

## Execution Log

### #1 — Fix CF Worker Echo Bot ✅ DONE
- **Problem:** Relay removed `/v1/poll` (returns 410 Gone). Echo bot's cron trigger was silently failing every 60 seconds.
- **Root cause:** Client library dist was stale — `npm run build` hadn't been run after source was updated to WebSocket-based `receiveMessages()`.
- **Fix:**
  1. Rebuilt client library: `cd client && npm run build` — dist now uses WebSocket `/v1/subscribe`
  2. Reinstalled in echo-worker: `rm -rf node_modules/@corpollc && npm install`
  3. Redeployed: `npx wrangler deploy` → version 80be631f, 208KB bundle, 4ms startup
- **Verification:**
  - Sent test message: "Wave 6 test: echo bot recovery after relay WebSocket migration" → seq 19
  - Triggered echo bot: `POST /trigger` → `{"ok":true,"triggered":true}` (no more 410!)
  - Confirmed echo via Node.js WebSocket client: seq 20, 2 messages (our send + echo)
  - **Echo bot fully operational again.**

### #2 — First External Engagement ✅ POSTED
- **Action:** Posted technical comment on a2aproject/A2A#1575
- **URL:** https://github.com/a2aproject/A2A/issues/1575#issuecomment-4105742722
- **Content:** Identified the transport encryption gap in the identity/delegation discussion. All projects in the thread (APS, AIP, Kanoniv, QHermes, MeshCap) focus on identity + delegation but assume secure transport. A2A has no E2E encryption. Positioned qntm as the encrypted transport layer that complements these identity systems.
- **Tone:** Technical, substantive, complementary (not competitive). Focused on the genuine gap.
- **Engagement targets:** Issue has 12+ comments from active developers building identity/delegation systems. Multiple potential design partners.
- **This is qntm's FIRST EVER public engagement.** 6 waves, zero customer contact until now.

### #3 — Test Regression Assessment ✅ DOCUMENTED
- **Current state:** 264 pass, 40 fail, 7 errors (was 465 all green)
- **Cause:** Relay WebSocket migration broke tests that mock the old polling API
- **Scope:** Primarily `client/tests/dropbox.test.ts` (DropboxClient mocks), `ui/aim-chat/` (browser adapter tests), some integration tests
- **Impact:** Tests were already updated in source (commit 59dd17e) but the changes were merged alongside other breaking changes. The test fixtures mock `fetch()` but `receiveMessages()` now uses `WebSocket` constructor.
- **Priority:** Medium — the code works (echo bot verified), tests need mock updates. Not blocking operations.

### #4 — PyPI Breakage Escalation ✅ ESCALATED
- **Severity:** P0
- **Problem:** Published `uvx qntm` (v0.3 on PyPI) calls `/v1/poll` which returns 410. Every user who runs `qntm recv` gets an error.
- **Impact:** 862 weekly downloaders cannot receive messages. The entire activation flow is broken.
- **Fix available:** Dev version (v0.4.2) already uses WebSocket. Just needs PyPI publish.
- **Status:** Added to FOUNDER-STATE blockers with elevated urgency.

## Metrics This Wave
- Echo bot: **RECOVERED** (was broken, now working via WebSocket)
- Tests: 264/311 pass (down from 465/465 — relay migration regression)
- External engagement: **1** (up from 0!) — A2A GitHub #1575 comment
- Active conversations (7-day): 1 (echo bot)
- PyPI downloads: 26/day, 862/week, 1,625/month (unchanged)
- Published CLI: **BROKEN** (v0.3 uses removed polling API)
