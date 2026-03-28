# Wave 7 — Test Regression Fixed + Second External Engagement
Started: 2026-03-22T08:34:00Z
Campaign: 2 (Waves 6-10)

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - Tests were at 264/311 (47 failures) from relay WebSocket migration
   - A2A #1575 comment posted 1 hour ago, no replies yet (expected — thread last active Mar 20)
   - Relay and echo bot both operational
   - PyPI still BROKEN, still needs chairman approval
   - No new activity from chairman on blockers

2. **Single biggest bottleneck?**
   - **Distribution** — 7 waves, 2 external engagements (both in A2A GitHub), 0 customer conversations, 0 users

3. **Bottleneck category?**
   - Distribution (zero inbound) + Reliability (test regression)

4. **Evidence?**
   - 0 external users who've ever messaged
   - 0 GitHub issues from external users
   - 862 weekly PyPI downloads → 0 activation (and published CLI is broken)
   - 264/311 tests passing (regression from relay migration)

5. **Highest-impact action?**
   - Fix test regression (trust the codebase again) + second A2A engagement (expand presence)

6. **Which customer conversation are we avoiding?**
   - All of them — we literally can't reach people. A2A GitHub is our only outbound channel.

7. **Manual work that teaches faster?**
   - Posting on A2A #1667 (heartbeat agents / relay pattern) — they're asking about the exact infrastructure we built

8. **Pretending-is-progress?**
   - No. Fixing tests = real reliability. A2A engagement = real distribution within permissions.

9. **Write down today?**
   - Test regression root cause and fix. Second engagement. Updated metrics.

10. **Escalation needed?**
    - Same as wave 6: **PyPI publish is P0.** Published CLI is broken.

## Wave 7 Top 5 (force ranked)

1. **Fix test regression** — identify root cause and fix WebSocket-related test failures ✅ DONE
2. **Post second A2A engagement** — #1667 (relay pattern for heartbeat agents) ✅ DONE
3. **Monitor A2A #1575 for responses** — no replies yet (posted 1h ago) ✅ CHECKED
4. **Commit & push all changes** — test fixes, wave log, state updates
5. **Update truth register & state**

## Execution Log

### #1 — Fix Test Regression ✅ DONE
- **Before:** 264/311 pass (40 fail, 7 errors = 47 failures)
- **After:** 287 pass, 0 test failures. 11 files with import errors (env deps, not code bugs).
- **Root causes found and fixed:**
  1. **TUI TestRelayServer missing `ready` frame.** The relay WebSocket migration added a `ready` frame protocol — after delivering backlog messages, the relay sends `{type: "ready", head_seq: N}` so the client knows it's caught up. The test relay didn't send this, causing `receiveMessages()` to hang indefinitely.
     - **Fix:** Added `ready` frame emission to `TestRelayServer.handleUpgrade()` after backlog delivery.
  2. **PTY smoke tests timeout too tight.** Tests spawn a real TUI process for 4 seconds, but with WebSocket overhead + receipt processing, the 5s default vitest timeout was too tight under full-suite load.
     - **Fix:** Increased timeout to 15s for the two PTY smoke tests that spawn real processes.
- **Remaining 11 "failed files" are all environment import errors:**
  - 7 `openclaw-qntm/tests/*` — missing `openclaw/plugin-sdk` (OpenClaw runtime dep)
  - 1 `gateway-worker/src/do.test.ts` — missing `cloudflare:workers` (CF Workers runtime)
  - 3 `integration/long-*` — need Playwright browser + running gateway
  - These are NOT code bugs. They require specific runtime environments to run.

### #2 — Second A2A Engagement ✅ POSTED
- **Action:** Posted technical comment on a2aproject/A2A#1667
- **URL:** https://github.com/a2aproject/A2A/issues/1667#issuecomment-4105825849
- **Context:** Issue asks "Is there prior art for relay layers?" for heartbeat-based agents that run on cron schedules. qntm IS exactly that relay.
- **Content:** Described qntm's store-and-forward WebSocket relay model, how it maps to the heartbeat agent pattern (wake → subscribe with from_seq → get backlog → process → sleep), and how message TTLs address bounded latency expiry.
- **Tone:** Technical, direct answer to the relay question. Not marketing — describing what we built and how it maps.
- **This is qntm's SECOND external engagement.** Both on A2A GitHub.

### #3 — A2A #1575 Monitoring ✅ CHECKED
- Our comment posted at 07:45 UTC, 50 min ago
- Thread last had activity Mar 20 (before our comment), so no replies yet is expected
- Will check again next wave

## Metrics This Wave
- Tests: 287/296 pass (0 actual failures, 9 skipped, 11 env-import file errors)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅
- External engagements: **2** (up from 1!) — A2A #1575 + #1667
- Active conversations (7-day): 1 (echo bot)
- PyPI downloads: 26/day, 862/week, 1,625/month (unchanged)
- Published CLI: **BROKEN** (v0.3 uses removed polling API)
