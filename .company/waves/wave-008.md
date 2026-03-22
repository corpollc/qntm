# Wave 8 — Instrument Primary Metric + Monitor Engagements
Started: 2026-03-22T09:34:00Z
Campaign: 2 (Waves 6-10)

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - ~45 minutes elapsed since wave 7 completion
   - Both A2A comments (#1575, #1667) still sitting — no replies yet
   - #1667 thread is very active (3 replies between Mar 21-22 before our comment)
   - Relay and echo bot both operational (healthz OK, echo bot responding)
   - PyPI still BROKEN, still needs chairman approval
   - No new chairman direction on blockers
   - No new substantive A2A issues since wave 7

2. **Single biggest bottleneck?**
   - **Distribution** — 8 waves, 2 external engagements, 0 customer conversations, 0 users. Published CLI is broken so even organic pull leads to broken experience.

3. **Bottleneck category?**
   - Distribution (zero inbound, can't post publicly) + broken product (published CLI 410)

4. **Evidence?**
   - 0 external users who've ever sent a message
   - 0 GitHub issues from external users
   - 0 conversations beyond echo bot self-test
   - Published CLI returns 410 on `qntm recv`
   - 862 weekly downloads → 0 activation → 0 retention

5. **Highest-impact action?**
   - **Instrument the primary metric.** Active conversations (7-day) is the north star metric and we literally cannot measure it from the relay side. Adding a `/v1/stats` endpoint makes the metric real and automated. CF deploy is ALLOWED. Won't generate users but makes the company smarter.

6. **Which customer conversation are we avoiding?**
   - All of them. We've never spoken to a single user. A2A GitHub comments are the closest we've gotten to external technical dialogue.

7. **Manual work that teaches faster?**
   - Monitoring A2A thread responses. If anyone replies to our comments, engage immediately — that's the manual selling work.

8. **Pretending-is-progress?**
   - Instrumenting a metric when there's nothing to measure could be vanity. But it's 15 minutes of work, makes the system self-aware, and removes "we can't measure it" as an excuse.

9. **Write down today?**
   - Stats endpoint implementation. A2A engagement status. Updated metrics.

10. **Escalation needed?**
    - Same as wave 6-7: **PyPI publish is P0.** Published CLI is broken for all users.

## Wave 8 Top 5 (force ranked)

1. **Instrument active conversations metric** — add `/v1/stats` endpoint to relay worker that counts conversations with activity in last 7 days. Deploy to CF. PRIMARY METRIC.
2. **Monitor A2A #1575 and #1667 for responses** — engage immediately if any replies
3. **Evaluate A2A #1029 (pub/sub) for third engagement** — 15 comments, directly relevant to relay, but last activity Feb 5 (6 weeks ago). Only post if genuinely useful, not necro-bumping.
4. **PyPI publish (if approved)** — P0, still blocked on chairman approval
5. **Write wave log, update state, update truth register**

## Execution Log

### #1 — Instrument Active Conversations Metric ✅ DONE
- **Added `/v1/stats` endpoint to relay worker** — returns `active_conversations_7d` count and per-conversation timestamps
- **Architecture:** Single KV key (`/__stats__/active_conversations`) stores a map of conv_id → last_message_ts. Updated on every `/v1/send`. Entries older than 7 days pruned on write.
- **Why single key:** KV `list()` has daily limits on free tier (hit that the hard way on first attempt). Single key with JSON map avoids list operations entirely.
- **Deployed:** Version `8617aade` → tested live. Stats endpoint returns correct data.
- **Tested:** Sent test message to echo bot → stats showed 1 active conversation. Echo bot replied → `last_message_ts` updated. Confirmed round-trip tracking works.
- **Live URL:** `https://inbox.qntm.corpo.llc/v1/stats`
- **First real reading:** 1 active conversation (echo bot conv `48055654...`)

### #2 — Monitor A2A Engagements ✅ CHECKED
- **#1575 (identity/delegation):** Our comment posted wave 6 at 07:45 UTC. Thread had activity from @aeoess on Mar 20, then our comment on Mar 22. No replies to our comment yet. Thread is technical and slower-paced — normal for identity discussions.
- **#1667 (heartbeat agents / relay):** Our comment posted wave 7 at 08:46 UTC. Thread had active discussion: 3 comments Mar 21-22 from @The-Nexus-Guard and @archedark-ada. We're the 4th comment, directly answering the "Is there prior art for relay layers?" question. No replies yet but thread is very fresh.
- **Assessment:** Both threads are correctly positioned. Wait for organic responses. 

### #3 — Evaluate Third A2A Engagement ❌ DECLINED
- **#1029 (pub/sub):** 15 comments but last activity Feb 5 (6+ weeks stale). Discussion focused on broker implementations (Kafka, FastStream) — not relay patterns. Necro-bumping would feel forced.
- **#1628 (trust signals):** 10 comments, about on-chain credentials and vouch chains. Not directly relevant to qntm's relay/encryption value prop.
- **Decision:** Don't force it. Two well-positioned engagements on active threads is better than three that include a weak one. Will watch for new issues that match our value prop.

### #4 — Confirmed P0 Still Active
- Ran `qntm recv 480` → got `HTTP 410: "relay polling has been removed; use /v1/subscribe"` 
- This is the exact same error all PyPI users would get. The published CLI is broken.
- **PyPI publish still blocked on chairman approval.**

## Metrics This Wave
- Tests: 287/296 pass (0 actual failures, 9 skipped, 11 env-import file errors) — unchanged
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ + `/v1/stats` endpoint live
- **Active conversations (7-day): 1** (echo bot, NOW MEASURED BY RELAY)
- External engagements: 2 (unchanged — A2A #1575 + #1667, awaiting responses)
- Active conversations metric: **NOW INSTRUMENTED** ✅
- PyPI downloads: 26/day, 862/week, 1,625/month (unchanged)
- Published CLI: **BROKEN** (v0.3 uses removed polling API)
