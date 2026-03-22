# KPI Dictionary v1 — qntm
Created: 2026-03-22
DRI: Founder

## Primary Metric
**Active conversations (7-day):** Count of conversations where ≥2 distinct participants exchanged ≥1 message each in the trailing 7 calendar days.
- Source: Relay KV/DO query
- Frequency: Every wave (automated when instrumented)
- Owner: COO
- Baseline: 0 (as of 2026-03-22)
- Target (Month 1): ≥5

## Leading Indicators

### L1: CLI Installs → Identity Generated
- **Definition:** Count of unique `uvx qntm` executions that result in a new identity keypair being created
- **Source:** PyPI download stats (proxy) + client telemetry (when instrumented)
- **Frequency:** Weekly
- **Owner:** CMO
- **Baseline:** Unknown
- **Target:** ≥25/week by Month 1

### L2: Identity → First Conversation Created
- **Definition:** % of new identities that create or join a conversation within 24 hours
- **Source:** Client telemetry (when instrumented)
- **Frequency:** Weekly
- **Owner:** CPO
- **Baseline:** Unknown
- **Target:** ≥50%

### L3: Time to First Message (TTFM)
- **Definition:** Wall-clock seconds from `uvx qntm` invocation to first message successfully sent
- **Source:** Manual measurement until instrumented
- **Frequency:** Every wave (manual), daily (instrumented)
- **Owner:** CPO
- **Baseline:** Unmeasured
- **Target:** <10 seconds

### L4: Multi-participant Conversations
- **Definition:** Count of conversations with ≥2 participants who have each sent ≥1 message
- **Source:** Relay query
- **Frequency:** Weekly
- **Owner:** Founder
- **Baseline:** 0
- **Target:** ≥3 by Month 1

### L5: Gateway Requests
- **Definition:** Count of API Gateway recipe executions (approved + denied)
- **Source:** Gateway DO logs/metrics
- **Frequency:** Weekly
- **Owner:** CPO
- **Baseline:** 0
- **Target:** ≥1 team using by Month 1

## Operational Metrics (health, not goals)

### O1: Test Suite Health
- **Definition:** Pass/fail/error counts across all test suites
- **Source:** `bun test` output
- **Frequency:** Every wave
- **Owner:** CTO
- **Current:** 250 pass / 41 fail / 5 errors (vitest compat issue)

### O2: Relay Uptime
- **Definition:** % of time inbox.qntm.corpo.llc/healthz returns 200
- **Source:** Health check (manual until monitoring set up)
- **Frequency:** Every wave
- **Owner:** COO
- **Current:** UP ✅

### O3: Deploy Frequency
- **Definition:** Number of production deploys per week
- **Source:** Git tags + CF deploy logs
- **Frequency:** Weekly
- **Owner:** COO

## Instrumentation Status
| Metric | Instrumented? | Next Step |
|--------|--------------|-----------|
| Active convos (7d) | ❌ | Add relay endpoint to query |
| CLI installs | ❌ | Check PyPI stats API |
| Identity → convo | ❌ | Client telemetry |
| TTFM | ❌ | Manual measurement first |
| Multi-participant | ❌ | Relay query |
| Gateway requests | ❌ | Gateway DO counter |
| Test health | ✅ | `bun test` |
| Relay uptime | ✅ (manual) | Set up automated checks |
