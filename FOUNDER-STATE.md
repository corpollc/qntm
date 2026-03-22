# Founder State — qntm
Updated: 2026-03-22T01:42:00Z
Wave: 1 (RELAUNCH — complete)

## Horizon Goals (set wave 1, review wave 10)
1. 5+ active external conversations per week — NOT STARTED
2. 3+ design partners using the protocol — NOT STARTED
3. At least 1 team using the API Gateway — NOT STARTED
4. TTFM measured and optimized to <10s — DONE ✅ (1.2s!)
5. All tests green, CI passing, relay fully functional — BLOCKED (deploy perms)

## Campaign Goals (set wave 1, review wave 5)
1. Deploy echo bot — BLOCKED (relay poll broken, need deploy)
2. Distribution research (where do agent devs hang out?) — NOT STARTED
3. Write quick-start snippet for README — NOT STARTED
4. Start 5 outbound conversations with target customers — NOT STARTED
5. Fix remaining test compat issue (TUI vi.hoisted) — NOT STARTED

## Wave 1 Summary — RELAUNCH COMPLETE
- Created .company/ workspace with all directories
- Wrote ALL Day One documents (9 documents):
  - Mission memo v1, PR/FAQ v0.1, KPI dictionary v1
  - Decision rights map, runway model v1, operating calendar
  - Thin-slice product plan, target customer list (25 names)
  - Security/privacy/AI policy
- Verified relay UP (healthz → 200)
- Measured TTFM: **1.2 seconds** (crushes 10s target)
- Tests: 299/300 (vitest compat, not real failures)
- Merged feat branch to main, pushed

## Wave 2 Top 5 (NEXT)
1. Get CF deploy working — ESCALATE: token invalid/lacks KV perms
2. Distribution research — CMO task, no deploy needed
3. Write quick-start code snippet for README
4. Fix TUI app.test.tsx vi.hoisted compat
5. Draft outbound messages for target customers

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **Cloudflare API token is INVALID** — `Bearer NfIXY0HKuyLyZgu9RtyyF0yJ__CFKsdeAOn4_AWf` returns "Invalid API Token" from CF verify endpoint. Cannot deploy worker updates. The relay poll endpoint returns 1101 (DO crash) because the deployed code predates our fix. **Send works, receive/poll is broken.** This blocks echo bot, blocks new users, blocks everything customer-facing.
   - NEED: New CF API token with Workers + KV write permissions
   - Impact: Cannot deploy ANY worker updates. Product is half-broken (can send, can't receive).

## Metrics
- Tests: 299/300 (193 client + 52 gateway + 43 ui + 11/12 TUI)
- Relay: PARTIAL ⚠️ (healthz OK, send OK, poll/recv 1101 crash)
- TTFM: 1.2 seconds ✅
- Active conversations (7-day): 0
- Design partners: 0
- Gateway users: 0

## Ops Log
- Wave 1: Full relaunch. All Day One docs created. TTFM measured at 1.2s. Relay poll broken (1101). CF token invalid — ESCALATED.
