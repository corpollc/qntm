# Wave 1 — Relaunch
Started: 2026-03-22T01:26:00Z

## Ops Review
- Relay: UP ✅ (healthz → 200)
- Tests: 299/300 (1 TUI compat issue — vi.hoisted under bun)
- Git: on feat/wave6-echo-bot-prep branch, 3 files ahead of main
- .company/ workspace: CREATED this wave
- Day One documents: ALL CREATED this wave

## Day One Documents Created
1. ✅ Mission memo v1
2. ✅ PR/FAQ v0.1
3. ✅ KPI dictionary v1
4. ✅ Decision rights map
5. ✅ Runway model v1
6. ✅ Thin-slice product plan
7. ✅ Target customer list (25 names)
8. ✅ Security/privacy/AI policy
9. ✅ Operating calendar
10. ✅ .company/ workspace structure

## Decisions Made
- Relaunch priorities: fix tests + customer-facing work simultaneously
- Test runner strategy: use vitest for client/ui/gateway (where tests were written for it), bun for TUI

## Executed
- Created all .company/ workspace directories
- Wrote all Day One shared memory documents
- Verified relay (UP), diagnosed test regressions (vitest compat, not real failures)
- Ran all test suites with correct runners: 299/300 green

## Remaining
- Measure TTFM (thin-slice #1)
- Fix TUI app.test.tsx vi.hoisted compat
- Merge branch to main
- Begin distribution research (CMO task)
