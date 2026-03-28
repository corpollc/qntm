# Operating Calendar — qntm
Created: 2026-03-22

## Wave Cadence (~45min cron cycles)

| Frequency | Activity | Output |
|-----------|----------|--------|
| Every wave | Ops review, execute Top 5, wave log | FOUNDER-STATE.md, wave log |
| Every 5 waves | Strategy review, campaign goal reset | Updated horizon/campaign goals |
| Every 10 waves | Horizon review, retro + decision audit | Decision audit doc |
| Weekly (wall clock) | Customer truth review | customers/ log update |
| Monthly (wall clock) | Chairman review packet | Memo to Pepper |

## Wave Execution Pattern
1. Read FOUNDER-STATE.md
2. Ops review (tests, relay, subagent results)
3. Check KPIs (`tail -5 .company/kpis.jsonl`)
4. Re-evaluate Top 5
5. Execute #1
6. Wave log + KPI append + state update

## Strategy Review (every 5 waves)
1. Are Horizon goals still correct?
2. Campaign retrospective
3. New Campaign Top 5
4. Org changes needed?
5. What should we STOP doing?

## Reporting
- Every wave: FOUNDER-STATE.md (Pepper reads on heartbeats)
- Blockers: Blockers section of FOUNDER-STATE.md
- Strategy changes: explicit memo to Pepper
- Monthly: Chairman review packet

## Current Position
- Wave 1 of relaunch (was wave 7, now reset to wave 1 per kernel reboot)
- Horizon review: wave 10
- Campaign review: wave 5
- Next strategy review: wave 5
