# Runway Model v1 — qntm
Created: 2026-03-22
DRI: Founder

## Current Costs (Monthly Estimates)

| Item | Cost | Notes |
|------|------|-------|
| Cloudflare Workers (free tier) | $0 | 100K requests/day, 10ms CPU |
| Cloudflare KV (free tier) | $0 | 100K reads/day, 1K writes/day |
| Cloudflare Durable Objects | ~$0.50 | Per-request pricing, minimal usage |
| Domain (corpo.llc) | $0 (prepaid) | Already provisioned |
| PyPI hosting | $0 | Free for open source |
| GitHub | $0 | Free tier |
| OpenClaw agent compute | $0 | Provided by corpo infrastructure |
| **Total** | **~$0.50/mo** | |

## Revenue: $0
## Runway: Effectively infinite at current burn

## Scaling Triggers
- >100K KV writes/day → upgrade to paid KV ($5/mo)
- >10M worker requests/mo → Workers paid plan ($5/mo)
- >1GB DO storage → DO pricing increase
- External API costs (if we host Gateway recipe execution) → per-request billing needed

## Pricing Hypothesis (untested)
- **Free tier**: Messaging only, up to N conversations
- **Paid tier**: API Gateway usage (per-recipe-execution or monthly)
- **Rationale**: Gateway is where we deliver unique value → charge there
- **Status**: Hypothesis only. Need customer conversations to validate.

## Key Assumptions
- Agent compute is subsidized by corpo infrastructure
- No marketing spend authorized (DENIED in autonomy)
- Growth is organic/outbound until customer evidence justifies spend request
