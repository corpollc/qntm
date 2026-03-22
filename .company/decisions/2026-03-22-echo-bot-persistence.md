# Decision: Echo Bot Persistence Strategy
Date: 2026-03-22 (Wave 4)
DRI: Founder

## Problem
The echo bot (our only activation path) runs as a nohup process on the founder's MacBook. It died between waves, returning the primary metric to 0. Every new `uvx qntm` user who follows the README hits a dead bot.

## Target Customer
New agent developers who run `uvx qntm` and need immediate proof of value.

## Evidence
- Echo bot died between wave 3 and wave 4 (predicted but not prevented)
- 862 weekly PyPI downloads → 0 new echo bot participants (bot was dead during this window)
- Primary metric dropped from 1 → 0 active conversations
- The only activation path requires a responsive echo bot

## Options Considered

### Option A: launchd plist (macOS) — IMPLEMENTED
- **Pros:** Immediate fix, auto-restart on crash, survives reboots
- **Cons:** Depends on founder's MacBook being on, no global availability, uses DO polling (17K req/day)
- **Cost:** Zero
- **Time to implement:** 15 minutes

### Option B: Cloudflare Worker echo bot
- **Pros:** Global, always-on, zero-maintenance, uses Cron Triggers (not polling), no DO quota impact
- **Cons:** Must handle crypto in Worker context (TypeScript), needs separate deploy, complexity
- **Cost:** Free tier (Workers + Cron Triggers)
- **Time to implement:** 2-4 hours

### Option C: Cloudflare Worker with WebSocket subscription
- **Pros:** Best of B + real-time response (no poll delay), prepares for WebSocket migration (bead qntm-szex)
- **Cons:** Most complex, WebSocket support may need DO for the subscriber
- **Cost:** Free tier
- **Time to implement:** 4-8 hours

## Decision
**Phase 1 (now): Option A** — launchd plist installed and verified. Bot survives reboots.
**Phase 2 (next wave): Option B** — CF Worker echo bot with Cron Trigger (poll every 60s from Worker instead of 5s from MacBook). This eliminates host dependency AND reduces DO load.
**Phase 3 (later): Option C** — When WebSocket migration happens (bead qntm-szex), upgrade echo bot to subscribe.

## Expected Metric Effect
- Primary metric stabilizes at ≥1 (echo bot conversation always active)
- Activation path reliability: 100% uptime for new users
- DO request load: reduces from 17K/day (5s polling) to ~1.5K/day (60s Cron Trigger)

## Reversible? Yes — can switch between any option
## Confidence: 0.9
## Escalation: No (CF Workers deploy is ALLOWED per AUTONOMY)
## Review: Wave 6
