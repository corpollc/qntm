# Founder State — qntm
Updated: 2026-03-21T22:40:00Z
Wave: 4

## Phase: OPERATING (dropbox fix complete, deploy blocked on CF token perms)

## Summary — Wave 4
1. **CRITICAL FINDING: Gateway DO has same bug** — `GatewayConversationDO` used `implements DurableObject` instead of `extends DurableObject<Env>`. Fixed: replaced class declaration, added `super(ctx, env)`, converted all `this.state` → `this.ctx` (55 occurrences). Added `cloudflare:workers` mock for vitest. Updated compat_date to 2025-09-01. All 52 gateway tests pass ✅.
2. **Created deploy-worker.yml** — GitHub Actions workflow for automated dropbox relay CI/CD on push to main.
3. **Peter added WebSocket subscriptions** — Commit `ef2df5f` adds realtime WebSocket transport to the relay. Major change: 15 files, +1390/-362 lines. New `/v1/subscribe` endpoint, new `DropboxClient` module in client.
4. **Relay still DOWN** — /healthz returns 200, but /v1/send and /v1/poll return 1101 (DO crash). Fix is built and verified but not deployed. CF token still lacks KV write permissions.

## Critical Blockers
- **CLOUDFLARE_API_TOKEN**: Token in ~/.env lacks KV write permissions. Error: "kv bindings require kv write perms [code: 10023]". Need Peter to create/update a token with: Workers Scripts Write + KV Write + Durable Objects Write. (escalated waves 2, 3, 4)

## Current prod status:
- /healthz → ✅ responds (200)
- /v1/send → ❌ 1101 (DO crash — fix not yet deployed)
- /v1/poll → ❌ 1101 (same)
- gateway.corpo.llc → ❌ 404 (gateway likely has same DO bug — fix ready but not deployed)

## Horizon Goals (set wave 1, next review wave 10)
1. Dropbox relay UP and stable with monitoring — MEASURABLE: 99.9% uptime over 24h
2. CI/CD pipeline deploys worker automatically on push — MEASURABLE: merge triggers deploy — PARTIALLY DONE (workflow created, needs CF secrets in GitHub)
3. Full integration test suite passing — MEASURABLE: all 7 integration test files green
4. Gateway worker verified healthy — MEASURABLE: gateway.corpo.llc responds correctly — FIX READY (gateway DO bug fixed, needs deploy)
5. Agent-to-agent comms working via qntm (Corpo Founder ↔ Pepper) — MEASURABLE: messages flow

## Campaign Goals (set wave 1, next review wave 5 ← DUE)
1. Deploy dropbox fix + gateway fix to production — BLOCKED (CF token needs KV write perms)
2. Add monitoring cron for dropbox health — MEASURABLE: health check runs every 5 min, alerts on failure
3. Fix TUI test failures — ✅ DONE (wave 3)
4. Create worker deploy CI/CD workflow — ✅ DONE (wave 4, deploy-worker.yml created)
5. Fix gateway DO bug — ✅ DONE (wave 4, same extends DurableObject fix applied)

## Wave 4 Top 5
1. Deploy dropbox fix — BLOCKED (CF token, re-escalated)
2. Fix gateway DO bug — ✅ DONE (commit 12c9afc)
3. Create deploy-worker CI/CD workflow — ✅ DONE (deploy-worker.yml)
4. Review Peter's WebSocket subscription commit — NOTED (ef2df5f, major transport change)
5. Run full test suite — ✅ ALL PASS (Client 193/193, AIM 43/43, TUI 12/12, Gateway 52/52)

## Next Wave (5) Top 5 — STRATEGY REVIEW DUE
1. Deploy dropbox + gateway fixes — BLOCKED (awaiting CF token update from Peter)
2. Write monitoring health check cron for dropbox relay
3. Review + test Peter's WebSocket subscription code
4. Run integration tests against live relay (once deployed)
5. Strategy review: reassess Campaign/Horizon goals at wave 5

## Ops Log
- Wave 0 (bootstrap): Full assessment. Dropbox outage diagnosed (compat date). Fix built, branch pushed. Plan written. 244/246 tests passing.
- Wave 1 (skipped — cron gap)
- Wave 2: CRITICAL DISCOVERY — compat date fix was NOT enough! Real root cause: DO class must extend base DurableObject class (not implement interface) when using new_sqlite_classes. Fixed in commit 4144e1e. Verified locally. Deploy still blocked — CF token lacks KV write permissions. Re-escalated via Pepper.
- Wave 3: Fixed TUI pty-smoke test failures. Root cause: expect's `sleep` blocks PTY reads → PTY buffer fills → Node.js stdout.write blocks → event loop stalls → React useEffect callbacks never fire. Fix: replaced sleep with active drain loop. 12/12 TUI tests pass. Commit 4d6cd83.
- Wave 4: CRITICAL FINDING — gateway-worker has identical DO bug (implements vs extends). Fixed all 55 this.state→this.ctx references. Added cloudflare:workers vitest mock. Updated compat_date. Created deploy-worker.yml CI/CD workflow. Peter committed WebSocket subscriptions (ef2df5f). All 300 tests passing across all packages.

## Metrics
- Tests: Client 193/193 ✅, AIM UI 43/43 ✅, TUI 12/12 ✅, Gateway 52/52 ✅ (fixed wave 4)
- Build: all components build, wrangler dry-run ✅
- Dropbox server: DOWN (fix ready + verified, deploy blocked on CF token perms)
- Gateway server: 404 on gateway.corpo.llc (fix ready, deploy blocked on CF token perms)
- Waves completed: 4

## Commits on fix/dropbox-outage-compat-date
1. `4af8c2a` — fix: update worker compat date and add /healthz endpoint
2. `4144e1e` — fix: use extends DurableObject base class for new_sqlite_classes compat
3. `4d6cd83` — fix: drain PTY output in pty-smoke tests to prevent event loop stall
4. `ef2df5f` — Migrate relay transport to websocket subscriptions (Peter)
5. `12c9afc` — fix: gateway DO extends DurableObject base class + deploy-worker CI workflow

## Peter's Standing Instructions
- Report to Pepper (chief of staff) via sessions_send(label="main")
- DO NOT push to main. Feature branches only.
- CF deploy: REQUIRES_APPROVAL (approved, needs working token with KV write perms)
