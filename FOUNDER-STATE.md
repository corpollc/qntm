# Founder State — qntm
Updated: 2026-03-22T00:45:00Z
Wave: 7

## Phase: OPERATING

## BLOCKERS — NEED PETER ACTION
1. **Cloudflare API token missing KV write permissions** — Both the local token (`~/.env` CLOUDFLARE_API_KEY) and the GitHub Actions secret (`CLOUDFLARE_API_TOKEN`) lack KV write perms. Wrangler deploy of `qntm-dropbox` worker fails with error 10023: "kv bindings require kv write perms". Peter needs to regenerate or update the CF API token to include Workers KV Storage:Edit permission, then update both `~/.env` and the GitHub secret. The gateway worker deploys fine (no KV).

## Relay Status
- URL: `inbox.qntm.corpo.llc` (NOT dropbox.corpo.llc — that DNS doesn't exist)
- /healthz → ✅ 200
- /v1/send → ✅ 201 (DO publish works, seq numbers assigned)
- /v1/poll → ❌ 1101 (unhandled exception — KV list/read fails at runtime)
- Root cause: Likely the same CF permissions issue affecting KV at runtime, or stale deploy. Cannot redeploy fix due to token permissions.
- Added top-level error handler (commit e1cc2a5) to surface actual errors — but can't deploy it.

## Gateway Status
- ✅ HEALTHY — gateway.corpo.llc/health returns 200
- CI deploys work fine (no KV binding)

## Wave 7 — Current
### Top 5 (force ranked)
1. **Fix relay deploy** → BLOCKED on Peter (CF token perms)
2. **Gemini recipe smoke test** → gateway is live, can test
3. **`qntm quickstart` command** → code work, no deploy needed
4. **Echo bot build** → BLOCKED until relay poll works
5. **README/docs polish** → can do anytime

### Actions Taken This Wave
- Verified relay at correct URL (inbox.qntm.corpo.llc)
- Discovered healthz works but poll returns 1101 (KV runtime failure)
- Confirmed send (DO path) works — returns seq:1 on test message
- Diagnosed root cause: CF API token lacks KV write perms
- Confirmed both local and CI tokens have same issue (error 10023)
- Added try/catch error handler to worker (commit e1cc2a5, pushed to main)
- CI deploy failed same way — confirming token is the blocker
- All tests passing: 288 total (193 client + 52 gateway + 43 AIM)
- Merged main into feat/wave6-echo-bot-prep branch

## Branch: feat/wave6-echo-bot-prep
- `76eaa68` — feat: add Gemini, OpenAI, Anthropic, GitHub API recipes
- `c851e06` — polish README: multi-sig positioning, recipe catalog

## Branch: main
- `e1cc2a5` — fix: add top-level error handler to relay worker for 1101 diagnostics
- `b5c29f8` — Add echo bot spec, CPO and CMO wave 5 reports

## Key Specs & Reports
- ECHO-BOT-SPEC.md — CTO's technical design for the echo bot
- CPO-REPORT-WAVE5.md — TTFM audit + 4 gateway next-step specs
- CMO-REPORT-WAVE5.md — 5 target profiles, 20 channels, top 3, competitive landscape

## Horizon Goals (10 waves)
1. TTFM <10 seconds on all clients — echo bot live, quickstart command works
2. Gateway demo: store key → call Gemini → response → all encrypted, m-of-n approved
3. Distribution Week 1 executed: HN + Reddit + Dev.to, measure results
4. Relay stable + monitored + auto-deploying
5. Document signing MVP working end-to-end

## Campaign Goals (waves 6-10)
1. Build + deploy echo bot — MEASURABLE: chat.corpo.llc TTFM <10s — BLOCKED on relay
2. Gemini recipe + e2e smoke test — MEASURABLE: script exits 0 with real Gemini response
3. `qntm quickstart` + TTY-default human output — MEASURABLE: <15s to first message
4. HN + Reddit + Dev.to launch — MEASURABLE: >50 GH stars from launch week
5. Gateway sample server setups — MEASURABLE: `bash scripts/gateway-local-dev.sh` works

## Ops Log (last 5 waves)
- Wave 7: Relay healthz ✅ but poll 1101. Root cause: CF token lacks KV perms. Deploy blocked. 288 tests passing.
- Wave 6: Gateway deployed + healthy. Echo bot spec done. API recipes added. README polished.
- Wave 5 STRATEGY: CPO + CMO reports. Echo bot #1. "Multi-sig for AI agent API calls" positioning.
- Wave 4: Gateway DO fix. Deploy-worker CI. 300 tests passing.
- Wave 3: TUI test fix (pty buffer drain). 12/12 TUI tests.

## Metrics
- Tests: Client 193/193 ✅, AIM 43/43 ✅, Gateway 52/52 ✅ (288 total)
- Relay: healthz ✅, send ✅, poll ❌ (1101)
- Gateway: ✅ healthy
- Waves completed: 7
- CI deploys: gateway ✅, relay ❌ (token perms)

## NOTE: Accidental commit to main
Wave 5 specs (echo bot, CPO, CMO reports) were committed to main instead of feature branch. Docs-only, not code. Noted for future prevention — always verify branch before commit.
