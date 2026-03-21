# Founder State — qntm
Updated: 2026-03-21T23:30:00Z
Wave: 5 (STRATEGY REVIEW)

## Phase: OPERATING

## Dropbox Relay Status
- Fix DEPLOYED by Peter. Awaiting ~00 UTC Cloudflare compat date reset.
- /healthz → ✅ (200)
- /v1/send → ❌ (1101 — should resolve after reset, ~1.5h from now)
- /v1/poll → ❌ (1101 — same)

## STRATEGY REVIEW — Wave 5

### CPO Report Received (CPO-REPORT-WAVE5.md)
- TTFM audit: Web UI 45-90s, CLI 60-120s, TUI 180-300s (all far above <10s target)
- #1 recommendation: Echo Bot + auto-joined demo conversation → <8s TTFM
- #2: `qntm quickstart` command → single CLI command for identity+convo+send
- #3: TTY-default `--human` output
- Gateway specs: GATE-NS1 (sample setups), GATE-NS2 (secret management UX), GATE-NS3 (Gemini smoke test), GATE-NS4 (document signing)
- Execution timeline: 22 days across 4 weeks

### CMO Report Received (CMO-REPORT-WAVE5.md)
- 5 target profiles: AI Agent Builders, DevOps/Platform Leads, DAO Treasury Operators, Security CTOs, AI Automation Freelancers
- 20 channel hypotheses evaluated
- Top 3 to test: HN Show HN, r/LocalLLaMA, Dev.to + Twitter
- Positioning: **"qntm is multi-sig for AI agent API calls"**
- Competitive landscape: YouAM and VectorGuard-Nano validated the market but lack gateway. A2A/MCP are complementary.
- Week 1 test plan: Mon prep, Tue HN, Wed Reddit, Thu Dev.to+Twitter, Fri measure
- Key insight: Nobody combines E2E encryption + agent-first + m-of-n approvals. Gateway is category-creating.

### Founder Strategic Decisions

**1. TTFM is existential. Echo bot is Wave 6 #1.**
The CPO's echo bot recommendation is exactly right. A visitor to chat.corpo.llc must have a working conversation in <10 seconds. This is the demo that proves qntm works.

**2. Gateway Gemini smoke test is #2.**
"Store a key, call Gemini, get a response with m-of-n approval" — that's the pitch for every investor meeting, HN post, and dev community demo. This must work flawlessly.

**3. Distribution starts AFTER relay is verified working.**
Can't launch to HN or Reddit with a broken relay. Relay verification at 00 UTC is the gate. Once confirmed, begin Week 1 distribution plan.

**4. Positioning: "Multi-sig for AI agent API calls."** Approved.
The CMO's positioning nails it. Crypto people understand multi-sig immediately. Agent builders understand the API key risk. This bridges both audiences.

## UPDATED Horizon Goals (10 waves)
1. TTFM <10 seconds on all clients — echo bot live, quickstart command works
2. Gateway demo: store key → call Gemini → response → all encrypted, m-of-n approved
3. Distribution Week 1 executed: HN + Reddit + Dev.to, measure results
4. Relay stable + monitored + auto-deploying
5. Document signing MVP working end-to-end

## UPDATED Campaign Goals (next 5 waves: 6-10)
1. Build + deploy echo bot with auto-joined demo conversation — MEASURABLE: chat.corpo.llc TTFM <10s
2. Gemini recipe + e2e smoke test script working — MEASURABLE: script exits 0 with real Gemini response
3. `qntm quickstart` + TTY-default human output — MEASURABLE: `uvx qntm quickstart` takes <15s
4. HN Show HN + r/LocalLLaMA posts live — MEASURABLE: >50 GH stars from launch week
5. Gateway sample server setups (local dev + hosted + Docker) — MEASURABLE: `bash scripts/gateway-local-dev.sh` works

## Wave 6 Top 5
1. ⏰ Verify relay works after 00 UTC reset — TEST: `qntm send` against inbox.qntm.corpo.llc
2. Begin echo bot implementation (CTO: design, build, deploy)
3. Add Gemini recipe to gateway starter catalog
4. `qntm quickstart` command spec + implementation
5. Prep GitHub README polish for distribution launch (badges, gif, "Why qntm?" section)

## Ops Log (last 5 waves)
- Wave 5 STRATEGY REVIEW: CPO + CMO reports received. Updated all goals per Chairman directive. Echo bot is #1 priority. Positioning: "multi-sig for AI agent API calls." Distribution starts after relay verification.
- Wave 4: Fixed gateway DO bug (same extends issue). Created deploy-worker.yml CI/CD. Peter committed WebSocket subscriptions (ef2df5f). 300 tests passing.
- Wave 3: Fixed TUI test failures (pty buffer drain fix). 12/12 TUI tests pass.
- Wave 2: Real root cause found (extends vs implements DO). Fixed. Deploy blocked.
- Wave 0: Bootstrap. Outage diagnosed. Fix built. Plan written.

## Commits on fix/dropbox-outage-compat-date
1. `4af8c2a` — update worker compat date + /healthz endpoint
2. `4144e1e` — extends DurableObject base class
3. `4d6cd83` — drain PTY output in pty-smoke tests
4. `ef2df5f` — WebSocket subscriptions (Peter)
5. `12c9afc` — gateway DO fix + deploy-worker CI workflow
6. `89341df` — state update wave 3

## Blockers
- Relay verification: awaiting 00 UTC compat date reset (~1.5h from now)
- Distribution: blocked on relay verification

## Metrics
- Tests: Client 193/193 ✅, AIM 43/43 ✅, TUI 12/12 ✅, Gateway 52/52 ✅ (300 total)
- Build: all clean, wrangler dry-run ✅
- Dropbox: deployed, awaiting verification
- Gateway: 404 on gateway.corpo.llc (needs investigation)
- Waves completed: 5

## Peter's Standing Instructions
- Report to Pepper (chief of staff) via sessions_send(label="main")
- DO NOT push to main. Feature branches only.
- CF deploy: REQUIRES_APPROVAL (approved, needs working token with KV write perms)
