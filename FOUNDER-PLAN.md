# qntm — Founder Strategic Plan
Created: 2026-03-21T20:45:00Z
Author: The Founder (autonomous CEO agent)

## Executive Summary

qntm is a well-architected encrypted messaging platform (QSP v1.1) with solid cryptographic foundations, three client types, and an innovative API Gateway for multi-party approval workflows. The core product is sound. However, the production dropbox relay is DOWN and operational infrastructure is critically lacking. This plan addresses the emergency first, then builds a sustainable operating model.

---

## 1. EMERGENCY: Dropbox Relay Outage

### Diagnosis

**Symptom:** `inbox.qntm.corpo.llc` returns Cloudflare error 1101 (uncaught Worker exception) on `/v1/send` and `/v1/poll` — the sequenced messaging endpoints that use Durable Objects. Legacy `/v1/drop` PUT/GET (KV-only) works fine. Root route returns proper 404.

**Root cause (high confidence):** The `ConversationSequencerDO` Durable Object is crashing in production. Evidence:
- Worker code runs **perfectly** on `wrangler dev` locally — both send and poll succeed
- Only DO-dependent endpoints crash; KV-only endpoints work
- The wrangler.toml uses `new_sqlite_classes` with `compatibility_date = "2024-02-08"` — this compat date is too old for SQLite-backed Durable Objects (which require `2024-04-01` or later)
- There is NO deploy workflow for the dropbox worker — deploys are manual-only
- The last worker code change (rate limit bump) may or may not have been deployed to production

**Fix required (2 steps):**
1. Update `compatibility_date` in `worker/wrangler.toml` to `"2025-09-01"` (or current date)
2. Run `wrangler deploy` from `worker/` with CLOUDFLARE_API_TOKEN

**⚠️ BLOCKER: Requires Peter to provide CLOUDFLARE_API_TOKEN for production deploy (REQUIRES_APPROVAL per AUTONOMY.md)**

### Impact
- ALL qntm messaging is down (CLI, web UI, channel plugin)
- corpo project's agent-to-agent communications blocked
- Gateway worker can't communicate (depends on dropbox relay)

---

## 2. Business & Technical Assessment

### What's Built (Strengths)
| Component | Status | Tests | Notes |
|-----------|--------|-------|-------|
| TS client library | ✅ Solid | 191 pass | QSP v1.1, clean architecture |
| Python CLI | ✅ Published | PyPI release | Primary agent runtime |
| Web UI (AIM) | ✅ Deployed | 43 pass | chat.corpo.llc via CF Pages |
| Terminal UI | ⚠️ 2 test failures | 10/12 pass | pty-smoke cursor bugs |
| Dropbox Worker | 🔴 DOWN | Works locally | Production DO crash |
| Gateway Worker | ❓ Unknown | 2 test files | Depends on dropbox relay |
| Channel plugin | ✅ Built | — | Claude Code MCP integration |
| Integration tests | ⚠️ Unknown | 7 test files | Can't run without relay |
| CI | ✅ Working | — | GitHub Actions, 3 test jobs |

### What's Missing (Critical Gaps)
1. **No monitoring** — zero uptime checks, no alerting, no health endpoints
2. **No dropbox deploy pipeline** — only manual `wrangler deploy`
3. **No health check endpoint** — worker has no `/healthz` or similar
4. **No error reporting** — no Sentry, no log aggregation
5. **No deployment tracking** — can't see what version is live
6. **No runbook** — no documented incident response process

### Technical Debt
- `compatibility_date: "2024-02-08"` is 2+ years old — should track quarterly
- 2 TUI test failures (pty-smoke cursor persistence)
- No Python tests running locally (missing pytest in system env)
- Rate limit is in-memory per isolate (not globally coordinated)

---

## 3. Organizational Design — Agent Types

### 3.1 DevOps Engineer 🔧
**Purpose:** Keep infrastructure healthy, prevent outages, deploy safely
**Responsibilities:**
- Monitor uptime of all services (dropbox relay, gateway, web UI)
- Run health checks every 5 minutes
- Alert on failures (via qntm message or WhatsApp escalation)
- Manage deployment pipelines
- Track compatibility dates and dependency updates
- Maintain runbooks

**Schedule:** Continuous (cron-based monitoring checks)

### 3.2 QA Engineer 🧪
**Purpose:** Maintain test quality and catch regressions
**Responsibilities:**
- Run full test suites across all components
- Fix broken tests (TUI pty-smoke failures)
- Expand integration test coverage
- Adversarial audit cycle: write tests → find bugs → fix → re-audit
- Cross-client interoperability testing

**Schedule:** On every code change + weekly full audit

### 3.3 Product Engineer 🛠️
**Purpose:** Build features and improve the product
**Responsibilities:**
- Feature development (protocol, clients, gateway)
- Bug fixes
- Documentation improvements
- Developer experience improvements

**Schedule:** Task-driven, spawned for specific work items

### 3.4 Security Auditor 🔒
**Purpose:** Validate cryptographic correctness and security properties
**Responsibilities:**
- Audit protocol implementation against QSP v1.1 spec
- Review new code for security issues
- Penetration testing of relay and gateway
- Verify threat model assumptions

**Schedule:** On significant code changes + monthly review

---

## 4. Immediate Action Plan (Next 48 Hours)

### Phase 0: Fix the Outage (NOW)
- [x] Diagnose root cause — Durable Object crash, likely compat date issue
- [ ] **ESCALATE TO PETER:** Need CLOUDFLARE_API_TOKEN + approval to deploy
- [ ] Prepare fix branch: update compatibility_date
- [ ] Add `/healthz` endpoint to worker for monitoring
- [ ] Deploy fixed worker
- [ ] Verify send/poll operations work

### Phase 1: Prevent Recurrence (After fix)
- [ ] Add health check endpoint to dropbox worker
- [ ] Create deploy workflow for dropbox worker (CI/CD)
- [ ] Set up cron-based monitoring (DevOps agent)
- [ ] Add deployment version tracking

### Phase 2: Stabilize (Week 1)
- [ ] Fix TUI test failures
- [ ] Run full integration test suite
- [ ] Verify gateway worker health
- [ ] Set up error reporting/alerting
- [ ] Document incident response runbook

### Phase 3: Grow (Week 2+)
- [ ] Security audit of protocol implementation
- [ ] Performance baseline (relay throughput, latency)
- [ ] Feature roadmap based on corpo project needs
- [ ] Developer documentation improvements

---

## 5. Key Metrics to Track
- **Uptime:** Dropbox relay, gateway, web UI (target: 99.9%)
- **Test pass rate:** All components (target: 100%)
- **Deploy frequency:** How often we ship (target: multiple times/week)
- **Mean time to recovery:** How fast we fix outages (target: < 1 hour)
- **Message throughput:** Messages/second through relay

---

## 6. Risk Register
| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Relay outage (current) | Critical | Happening now | Fix compat date + deploy |
| No monitoring | High | High | DevOps agent + health checks |
| Single point of failure (Peter for deploys) | High | Medium | CI/CD automation |
| Stale dependencies | Medium | Medium | Quarterly compat date bumps |
| Security vulnerability in crypto | Critical | Low | Regular audits |

---

## Appendix: Prepared Fix

```toml
# worker/wrangler.toml — change line 3
compatibility_date = "2025-09-01"  # was "2024-02-08"
```

```typescript
// worker/src/index.ts — add health check before the rate limiter
if (request.method === "GET" && path === "/healthz") {
    return jsonResponse({ status: "ok", ts: Date.now() }, 200);
}
```

Both changes are ready to apply. Just need CLOUDFLARE_API_TOKEN and deploy approval.
