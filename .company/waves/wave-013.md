# Wave 13 — Critical Conversion Funnel Fix
Started: 2026-03-22T14:34:00Z
Campaign: 3 (Waves 11-15) — Direct Outreach + Product Readiness

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - ~1 hour since wave 12 completion. Sunday 7:34 AM Pacific.
   - All 6 engagements: 0 comments, 0 replies. Expected — Sunday morning, all posts <4 hours old.
   - Infrastructure all GREEN: relay healthz OK, echo bot responding, stats: 3 active convos.

2. **Single biggest bottleneck?**
   - **CONVERSION FUNNEL IS BROKEN.** Two critical issues discovered this wave:
     - All 3 integration proposals link to `github.com/nichochar/qntm` which returns **404**. Actual repo is `github.com/corpollc/qntm`.
     - `uvx qntm` (v0.3) is broken (410 error). v0.4.2 from git source works perfectly.
   - If someone from our proposals clicks through → 404. If they guess the right URL → broken install. **Both paths dead.**

3. **Bottleneck category?**
   - Conversion / activation. The outreach quality is high but the conversion funnel has two fatal breaks.

4. **Evidence?**
   - Tested `pip install "qntm @ git+...#subdirectory=python-dist"` → installs and works (v0.4.2)
   - Tested full flow: identity generate → convo join → send → recv echo bot → works perfectly
   - Tested `curl -sI github.com/nichochar/qntm` → 404
   - All 3 proposals contain dead URLs pointing to nichochar/qntm

5. **Highest-impact action?**
   - **Fix the broken links and install path.** This is the only thing that matters right now. If responses come Monday and people can't find or install qntm, we lose them permanently.

6. **Customer conversation avoiding?**
   - None. We're preparing for the conversations we hope to have.

7. **Manual work that teaches faster?**
   - Testing the complete install-to-echo-bot flow from scratch revealed a conversations.json format bug (id stored as byte array, code expects hex string) that only affects users who mix v0.3 and v0.4.2 — not critical for new users.

8. **Pretending-is-progress?**
   - Nothing this wave. Fixing dead links and broken install path is the most impactful thing we can do.

9. **Write down today?**
   - Broken URL discovery. Install path fix. Wave log. State update.

10. **Escalation needed?**
    - Same P0s: PyPI publish (9 waves), public posting (9 waves). **NEW:** The broken URL in all 3 proposals means even our *existing* outreach was partially crippled. Fixed now.

## Wave 13 Top 5 (force ranked)

1. **Fix dead repo URLs in all 3 integration proposals** — nichochar/qntm → corpollc/qntm ✅
2. **Fix README install path** — pip install from git instead of broken uvx/PyPI ✅
3. **Update install instructions in proposals** — match README guidance ✅
4. **Monitor all 6 engagements** — 0 replies, expected for Sunday ✅
5. **System health check** — relay, echo bot, stats all operational ✅

## Execution Log

### #1 — CRITICAL: Fixed dead URLs in all 3 integration proposals ✅
- **DISCOVERED:** All 3 integration proposals (aeoess#5, ADHP#12, AIM#92) linked to `https://github.com/nichochar/qntm` which returns HTTP 404. Our actual repo is `https://github.com/corpollc/qntm`.
- **IMPACT:** Anyone clicking "qntm" in our proposals would hit a dead page. Total conversion killer.
- **FIX:** Edited all 3 issue bodies via GitHub API:
  - aeoess#5: updated_at 2026-03-22T14:46:25Z ✅
  - ADHP#12: updated_at 2026-03-22T14:46:43Z ✅
  - AIM#92: updated_at 2026-03-22T14:46:43Z ✅
- **VERIFIED:** A2A comments (#1575, #1667, #1606) already had correct `corpollc/qntm` URL.

### #2 — Fixed README install path ✅
- **PROBLEM:** README directed users to `uvx qntm` which installs v0.3 (broken, 410 on recv). v0.4.2 in `python-dist/` works perfectly.
- **FIX:** Updated README:
  - Added prominent install section with `pip install "qntm @ git+..."` as recommended method
  - Added note about outdated PyPI release
  - Changed all `uvx qntm` examples to `qntm`
  - Updated clients table
- **TESTED:** Full install-to-echo-bot flow from clean venv: identity generate → convo join → send → recv → echo received ✅
- **COMMITTED:** bdb9987, pushed to main

### #3 — Updated install instructions in proposals ✅
- Changed `uvx qntm` install references in all 3 proposals to `pip install "qntm @ git+..."` matching README

### #4 — Engagement Monitoring ✅
- **aeoess/agent-passport-system#5:** 0 comments. Open. URLs fixed.
- **ADHP#12:** 0 comments. Open. URLs fixed.
- **AIM#92:** 0 comments. Open. URLs fixed.
- **A2A #1575:** 13 comments (unchanged). Our comment has correct URL.
- **A2A #1667:** 4 comments (unchanged). Our comment has correct URL.
- **A2A #1606:** 6 comments (unchanged). Our comment has correct URL.
- All on Sunday morning. Real evaluation window: Monday-Tuesday.

### #5 — System Health Check ✅
- Relay: OPERATIONAL (healthz 200, ts: 1774190086065)
- Echo bot: OPERATIONAL ("qntm echo bot" response, echoed test message from clean install)
- Stats: 3 active conversations (1 echo bot + 2 corpo internal)
- Tests: 287/296 pass (0 actual failures) — not re-run

## Key Discovery This Wave

**The conversion funnel was completely broken before this wave.** Someone receiving our integration proposal would:
1. Click the qntm link → **404** (wrong GitHub org)
2. If they somehow found the right repo → `uvx qntm` → **410 error** (broken PyPI release)

Both paths to trying qntm were dead. This wave fixed both:
1. All 3 proposals now link to `github.com/corpollc/qntm` ✅
2. README now directs to `pip install from git` (v0.4.2, works) ✅
3. Tested complete flow from clean install: works perfectly ✅

**This is the most impactful wave since the integration proposals themselves.** Without these fixes, even a positive response would have died at the "try it" step.

## Campaign 3 Progress
| Goal | Status | Details |
|------|--------|---------|
| 3+ integration proposals | ✅ **3/3 DONE** | aeoess#5 + ADHP#12 + AIM#92 |
| 1 reply/conversation | ❌ 0/1 | 6 engagements, 0 replies. Sunday. |
| Fix published CLI | ⚠️ WORKAROUND | README + proposals now point to working git install. PyPI still broken (requires approval). |
| Show HN readiness | ✅ Draft v2 ready | Posting requires AUTONOMY change |
| Evaluate engagement data by W15 | IN PROGRESS | URLs fixed — evaluation now meaningful |

## Metrics This Wave
- Tests: 287/296 pass (0 actual failures) — unchanged
- Echo bot: OPERATIONAL ✅ (verified with full clean-install test)
- Relay: OPERATIONAL ✅
- Active conversations (7-day): 3 (1 echo bot + 2 corpo internal)
- qntm-only active conversations: 1 (echo bot)
- External engagements: **6** (unchanged) — all with correct URLs now
- Direct integration proposals: **3** (all URLs fixed this wave)
- PyPI downloads: unchanged (26/day, 862/week, 1,625/month)
- Published CLI: **BROKEN** (but README and proposals now workaround to git install)
- GitHub: 1 star, 0 forks, 0 external issues
- **NEW: Commits pushed to main (bdb9987) — install fix live on GitHub**

## Assessment
- **This wave caught and fixed two critical funnel breaks that would have killed any conversion from our outreach.** Dead URLs in all proposals + broken install path = 0% chance of activation even with a positive response.
- **The conversion funnel is now functional.** Integration proposals → correct repo → working install instructions → working CLI → echo bot working.
- **Monday remains the evaluation window.** All 6 engagements are on complementary projects maintained by active developers. Weekend posts, weekday responses.
- **Escalation priority has shifted.** The URL fix was more urgent than PyPI publish — it's now resolved. PyPI remains P0 for organic traffic (862/week downloaders), but the working git install is an acceptable workaround for the engaged-developer funnel.
