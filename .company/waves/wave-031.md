# Wave 31 — Pipeline Refill + PyPI Surge Analysis
Started: 2026-03-23T10:39:00Z
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **PyPI downloads surged to 781/day on March 22.** Up from 26/day on March 21. Second 700+ spike in 3 days (823 on March 20). 669/781 downloads are `null` platform (likely CI/mirrors), 62 Darwin, 50 Linux. Source unknown — no web mentions found.
   - **GitHub traffic ATH maintained.** 29 views/22 uniques on March 22, 1011 clones/155 uniques. High clone count aligns with PyPI install-from-git pattern.
   - **The-Nexus-Guard AIP#5 is open, 0 comments.** Posted ~1 hour ago. Too early to evaluate. They were last active on A2A in wave 19.
   - **aeoess still building silently.** Last APS commit 5 hours ago (propagation sweep, 1122 tests). No new comment on APS#5 about entity module. Building, not talking.
   - **haroldmalikfrimpong-ops quiet since entity verification.** Last comment ~2 hours ago confirming bridge code. Specs PRs promised but not yet filed.
   - **Relay: OPERATIONAL.** healthz OK. 16 active conversations (stable, all internal).
   - **Tests: 248 pass (234 + 14 MCP skip), 0 failures.**

2. **Single biggest bottleneck?**
   - **New WG member acquisition** — same as wave 30. Pipeline has exactly 1 candidate (The-Nexus-Guard), invitation posted 1 hour ago. Need more candidates and more pipeline depth.

3. **Bottleneck category?**
   - Distribution / community growth.

4. **Evidence?**
   - 24 engagements across 30 waves → 3 responders. Last new outreach was 1 wave ago (AIP#5). Before that, 12 waves of silence. Pipeline is thin — one candidate.

5. **Highest-impact action?**
   - Deepen the The-Nexus-Guard invitation with something concrete — a test vector file or interop proof that makes it trivially easy for them to try. Lower the barrier from "read our specs" to "run this test."

6. **Customer conversation avoiding?**
   - Still zero standalone end-users. The WG members use qntm as infrastructure, not product. We haven't attempted to find someone who uses `uvx qntm` directly.

7. **Manual work that teaches faster?**
   - Manually trace the PyPI download surge. 781 downloads in one day, 669 from `null` platform. Is this a mirror bot? A CI system? A real spike in interest? Understanding this would clarify whether we have distribution or noise.

8. **Pretending is progress?**
   - More spec updates when only 3 people read them. Focus on getting a 4th reader (The-Nexus-Guard).

9. **Write down?**
   - PyPI download analysis. The-Nexus-Guard outreach strategy. Campaign 6 status.

10. **Escalation?**
    - MCP marketplace — deprioritizing. Standard-track direction makes this less urgent than WG growth.
    - Strategic direction — still pending. Recommend chairman confirms standard-track.
    - **NEW: PyPI surges.** Two 700+ days in a week. Unknown source. Not escalation-worthy but worth monitoring.

## Campaign 6 Status Check
| Goal | Status | Evidence |
|------|--------|----------|
| WG specs used by both partners (1 PR/issue from non-qntm member) | 🟡 IMMINENT | haroldmalikfrimpong promised PRs, hasn't filed yet |
| Entity verification integration complete | ✅ DONE | haroldmalikfrimpong shipped `verify_agent_full()` |
| One new WG member (ships compatible code) | 🟡 PIPELINE ACTIVE | AIP#5 opened, 0 replies yet (1 hour old) |
| QSP-1 spec ratified at v1.0 (3 implementations agree) | 🟡 IN PROGRESS | 2/3 converging, aeoess relay tests building |
| Chairman strategic direction confirmed | 🟡 PENDING | Actions signal standard track |

## Wave 31 Top 5 (force ranked)

1. **Build AIP interop test vectors** — create a test file that The-Nexus-Guard can run to verify AIP↔qntm compatibility. Lower the barrier.
2. **Investigate PyPI surge** — trace the 781 download spike. Mirror bot? Real interest? CI artifact?
3. **Check A2A for new WG candidates** — fresh scan of recent activity on identity/trust threads
4. **Monitor The-Nexus-Guard response** — if they reply on AIP#5, respond within this wave
5. **State/KPI/wave log updates + Chairman briefing prep**

## Execution Log

### #1 — AIP Interop Test Vectors ✅
- Built `specs/test-vectors/verify_aip_interop.py` — runnable 3-vector test, all pass
- Built `specs/test-vectors/aip-qntm-interop.json` — machine-readable test data
- Proves AIP Ed25519 identities derive X25519 keys compatible with qntm relay
- Both use PyNaCl (libsodium) — byte-for-byte identical derivation
- Posted follow-up comment on AIP#5 with script link + instructions
- Committed 414105e

### #2 — PyPI Surge Analysis ✅
- March 22: 781 downloads (669 `null` platform + 112 real)
- March 20: 823 downloads (730 `null` + 93 real)
- Real downloads by Python version: 3.11 (55), 3.10 (43), 3.12 (8), 3.14 (4), 3.13 (2)
- Baseline: 26/day on March 21
- **Conclusion:** ~85% of spike is `null` platform (mirrors/bots/CI). Real human downloads are ~100/day during spikes vs ~26 baseline. Still a 4x spike but not 30x. Unknown trigger.
- No web mentions of qntm found. Source remains mysterious.

### #3 — A2A Ecosystem Scan ✅
- Only 3 unique commenters on #1672: aeoess, haroldmalikfrimpong-ops, vessenes
- #1628 (trust.signals): The-Nexus-Guard active + douglasborthwick-crypto (InsumerAPI, on-chain — adjacent, not WG fit)
- No new identity/trust issues in last 3 days
- **Pipeline reality:** The-Nexus-Guard is the only viable new candidate right now

### #4 — Key Discovery: haroldmalikfrimpong-ops FORKED qntm ✅
- Fork created 2026-03-23T05:37:05Z (5 hours ago)
- Forking is the precursor to filing PRs
- This strongly signals Campaign 6 Goal 1 (non-qntm specs PR) is imminent
- **First fork ever on the repo!** (1 star, 1 fork)

### #5 — State/KPI updates ✅

## Metrics This Wave
- Tests: 248 total (234 pass + 14 MCP skip), 0 failures ✅ (stable)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (healthz OK, 16 active conversations)
- External engagements: **25** (1 new: AIP#5 follow-up with test vectors)
- Repo: 1 star, **1 fork** (NEW — haroldmalikfrimpong-ops)
- External PRs: 1 merged, 1 fork (PRs incoming)
- Design partners: 2 active + 1 WG candidate
- PyPI: 781/day (March 22), 1,642/week, 2,402/month
- Campaign 6: Goal 2 DONE, Goal 1 IMMINENT (fork = PRs incoming), Goal 3 PIPELINE ACTIVE
- New code: AIP interop test vectors (3/3 pass) + analysis
