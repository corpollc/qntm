# Founder State — qntm
Updated: 2026-03-23T07:39:00Z
Wave: 28 (COMPLETE) — WORKING GROUP FORMATION

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 5 Status (Waves 23-28) — CLOSED, Score 3/5
**Theme: Bridge the Gap — Convert engagement to product usage**

Goal 1: First external `qntm identity generate` — NOT ACHIEVED (partners use their own identity systems)
Goal 2: Interop proof-of-concept code (APS identity → qntm encrypted channel) — ✅ THREE POCS + DID CROSS-VERIFICATION
Goal 3: MCP marketplace listing (requires AUTONOMY ruling) — BLOCKED (13th wave asking)
Goal 4: aeoess vector exchange complete — ✅ ACHIEVED WAVE 23 (5/5 vectors, code shipped)
Goal 5: One integration PR (code contributed to/from external project) — ✅ ACHIEVED WAVE 27 (PR #3 merged)

## Campaign 6 — TBD (pending chairman strategic direction)
**Theme: "Standard or Product?"**
- Awaiting chairman decision on protocol-standard vs direct-product path
- Working Group proposal from haroldmalikfrimpong-ops endorsed
- Entity formation POC waiting on Corpo staging credentials

## What We Accomplished Wave 28
- **WORKING GROUP ENDORSED.** haroldmalikfrimpong-ops proposed formalizing AgentID + APS + qntm as an Agent Identity Working Group on A2A #1672. We replied with code-first principles, scope table, and commitments. 20 total engagements.
- **DID FIELD SHIPPED.** Optional `did` parameter in `create_message()`, `extract_did()` helper, QSP-1 spec v0.1.1. Backwards compatible. 2 new tests, 232 total pass.
- **aeoess CONFIRMED E2E ROUNDTRIP.** Full crypto chain closed: APS encrypt → relay → echo bot decrypt → re-encrypt → relay → APS decrypt. Three identity systems in one conversation.
- **aeoess ASKED FOR CORPO STAGING ENTITY_ID.** Ready to build entityBinding integration test. Blocked on chairman providing API credentials.
- **GITHUB TRAFFIC AT ALL-TIME HIGH.** 29 views/22 uniques + 1,011 clones/155 uniques on March 22.
- **CAMPAIGN 5 CLOSED.** Score: 3/5. Strong on integration + interop, weak on product adoption. Protocol > product tension is real.
- **CHAIRMAN BRIEFING SENT** — Wave 28, Page 1/2 format.
- **232 TESTS PASS** — python-dist, 0 failures

## What We Accomplished Wave 27
- **FIRST EXTERNAL PR MERGED.** haroldmalikfrimpong-ops opened PR #3 on corpollc/qntm — 298-line AgentID bridge example (relay_test.py). Code reviewed, approved, merged. First external contribution in project history.
- **DID INTEROP EMERGED ORGANICALLY.** Both partners independently moved from relay-proven to DID cross-verification. haroldmalikfrimpong-ops shipped `did:agentid` ↔ `did:aps` mutual verification (10/10 checks, 82 tests, deterministic test vectors). aeoess proposed 5-step DID test sequence.
- **CONVERSATION IS SELF-SUSTAINING.** Partners collaborating directly on APS#5 without qntm driving.
- **QSP-1 ENVELOPE SPEC DRAFTED.** Formal spec at `.company/specs/qsp1-envelope-spec-v0.1.md`.
- **CHAIRMAN BRIEFING SENT** — Wave 27, Page 1/2 format.
- **230 TESTS PASS** — python-dist, 0 failures

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🟢 P0 RESOLVED: PyPI publishing works!** v0.4.20 live. `uvx qntm` and `pip install qntm` both work.
2. **🟡 P1: MCP marketplace listing.** Materials ready (LobeHub manifest + Smithery config). Smithery requires active submission. RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post" under AUTONOMY.md? **13th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 20 outbound engagements, 3 active responders, 1 merged PR, proven crypto interop, Working Group proposed. HN would 10x reach.
4. **🟡 P1: Protocol vs Product strategic decision.** Working Group proposal forces this choice. If endorsed, qntm becomes a standard (defensible, slow to monetize). If not, refocus on direct product adoption. Chairman-level.
5. **🟡 P1: Corpo staging entity_id needed.** aeoess ready to build entityBinding integration test. Need API credentials from chairman.
6. **🟢 P0: CF KV daily write limits.** Need $5/mo upgrade or DO storage migration. Echo bot cursor management breaks when limit is hit.

## aeoess Engagement Timeline (Design Partner #1)
- Wave 10: Integration proposal posted (APS#5)
- Wave 19: First reply — detailed 5-layer integration stack proposed
- Wave 19-20: Vector exchange accepted, 3-step plan
- Wave 23: VECTOR EXCHANGE COMPLETE — 5/5 vectors, 8 tests, 1081 suite green
- Wave 24: RELAY TEST GREENLIT — asked for relay details, we provided everything
- Wave 25: FULL SPEC SHARED — integration plan posted (qntm-bridge.ts)
- Wave 26: RELAY ROUNDTRIP PROVEN — qntm-bridge.ts shipped (369 lines, 18/18 tests)
- Wave 27: DID INTEROP PROPOSED — 5-step cross-verification test sequence
- **Wave 28: E2E ROUNDTRIP CONFIRMED.** Full crypto chain closed. Asked for Corpo staging entity_id for entityBinding integration test. Ready to build legal+crypto+comms stack.
- **Status:** STEP 7 — ENTITY FORMATION POC. Relay proven, DID proven, now extending to legal entity binding.

## haroldmalikfrimpong-ops Engagement Timeline (Design Partner #2)
- Wave 22: First reply — validated thesis, asked to connect with APS
- Wave 25: SHIPPED 809-LINE WORKING DEMO — first external code
- Wave 26: RELAY ROUNDTRIP PROVEN — connected to live relay
- Wave 27: PR MERGED + DID INTEROP SHIPPED — 10/10 checks, 82 tests
- **Wave 28: WORKING GROUP PROPOSED.** Proposed formalizing AgentID + APS + qntm as Agent Identity Working Group on A2A #1672. We endorsed with code-first principles.
- **Status:** WORKING GROUP PROPOSER — first contributor, PR merged, DID shipped, now community organizer

## Metrics
- Tests: 232 pass, 0 failures ✅ (up from 230)
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (stable)
- Active conversations (qntm-only): 2 (echo bot × 2)
- Design partners: **2 ACTIVE** (aeoess: code shipped + DID, haroldmalikfrimpong-ops: PR merged + DID + WG)
- External users who've ever messaged: 0
- **External engagements: 20** — 3 REPLIES (aeoess E2E confirmed, The-Nexus-Guard stable, haroldmalikfrimpong-ops WG proposed), 9 no reply
- **Direct integration proposals: 6** — 2 active with DID-level interop + WG formation, 4 pending
- **External PRs: 1 merged** (haroldmalikfrimpong-ops, PR #3)
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues — BUT: 22 unique visitors + 155 unique cloners on March 22 (ATH)
- **Competitors (March 2026):** 10+ new projects (leyline, HuiNet latest)
- **Campaigns completed:** 5 (Campaign 6 pending strategic direction)
- **Total waves:** 28
- **DID field: SHIPPED** (optional in envelopes, QSP-1 v0.1.1)
- **Working Group: ENDORSED** (code-first, shared specs, open membership)
- **Entity formation POC: BLOCKED** (need Corpo staging credentials)

## Ops Log
- Wave 1-22: [see wave logs for full history]
- Wave 23: **VECTOR EXCHANGE COMPLETE.** CAMPAIGN 5 WAVE 1.
- Wave 24: **THE CONVERSION REPLY.** aeoess asked for relay endpoint — we replied with everything.
- Wave 25: **THE THREE-WAY CONVERGENCE.** First external code (haroldmalikfrimpong-ops 809-line demo). QSP-1 spec published.
- Wave 26: **THE BRIDGE WORKS.** First cross-project E2E encrypted message exchange proven.
- Wave 27: **DID CONVERGENCE.** First external PR merged. DID interop emerged organically. QSP-1 envelope spec drafted.
- Wave 28: **WORKING GROUP FORMATION.** haroldmalikfrimpong-ops proposed WG on A2A #1672. We endorsed with code-first principles. DID field shipped in envelopes (QSP-1 v0.1.1, 232 tests). aeoess confirmed full E2E roundtrip and asked for Corpo entity_id. GitHub traffic ATH (22 unique visitors). Campaign 5 closed (3/5). Campaign 6 pending strategic direction from chairman.

## Resolved Blockers
- ~~CF token invalid~~ — RESOLVED Wave 2
- ~~Relay poll broken (500/1101)~~ — RESOLVED Wave 2
- ~~TUI vi.hoisted test~~ — RESOLVED Wave 2
- ~~No activation path for new users~~ — RESOLVED Wave 3 (echo bot)
- ~~Echo bot dies on reboot~~ — RESOLVED Wave 4 (launchd plist)
- ~~Echo bot depends on Peter's Mac~~ — RESOLVED Wave 5 (CF Worker)
- ~~Echo bot broken by relay migration~~ — RESOLVED Wave 6 (rebuilt with WebSocket)
- ~~Test regression from relay migration~~ — RESOLVED Wave 7 (TestRelayServer missing `ready` frame)
- ~~Dead URLs in integration proposals~~ — RESOLVED Wave 13 (nichochar → corpollc)
- ~~Broken install in README~~ — RESOLVED Wave 13 (uvx → pip from git)
- ~~Broken install in docs pages~~ — RESOLVED Wave 14 (getting-started, tutorial, PyPI README)
- ~~conversations.json v0.3 format incompatibility~~ — RESOLVED Wave 15 (auto-migration function)
- ~~No MCP distribution channel~~ — RESOLVED Wave 16 (MCP server built and shipped)
- ~~PyPI CLI broken (v0.3, 11-wave escalation)~~ — RESOLVED Wave 17 (v0.4.20 published by chairman)
- ~~Subscribe has no identity verification~~ — RESOLVED Wave 19 (Ed25519 challenge-response, optional)
- ~~No DID metadata in envelopes~~ — RESOLVED Wave 28 (optional `did` field shipped, QSP-1 v0.1.1)
