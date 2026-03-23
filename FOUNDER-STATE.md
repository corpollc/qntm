# Founder State — qntm
Updated: 2026-03-23T08:39:00Z
Wave: 29 (COMPLETE) — THE WG GETS A HOME

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 6 Status (Waves 29+) — ACTIVE
**Theme: "Standard or Product?" — Lean into the standard path**

Goal 1: WG specs used by both partners (1 PR/issue from non-qntm member) — IN PROGRESS (specs directory published)
Goal 2: Entity verification integration complete (partner ships code calling Corpo API) — IN PROGRESS (module shipped, partners notified)
Goal 3: One new WG member (ships compatible code) — NOT YET
Goal 4: QSP-1 spec ratified at v1.0 (3 implementations agree) — IN PROGRESS (v0.1.1 published)
Goal 5: Chairman strategic direction confirmed (standard vs product) — PENDING

## What We Accomplished Wave 29
- **WG SPECS DIRECTORY PUBLISHED.** `specs/` at repo root with README (members, principles, scope), QSP-1 envelope spec, DID resolution interface, entity verification interface, and test vectors. Posted links on A2A #1672. The WG has a home.
- **ENTITY VERIFICATION MODULE SHIPPED.** `entity.py` with `verify_entity()` and `verify_sender_entity()` — full chain from DID → key → sender → Corpo entity. 8 tests with mock HTTP server. 240 total pass (up from 232).
- **CORPO STAGING API CONFIRMED LIVE.** Chairman unblocked between waves — `api.corpo.llc/api/v1/entities/test-entity/verify` returns active entity. Both partners can now build entity integration.
- **haroldmalikfrimpong-ops BUILDING ENTITY INTEGRATION.** Confirmed API working, building `verify_agent_full(did)` chain into AgentID. Endorsed WG structure with full commitments.
- **22 TOTAL ENGAGEMENTS.** 2 new (WG specs + entity module on APS#5).
- **240 TESTS PASS** — python-dist, 0 failures (8 new entity tests)

## What We Accomplished Wave 28
- **WORKING GROUP ENDORSED.** haroldmalikfrimpong-ops proposed formalizing AgentID + APS + qntm as an Agent Identity Working Group on A2A #1672. We replied with code-first principles, scope table, and commitments. 20 total engagements.
- **DID FIELD SHIPPED.** Optional `did` parameter in `create_message()`, `extract_did()` helper, QSP-1 spec v0.1.1. Backwards compatible. 2 new tests, 232 total pass.
- **aeoess CONFIRMED E2E ROUNDTRIP.** Full crypto chain closed: APS encrypt → relay → echo bot decrypt → re-encrypt → relay → APS decrypt. Three identity systems in one conversation.
- **GITHUB TRAFFIC AT ALL-TIME HIGH.** 29 views/22 uniques + 1,011 clones/155 uniques on March 22.
- **CAMPAIGN 5 CLOSED.** Score: 3/5. Strong on integration + interop, weak on product adoption.

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🟢 P0 RESOLVED: PyPI publishing works!** v0.4.20 live.
2. **🟡 P1: MCP marketplace listing.** Materials ready. RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post"? **14th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready. HN would 10x reach.
4. **🟡 P1: Protocol vs Product strategic decision.** Campaign 6 assumes standard-track based on chairman's actions. Explicit confirmation requested.
5. **🟢 P1 RESOLVED: Corpo staging entity_id.** Chairman posted test entity API (Wave 28→29 gap). Both partners have access.
6. **🟡 P0: CF KV daily write limits.** Need $5/mo upgrade or DO storage migration.

## aeoess Engagement Timeline (Design Partner #1)
- Wave 10: Integration proposal posted (APS#5)
- Wave 19: First reply — detailed 5-layer integration stack proposed
- Wave 19-20: Vector exchange accepted, 3-step plan
- Wave 23: VECTOR EXCHANGE COMPLETE — 5/5 vectors, 8 tests, 1081 suite green
- Wave 24: RELAY TEST GREENLIT — asked for relay details, we provided everything
- Wave 25: FULL SPEC SHARED — integration plan posted (qntm-bridge.ts)
- Wave 26: RELAY ROUNDTRIP PROVEN — qntm-bridge.ts shipped (369 lines, 18/18 tests)
- Wave 27: DID INTEROP PROPOSED — 5-step cross-verification test sequence
- Wave 28: E2E ROUNDTRIP CONFIRMED. Asked for Corpo staging entity_id.
- **Wave 29: ENTITY API AVAILABLE.** Module shipped, integration path clear. Awaiting response.
- **Status:** STEP 7 — ENTITY FORMATION POC. Relay proven, DID proven, entity API live.

## haroldmalikfrimpong-ops Engagement Timeline (Design Partner #2)
- Wave 22: First reply — validated thesis, asked to connect with APS
- Wave 25: SHIPPED 809-LINE WORKING DEMO — first external code
- Wave 26: RELAY ROUNDTRIP PROVEN — connected to live relay
- Wave 27: PR MERGED + DID INTEROP SHIPPED — 10/10 checks, 82 tests
- Wave 28: WORKING GROUP PROPOSED on A2A #1672. We endorsed with code-first principles.
- **Wave 29: CONFIRMED ENTITY API + BUILDING INTEGRATION.** Building `verify_agent_full(did)` — full DID → certificate → entity chain. Endorsed WG structure.
- **Status:** BUILDING ENTITY INTEGRATION — WG proposer, PR merged, DID shipped, entity API confirmed

## Metrics
- Tests: 240 pass, 0 failures ✅ (up from 232)
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (stable)
- Active conversations (qntm-only): 2 (echo bot × 2)
- Design partners: **2 ACTIVE** (aeoess: E2E proven + entity pending, haroldmalikfrimpong-ops: PR merged + entity building)
- External users who've ever messaged: 0
- **External engagements: 22** — 3 REPLIES + WG + entity integration active
- **Direct integration proposals: 6** — 2 active with DID-level interop + WG + entity
- **External PRs: 1 merged** (haroldmalikfrimpong-ops, PR #3)
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues — BUT: 22 unique visitors on March 22 (ATH)
- **Campaigns completed:** 5 (Campaign 6 active — standard-track)
- **Total waves:** 29
- **WG specs: PUBLISHED** (QSP-1 v0.1.1, DID resolution v0.1, entity verification v0.1)
- **Entity verification: SHIPPED** (entity.py, 8 tests, Corpo staging API live)
- **Working Group: 3 FOUNDING MEMBERS** (qntm, APS, AgentID)
- **Corpo staging: LIVE** (test-entity verified by 2 partners)

## Ops Log
- Wave 1-22: [see wave logs for full history]
- Wave 23: **VECTOR EXCHANGE COMPLETE.** CAMPAIGN 5 WAVE 1.
- Wave 24: **THE CONVERSION REPLY.** aeoess asked for relay endpoint.
- Wave 25: **THE THREE-WAY CONVERGENCE.** First external code (809-line demo).
- Wave 26: **THE BRIDGE WORKS.** First cross-project E2E encrypted message exchange proven.
- Wave 27: **DID CONVERGENCE.** First external PR merged. DID interop emerged organically.
- Wave 28: **WORKING GROUP FORMATION.** WG proposed, endorsed, Campaign 5 closed (3/5).
- Wave 29: **THE WG GETS A HOME.** Specs directory published (QSP-1, DID resolution, entity verification). Entity module shipped (8 tests, 240 total). Corpo staging API live. haroldmalikfrimpong-ops building entity integration. Campaign 6 launched (standard-track). 22 total engagements.

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
- ~~Corpo staging entity_id needed~~ — RESOLVED Wave 29 (chairman posted test entity API)
