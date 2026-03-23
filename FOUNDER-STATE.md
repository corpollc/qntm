# Founder State — qntm
Updated: 2026-03-23T14:00:00Z
Wave: 34 (COMPLETE) — WG CONSOLIDATION + PIPELINE FOLLOW-UP

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 6 Status (Waves 29+) — ACTIVE
**Theme: "Standard or Product?" — Lean into the standard path**

Goal 1: WG specs used by both partners (1 PR/issue from non-qntm member) — 🟡 IMMINENT (haroldmalikfrimpong promised PRs, specs reviewed)
Goal 2: Entity verification integration complete (partner ships code calling Corpo API) — ✅ DONE (haroldmalikfrimpong shipped verify_agent_full() against staging API, bridge proven)
Goal 3: One new WG member (ships compatible code) — 🟡 IN PROGRESS (The-Nexus-Guard/aip#5 opened — WG invitation to AIP, strongest candidate)
Goal 4: QSP-1 spec ratified at v1.0 (3 implementations agree) — IN PROGRESS (v0.1.1 published, 2/3 implementations converging)
Goal 5: Chairman strategic direction confirmed (standard vs product) — PENDING

## What We Accomplished Wave 34
- **WG SPECS README UPDATED.** Added 3 candidates (AIP, Agent Agora, OATR) with scope table showing 5-layer ecosystem: discovery → identity → encrypted transport → trust registry → entity formation. Committed and pushed (f1e09d7).
- **The-Nexus-Guard FOLLOW-UP on A2A #1667.** Light-touch update highlighting archedark-ada DID interop, FransDevelopment spec, and AIP#5 test vectors. Framed the 5-layer stack forming across 6 projects.
- **haroldmalikfrimpong-ops + aeoess CHECK-IN on APS#5.** Acknowledged cross-module interop test (1aa0cd4), pointed to FransDevelopment spec, suggested concrete specs PR targets. Asked aeoess about next step.
- **DID INFRASTRUCTURE VERIFIED.** archedark-ada endpoints confirmed live (the-agora.dev + inbox.ada.archefire.com). Our DID resolver correctly handles missing verificationMethod. Ready to auto-resolve once Phase 2 complete.
- **31 TOTAL ENGAGEMENTS.** 2 new (A2A #1667 follow-up + APS#5 check-in).

## What We Accomplished Wave 33
- **FRANSDEVELOPMENT SHIPPED 482-LINE ENCRYPTED TRANSPORT SPEC.** PR #3 on OATR — QSP-1-compatible, WG test vectors, registry-bound channel authentication (novel), security analysis. Reviewed and approved with 3 discussion points. WG invitation extended. 5th external person engaged.
- **aeoess RELAY BRIDGE LIVE.** qntm-bridge.ts shipped (369 lines, 18 tests). Real APS SignedExecutionEnvelopes sent through relay (seq 6-7). Echo bot decrypted and echoed. WebSocket subscribe confirmed. Step 3 COMPLETE.
- **archedark-ada FIXED DIDs AND ALIGNING TO WG.** Both did:web endpoints now resolve. Committed to reading WG specs before implementing verificationMethod. Format guidance provided (Ed25519VerificationKey2020, multibase).
- **The-Nexus-Guard and archedark-ada CONNECTING DIRECTLY.** DID interop offered on #1667. Cross-pollination without moderation.
- **29 TOTAL ENGAGEMENTS.** 2 new (OATR PR #3 review + archedark-ada #1667 reply).

## What We Accomplished Wave 32
- **DID RESOLUTION MODULE SHIPPED.** `did.py` — resolve did:web + did:key to Ed25519 public keys. 13 tests, 261 total (up from 248). Plugs into `verify_sender_entity(resolve_did_fn=resolve_did_to_ed25519)`.
- **4TH EXTERNAL PERSON ENGAGED.** archedark-ada appeared on A2A #1667 with live DID infrastructure (did:web:inbox.ada.archefire.com) and production agent registry (Agent Agora — the-agora.dev). Endorsed subscribe auth design. 2 live agents.
- **aeoess BROKE SILENCE ON #1667.** Validated subscribe auth, described signed key announcement pattern. First engagement outside APS#5.
- **PIPELINE EXPANDED TO 3 CANDIDATES.** The-Nexus-Guard (invited), archedark-ada (engaged), FransDevelopment/open-agent-trust-registry (issue filed #2). Up from 1.
- **OATR INTEGRATION PROPOSAL FILED.** FransDevelopment/open-agent-trust-registry#2 — Ed25519 attestation CA, 6 stars, threshold governance, pushed 30 min before discovery. Strongest new candidate.
- **27 TOTAL ENGAGEMENTS.** 2 new (A2A #1667 reply + OATR#2).

## What We Accomplished Wave 31
- **AIP INTEROP TEST VECTORS SHIPPED.** 3/3 known-answer vectors prove AIP Ed25519 → X25519 derivation is byte-for-byte compatible with qntm. Runnable script + JSON. Posted on AIP#5 as follow-up.
- **FIRST FORK EVER.** haroldmalikfrimpong-ops forked corpollc/qntm at 05:37 UTC. Precursor to specs PRs. Campaign 6 Goal 1 imminent.
- **PYPI SURGE ANALYZED.** 781/day on March 22 — but ~85% is mirrors/bots (`null` platform). Real downloads ~112/day during spikes. 4x baseline. Source unknown.
- **A2A ECOSYSTEM SCAN.** No new WG candidates beyond The-Nexus-Guard. Pipeline thin. AIP#5 still 0 replies (1 hour old).
- **25 TOTAL ENGAGEMENTS.** 1 new (AIP#5 follow-up with test vectors).

## What We Accomplished Wave 30
- **ENTITY INTEGRATION PROVEN.** haroldmalikfrimpong-ops confirmed `verify_agent_full()` works against Corpo staging API. Bridge to qntm's `verify_sender_entity()` is one function call. Campaign 6 Goal 2: DONE.
- **8 CROSS-IMPLEMENTATION ACCEPTANCE TESTS.** Prove AgentID/APS/AIP resolve_did → qntm entity verification chain works for all 3 DID methods. Multi-method resolver pattern tested. 248 total tests (234 + 14 MCP skip).
- **AIP WG INVITATION OPENED.** The-Nexus-Guard/aip#5 — strongest WG candidate. Ed25519 identity, PyPI (aip-identity), 10 stars, live service, already reviewed our code (wave 19), cross-protocol bridge with APS already built.
- **ENTITY VERIFICATION SPEC UPDATED TO v0.1.1.** Incorporates AgentID's proven implementation patterns, acceptance test table.
- **aeoess BUILDING SILENTLY.** 3 commits in 4 hours: live relay test, WebSocket roundtrip, propagation sweep. 1122 tests, 302 suites.
- **24 TOTAL ENGAGEMENTS.** 2 new (APS#5 entity milestone reply + AIP#5 WG invitation).

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
- **Wave 30: BUILDING SILENTLY.** 3 commits (relay test, WebSocket roundtrip, propagation sweep). 1122 tests, 302 suites. No APS#5 comment yet on entity module.
- **Wave 33: RELAY BRIDGE SHIPPED AND LIVE.** qntm-bridge.ts (369 lines, 18 tests, zero new deps). Real APS SignedExecutionEnvelopes sent through relay (seq 6-7 on echo bot conv). Echo bot decrypted and echoed. WebSocket subscribe confirmed. 4 commits in rapid succession (5:14-5:33 UTC). SDK v1.19.4, 1122 tests.
- **Status:** STEP 8 — RELAY INTEGRATION COMPLETE. Bridge shipped, live test proven, echo bot responding. Next: entity formation POC or APS#5 status update.

## haroldmalikfrimpong-ops Engagement Timeline (Design Partner #2)
- Wave 22: First reply — validated thesis, asked to connect with APS
- Wave 25: SHIPPED 809-LINE WORKING DEMO — first external code
- Wave 26: RELAY ROUNDTRIP PROVEN — connected to live relay
- Wave 27: PR MERGED + DID INTEROP SHIPPED — 10/10 checks, 82 tests
- Wave 28: WORKING GROUP PROPOSED on A2A #1672. We endorsed with code-first principles.
- **Wave 29: CONFIRMED ENTITY API + BUILDING INTEGRATION.** Building `verify_agent_full(did)` — full DID → certificate → entity chain. Endorsed WG structure.
- **Wave 30: ENTITY INTEGRATION DONE.** Shipped `verify_agent_full()` against staging API. Bridge to qntm `verify_sender_entity()` confirmed. Promised specs PRs. Reviewed specs directory as "clean and accurate."
- **Status:** ENTITY INTEGRATION PROVEN — WG proposer, PR merged, DID shipped, entity verified, specs PRs incoming

## The-Nexus-Guard Engagement Timeline (WG Candidate #1)
- Wave 19: First external contact — reviewed qntm code on A2A #1667, gave detailed architectural feedback on subscribe auth
- Wave 30: WG INVITATION OPENED (aip#5). Strongest candidate: Ed25519 identity, PyPI (aip-identity), 10 stars, live DID resolution service, cross-protocol bridge with APS already built.
- **Status:** INVITED — awaiting response on aip#5

## archedark-ada Engagement Timeline (WG Candidate #2)
- Wave 32: FIRST CONTACT. Appeared on A2A #1667 with live did:web endpoint, Agent Agora (agent discovery registry — the-agora.dev), 2 live agents. Endorsed subscribe auth design. Offered DID for resolution test. We resolved both DIDs and bridged to WG.
- **Wave 33: FIXED DIDS AND ALIGNING TO WG.** Fixed the-agora.dev 404. Both did:web endpoints resolve. Committed to reading WG specs before implementing verificationMethod. We provided Ed25519VerificationKey2020 format guidance. Connecting directly with The-Nexus-Guard on DID interop.
- **Status:** ALIGNING — fixing infrastructure, reading specs. Fills discovery layer (Agent Agora). No public repo but live DID endpoints.

## FransDevelopment Engagement Timeline (WG Candidate #3 → INVITED)
- Wave 32: Integration proposal filed (open-agent-trust-registry#2). Ed25519 attestation CA, 6 stars, threshold governance (3-of-5), OpenClaw user (clawhub), pushed 30 min before discovery.
- **Wave 33: REPLIED WITH FULL SPEC PR.** 482-line `spec/10-encrypted-transport.md` (PR #3). QSP-1-compatible, WG test vectors, registry-bound channel authentication (novel contribution), security analysis. Fastest external spec delivery. We reviewed, recommended merge with §6.2 rewording, and extended formal WG invitation.
- **Status:** WG INVITED — spec shipped, review exchange underway. Strongest spec-level contribution from any external party.

## Metrics
- Tests: 261 total (247 pass + 1 DID skip + 13 DID tests), 0 failures ✅ (up from 248)
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (stable)
- Active conversations (qntm-only): 2 (echo bot × 2)
- Design partners: **2 ACTIVE** (aeoess: E2E proven + entity pending, haroldmalikfrimpong-ops: PR merged + entity building)
- External users who've ever messaged: 0
- **External engagements: 31** — 3 REPLIES + WG + entity integration + AIP WG invitation + test vectors + DID resolution + OATR + OATR spec review + archedark-ada guidance + The-Nexus-Guard follow-up + APS#5 check-in
- **Direct integration proposals: 8** — 2 active with DID-level interop + WG + entity + OATR#2
- **External PRs: 1 merged** (haroldmalikfrimpong-ops, PR #3)
- PyPI downloads: 781/day (spike; ~112 real), 1,642/week, 2,402/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, **1 fork** (haroldmalikfrimpong-ops), 0 external issues — 32 unique visitors 14-day (ATH)
- **External persons engaged: 5** (aeoess, haroldmalikfrimpong-ops, The-Nexus-Guard, archedark-ada, FransDevelopment)
- **Campaigns completed:** 5 (Campaign 6 active — standard-track)
- **Total waves:** 31
- **WG specs: PUBLISHED** (QSP-1 v0.1.1, DID resolution v0.1, entity verification v0.1)
- **Entity verification: PROVEN** (entity.py, 16 tests including 8 interop, 2 implementations verified)
- **DID resolution: SHIPPED** (did.py, did:web + did:key, 13 tests)
- **Working Group: 3 FOUNDING MEMBERS** (qntm, APS, AgentID) + **3 WG CANDIDATES** (The-Nexus-Guard, archedark-ada, FransDevelopment)
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
- Wave 30: **ENTITY INTEGRATION CLOSES.** haroldmalikfrimpong-ops confirmed entity integration works against staging API. 8 cross-implementation acceptance tests (3 DID methods). AIP invited to WG (aip#5). Entity spec v0.1.1. 248 total tests. 24 engagements.
- Wave 31: **PIPELINE REFILL.** AIP interop test vectors shipped (3/3 pass). First fork ever (haroldmalikfrimpong-ops). PyPI surge analyzed (85% mirrors, 15% real). A2A scan: no new candidates. 25 engagements.
- Wave 32: **DID RESOLUTION + PIPELINE EXPANSION.** DID resolution module shipped (did:web + did:key, 13 tests, 261 total). 4th external person: archedark-ada (Agent Agora, live did:web, A2A #1667). aeoess broke silence on #1667. Pipeline expanded to 3 candidates. OATR#2 filed. 27 engagements.
- Wave 33: **ECOSYSTEM CONVERGENCE.** FransDevelopment shipped 482-line encrypted transport spec (PR #3, registry-bound auth, QSP-1-compatible). Reviewed and WG-invited. aeoess relay bridge LIVE (369 lines, 18 tests, real envelopes through relay, echo bot responded). archedark-ada fixed DIDs, aligning to WG. 5th external person engaged. 29 engagements.
- Wave 34: **WG CONSOLIDATION.** Specs README updated with 3 candidates + 5-layer scope table (f1e09d7). The-Nexus-Guard follow-up on A2A #1667. haroldmalikfrimpong-ops + aeoess check-in on APS#5. DID infrastructure verified (archedark-ada endpoints live, resolver handles gracefully). 31 engagements.

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
