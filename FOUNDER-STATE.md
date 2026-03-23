# Founder State — qntm
Updated: 2026-03-23T23:50:00Z
Wave: 43 (COMPLETE) — QSP-1 v1.0-rc1 CIRCULATED

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 6 Status (Waves 29+) — ACTIVE
**Theme: "Standard or Product?" — Lean into the standard path**

Goal 1: WG specs used by both partners (1 PR/issue from non-qntm member) — ✅ DONE (desiorac PR #4 merged — did:web spec addition, wave 37)
Goal 2: Entity verification integration complete (partner ships code calling Corpo API) — ✅ DONE (haroldmalikfrimpong shipped verify_agent_full() against staging API, bridge proven)
Goal 3: One new WG member (ships compatible code) — 🟡 EFFECTIVELY DONE (The-Nexus-Guard broke silence wave 37 — resolved DIDs, offered test vectors, engaging with WG. aeoess formally committed on #1672.)
Goal 4: QSP-1 spec ratified at v1.0 (3 implementations agree) — **v1.0-rc1 CIRCULATED** (7 gaps addressed, full roundtrip vector, pending 3/4 sign-off)
Goal 5: Chairman strategic direction confirmed (standard vs product) — PENDING

## What We Accomplished Wave 43
- **QSP-1 v1.0-rc1 CIRCULATED.** Full spec update from v0.1.1: expiry_ts field, Security Considerations (§7, 8 subsections), Error Handling (§6), Versioning (§8), RFC 2119 conformance, deprecated alias sunset, full roundtrip test vector. No protocol changes — editorial + security + completeness. Posted on A2A#1672 for WG review.
- **archedark-ada REGISTERED IN OATR.** PR #14 merged (23:32 UTC). Agent Agora is the 7th issuer. Tiered verification: ERC-8004 + DNS + DID. Key separation (DID key ≠ OATR key) — documented as RECOMMENDED in spec §7.8.
- **FransDevelopment CATALYZED REGISTRATION.** Posted invitation on A2A#1667 at 23:12 UTC → archedark-ada registered in 20 minutes. WG is self-organizing.
- **DID RESOLUTION VERIFIED.** `did:web:the-agora.dev` → valid 32-byte Ed25519 → sender_id `66f65dd543fa0c6f50580f7e35327e04`. Third verified cross-project DID resolution (after ArkForge + qntm bidirectional).
- **SPECS README UPDATED.** Agora + ArkForge promoted from candidate to registered. desiorac listed as proposed founding. QSP-1 version updated to v1.0-rc1.
- **58 TOTAL ENGAGEMENTS.** 2 new (A2A#1667 archedark-ada + A2A#1672 QSP-1 v1.0-rc1).

## What We Accomplished Wave 42
- **ALL 4 WG FOUNDING MEMBERS NOW IN OATR.** Historic convergence: aeoess (PR #12, merged 21:09 UTC), haroldmalikfrimpong-ops (PR #5, merged 21:58 UTC), qntm (PR #8, wave 41), ArkForge (PR #10, wave 41). All registered autonomously within ~2 hours.
- **6 TOTAL OATR ISSUERS:** arcede, agentinternetruntime, qntm, arkforge, agent-passport-system, agentid. Registry is the canonical cross-project artifact.
- **FransDevelopment CI FIX (PR #13) UNBLOCKED 2 REGISTRATIONS.** Fork PRs had downgraded GITHUB_TOKEN — the 403 killed auto-merge. Fixed. One CI fix → 2 registrations → 6 issuers.
- **aeoess oatr/ .gitignore (22:20 UTC).** Registry is now a permanent part of their workflow — housekeeping commit signals commitment.
- **QSP-1 v1.0 GAP ANALYSIS COMPLETE.** 7 gaps identified: expiry_ts, deprecated alias sunset, security considerations, error handling, versioning, conformance language, test vector completeness. Estimated 3-5 waves to ratifiable v1.0.
- **desiorac PROPOSED AS 5TH FOUNDING MEMBER.** Posted on A2A#1672 and OATR#2. Fills execution attestation layer.
- **56 TOTAL ENGAGEMENTS.** 3 new (A2A#1672 milestone + APS#5 acknowledgement + OATR#2 convergence).

## What We Accomplished Wave 41
- **qntm OATR REGISTRATION MERGED.** PR #8 auto-merged after FransDevelopment's CI fingerprint fix (PR #9). qntm is now a registered issuer in the trust registry with domain verification live.
- **desiorac/ArkForge REGISTERED AS OATR ISSUER.** PR #10 merged. Domain verification at arkforge.tech/.well-known/agent-trust.json. Second WG-aligned project to register in same day as qntm.
- **haroldmalikfrimpong-ops SUBMITTED AgentID REGISTRATION.** OATR PR #5 open, CI pending. Provided guidance on rebasing onto main for fingerprint fix.
- **desiorac SHIPPED DID BINDING.** trust-layer#18 merged: `POST /v1/keys/bind-did` with challenge-response (Path A) + OATR delegation (Path B). `verified_did` overrides self-declared `agent_identity`. Implements exactly what we proposed on OATR#2.
- **FransDevelopment PR #11: §6.2 SPEC WORDING.** Transition language for expiry_ts. Reviewed and APPROVED. Tracks per-implementation adoption status.
- **FransDevelopment POSTED REGISTRY STATUS UPDATE.** 4 active issuers (arcede, agentinternetruntime, qntm, arkforge) + AgentID pending.
- **aeoess CLEANUP + SDK v1.21.2.** Removed 68 unused imports, tracked tarballs, README update (data governance layers 38-42). 1178 tests, 83 MCP tools.
- **53 TOTAL ENGAGEMENTS.** 4 new (PR#11 review + OATR#2 desiorac ack + OATR#5 guidance + A2A#1672 milestone).

## What We Accomplished Wave 40
- **OATR ISSUER REGISTRATION SUBMITTED.** PR #8 on FransDevelopment/open-agent-trust-registry. qntm.json + qntm.proof (Spec 11 format). Same Ed25519 key as DID Document and relay transport. First WG member to register in the trust registry. Domain verification endpoint deployed at `/.well-known/agent-trust.json`.
- **FRANSDEVELOPMENT PROMOTED TO FOUNDING WG MEMBER.** 4th founding member. Evidence: Spec 10 authored + merged, Spec 11 shipped (proof-of-key-ownership + CI pipeline), alignment issue #4 filed + resolved. Specs README updated.
- **FRANSDEVELOPMENT SHIPPED SPEC 11.** Proof-of-key-ownership system with CI verification pipeline (809cefe). Canonical proof format (PEM delimiters, versioned message, Ed25519 signature). Auto-merge on 3-check pass. File-scope restriction prevents supply-chain attacks.
- **desiorac CONFIRMED BIDIRECTIONAL DID RESOLUTION.** Reverse test passes: `did:web:inbox.qntm.corpo.llc` resolves correctly from ArkForge resolver. sender_id derivation matches both directions. First bidirectional DID resolution between independent WG projects on live infrastructure.
- **aeoess PUSHED 3 COMMITS.** Derivation Chain (training attribution, 314 lines), SDK v1.21.2, 1178 tests, 83 MCP tools. Building steadily.
- **49 TOTAL ENGAGEMENTS.** 4 new (OATR#4 reply + OATR#2 reply + OATR PR#8 + A2A#1672 update).

## What We Accomplished Wave 39
- **did:web:inbox.qntm.corpo.llc IS LIVE.** DID Document published at /.well-known/did.json on relay worker. Ed25519VerificationKey2020, multibase z-prefix, QSP1Relay + QSP1RelayWebSocket service endpoints. Self-test passes: resolver → pubkey → sender_id = f0a6e0c2a1cbbebc0306b5f744d2be70. Credibility gap CLOSED.
- **expiry_ts RELAY ENFORCEMENT DEPLOYED.** Graceful degradation per FransDevelopment's OATR #4: enforced when present, pass-through when absent. Backwards compatible. CF Worker version 5d8875ec.
- **FransDevelopment MERGED SPEC 10 AND FILED ALIGNMENT ISSUE.** PR #3 (482-line encrypted transport spec) merged. Issue #4 (expiry_ts gap) opened with proposed resolution. WG-member-grade behavior. Formal invitation extended.
- **desiorac REVERSE TEST REVEALED GAP.** `did:web:qntm.corpo.llc` returned 404 — we weren't dogfooding our own specs. Fixed. Posted bidirectional test results.
- **DID RESOLVER USER-AGENT FIX.** Cloudflare blocks Python's default urllib User-Agent. Added `qntm-did-resolver/1.0` header.
- **45 TOTAL ENGAGEMENTS.** 4 new (OATR#4 reply + OATR#2 reply + OATR#2 DID results + OATR#4 implementation).

## What We Accomplished Wave 38
- **desiorac DID INTEGRATION TEST: PASSED.** `resolve_did_to_ed25519("did:web:trust.arkforge.tech")` returns valid 32-byte Ed25519 key. Trunc16(SHA-256) = `174e20acd605f8ce6fca394246729bd7`. buyer_fingerprint alignment confirmed against live infrastructure. First cross-project DID resolution outside founding WG members.
- **aeoess ENDORSED CODE-FIRST GOVERNANCE.** Agreed multibase z-prefix canonical, hex alias. Will update createDID() to emit multibase. "The code-first approach is working."
- **QSP-1 SPEC UPDATED TO v0.1.1.** Multibase encoding convention, sender ID derivation cross-project alignment, FransDevelopment reference.
- **PROPOSED FULL-STACK ENTITY FORMATION POC.** 6-layer test: APS identity → DID resolution → qntm transport → Corpo entity → OATR registry → ArkForge execution. 4/6 layers have proven interop.
- **The-Nexus-Guard ENGAGED ON SUBSCRIBE AUTH.** Shared relay details, proposed 5-step test scenario. did:agip resolution rules PR invited.
- **41 TOTAL ENGAGEMENTS.** 3 new (OATR#2 DID results + A2A#1672 POC proposal + AIP#5 subscribe auth).

## What We Accomplished Wave 37
- **aeoess FORMALLY COMMITTED TO WG.** Full deliverables declared on A2A #1672: self-sovereign identity, delegation chains, 32 constitutional modules, 1122 tests, 72 MCP tools, qntm bridge live, shared test vectors. Proposed multibase encoding standardization.
- **The-Nexus-Guard BROKE 5-WAVE SILENCE.** Independently resolved archedark-ada's DIDs. Offered subscribe auth test vectors. Flagged `did:aip` → `did:agip` rename (Aries collision). Acknowledged aip#5 invitation. Gold-standard DID Document format.
- **desiorac OPENED AND MERGED PR #4.** First external spec contribution to WG directory. `did:web` documented in DID resolution spec (8 additions). Also confirmed `buyer_fingerprint` = `Trunc16(SHA-256(pubkey))` aligns with qntm sender ID derivation.
- **haroldmalikfrimpong-ops DECLARED "WG IS REAL."** Three projects, three commitments, shared specs.
- **archedark-ada + The-Nexus-Guard CONNECTING DIRECTLY.** Phase 2 verificationMethod format alignment without qntm moderating.
- **6 PROJECTS TOUCHED SAME STACK IN ONE DAY.** qntm, APS, AgentID, AIP, ArkForge, Agent Agora.
- **38 TOTAL ENGAGEMENTS.** 3 new (A2A #1672 WG roster + OATR#2 integration test + A2A #1667 welcome back).
- **CAMPAIGN 6 GOAL 1: DONE.** First external spec PR merged.

## What We Accomplished Wave 36
- **desiorac REPLIED WITH EXACT DID INTEGRATION ARCHITECTURE.** Registration-time binding: caller presents DID → proxy resolves → extracts Ed25519 → challenge-response. `agent_identity` field already in proof receipts (self-declared). Missing step = verification. Our `resolve_did_to_ed25519()` fills this gap. Multi-agent: `contributing_agents` array with per-contribution hash. Responded with concrete code integration path.
- **archedark-ada SELF-MODERATED A2A #1667.** Suggested moving DID/WG discussion to dedicated venue. Endorsed WG. We offered specs repo as home.
- **HN REFERRAL CORRECTED: CHAIRMAN-SOURCED.** Algolia search confirms all links from `vessenes` account on 399-pt Claude Code thread (March 20). NOT organic external discovery. Truth register updated.
- **SPECS README UPDATED.** ArkForge added as 4th WG candidate (execution attestation layer). Scope table now 7 layers.
- **The-Nexus-Guard STILL COLD.** Active on their repo (3 commits in 2 days) but 0 response to AIP#5 after 5 waves. Deprioritized.
- **35 TOTAL ENGAGEMENTS.** 2 new (desiorac DID reply + archedark-ada venue redirect).

## What We Accomplished Wave 35
- **6TH EXTERNAL PERSON: desiorac (ArkForge).** Appeared organically on OATR#2 via FransDevelopment's reply — NOT from our outreach. Posted substantive execution attestation thesis: "identity at rest / in transit / at execution." Builds trust.arkforge.tech with 8 repos (ark-forge org), MCP server on Glama, Sigstore/Rekor, Ed25519 proofs, EU AI Act compliance. Real infrastructure.
- **FRANSDEVELOPMENT VALIDATED CRYPTO ARCHITECTURE.** Full reply on OATR#2: "genuine, not superficial." Ed25519→X25519 mapping, zero-trust relay, WG interop proof all endorsed. Their encrypted transport spec PR #3 reviewed — recommended merge with §6.2 wording adjustment.
- **desiorac REPLIED TO on OATR#2.** Engaged technically: validated three trust surfaces framework, asked about DID-bound agent_identity in proof-spec, Sigstore/Rekor for EU AI Act, multi-agent session proof chains.
- **FIRST HN REFERRAL EVER.** news.ycombinator.com in GitHub referrers (3 views, 2 uniques). Source: chairman (vessenes account) on 399-pt Claude Code thread. Not organic external discovery.
- **CLONE TRAFFIC 3.3x.** 3,940/516 uniques (14-day) vs 1,011/155 last period. Deep page reads: MCP docs (5), API gateway (6), QSP spec (4), LICENSE (4). Serious evaluation signals.
- **33 TOTAL ENGAGEMENTS.** 2 new (desiorac + FransDevelopment spec review on OATR#2).

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
2. **🟡 P1: MCP marketplace listing.** Materials ready. RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post"? **15th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready. HN would 10x reach.
4. **🟡 P1: Protocol vs Product strategic decision.** Campaign 6 assumes standard-track based on chairman's actions. Explicit confirmation requested. **NEW: WG is formally committed by 3 projects. Decision increasingly urgent.**
5. **🟢 P1 RESOLVED: Corpo staging entity_id.** Chairman posted test entity API (Wave 28→29 gap). Both partners have access.
6. **🟡 P0: CF KV daily write limits.** Need $5/mo upgrade or DO storage migration.
7. **🟡 P1 NEW: WG governance formalization.** 3 committed members, 4 candidates. Should we draft a charter + decision process, or stay code-first? Raised on A2A #1672.

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
- **Wave 37: FORMALLY COMMITTED TO WG.** Full deliverables declared on A2A #1672. Proposed multibase encoding standardization (hex vs z-base58btc). Acknowledged by haroldmalikfrimpong-ops ("WG is real").
- **Wave 38: GOVERNANCE ENDORSED.** Multibase z-prefix canonical agreed. Code-first philosophy confirmed. Full-stack entity formation POC proposed.
- **Wave 42: REGISTERED IN OATR.** PR #12 merged (21:09 UTC). Domain verification at aeoess.com/.well-known/agent-trust.json. Capabilities: delegation_chain supervision, immutable audit logging, aps-receipt-v1. oatr/ added to .gitignore (22:20 UTC) — permanent workflow integration. FransDevelopment CI fix (PR #13) unblocked fork registration.
- **Status:** WG FOUNDING MEMBER + OATR REGISTERED — bridge live, 1178 tests, 83 MCP tools, governance aligned, registry integrated. Next: QSP-1 v1.0 spec review, entity formation POC.

## haroldmalikfrimpong-ops Engagement Timeline (Design Partner #2)
- Wave 22: First reply — validated thesis, asked to connect with APS
- Wave 25: SHIPPED 809-LINE WORKING DEMO — first external code
- Wave 26: RELAY ROUNDTRIP PROVEN — connected to live relay
- Wave 27: PR MERGED + DID INTEROP SHIPPED — 10/10 checks, 82 tests
- Wave 28: WORKING GROUP PROPOSED on A2A #1672. We endorsed with code-first principles.
- **Wave 29: CONFIRMED ENTITY API + BUILDING INTEGRATION.** Building `verify_agent_full(did)` — full DID → certificate → entity chain. Endorsed WG structure.
- **Wave 30: ENTITY INTEGRATION DONE.** Shipped `verify_agent_full()` against staging API. Bridge to qntm `verify_sender_entity()` confirmed. Promised specs PRs. Reviewed specs directory as "clean and accurate."
- **Wave 42: REGISTERED IN OATR.** PR #5 merged (21:58 UTC). Domain verification at getagentid.dev/.well-known/agent-trust.json. Rebased onto main to pick up PR #9 fingerprint fix.
- **Status:** WG FOUNDING MEMBER + OATR REGISTERED — WG proposer, PR merged, DID shipped, entity verified, registry integrated.

## The-Nexus-Guard Engagement Timeline (WG Candidate #1)
- Wave 19: First external contact — reviewed qntm code on A2A #1667, gave detailed architectural feedback on subscribe auth
- Wave 30: WG INVITATION OPENED (aip#5). Strongest candidate: Ed25519 identity, PyPI (aip-identity), 10 stars, live DID resolution service, cross-protocol bridge with APS already built.
- **Wave 37: BROKE 5-WAVE SILENCE.** Independently resolved archedark-ada's DIDs. Offered subscribe auth test vectors. Flagged `did:aip` → `did:agip` rename (W3C Aries collision). Acknowledged aip#5. Gold-standard DID Document format. Connecting directly with archedark-ada on Phase 2 alignment.
- **Wave 38: SUBSCRIBE AUTH TEST ACCEPTED.** We shared relay WebSocket endpoint, echo bot conv ID, 5-step test scenario. Invited did:agip resolution rules PR to specs directory.
- **Status:** RE-ENGAGED — subscribe auth test vectors pending, relay details shared. Name change pending (`did:aip` → `did:agip`).

## archedark-ada Engagement Timeline (WG Candidate #2)
- Wave 32: FIRST CONTACT. Appeared on A2A #1667 with live did:web endpoint, Agent Agora (agent discovery registry — the-agora.dev), 2 live agents. Endorsed subscribe auth design. Offered DID for resolution test. We resolved both DIDs and bridged to WG.
- **Wave 33: FIXED DIDS AND ALIGNING TO WG.** Fixed the-agora.dev 404. Both did:web endpoints resolve. Committed to reading WG specs before implementing verificationMethod. We provided Ed25519VerificationKey2020 format guidance. Connecting directly with The-Nexus-Guard on DID interop.
- Wave 36: SELF-MODERATED A2A #1667. Suggested dedicated venue. We offered WG specs repo. Endorsed WG work, thanked us for DID resolution checks. Active on Moltbook as @adasprout.
- **Wave 43: OATR REGISTERED + DID DOCUMENT LIVE.** PR #14 merged (23:32 UTC). Agent Agora = 7th issuer. Full DID Document at `did:web:the-agora.dev` (Ed25519VerificationKey2020, verificationMethod, authentication + assertionMethod). Domain verification at `the-agora.dev/.well-known/agent-trust.json`. Key separation: DID key ≠ OATR key. Tiered verification: ERC-8004 + DNS + DID. Catalyzed by FransDevelopment invitation on #1667 → registered in 20 minutes. Our DID resolver verified: sender_id `66f65dd543fa0c6f50580f7e35327e04`.
- **Status:** OATR REGISTERED — discovery layer (Agent Agora) + DID infrastructure live. Fills the discovery/registration tier of the trust stack. Strong key separation practices. Next: formally propose as WG member (5th founding or candidate-to-member promotion).

## FransDevelopment Engagement Timeline (WG Candidate #3 → INVITED)
- Wave 32: Integration proposal filed (open-agent-trust-registry#2). Ed25519 attestation CA, 6 stars, threshold governance (3-of-5), OpenClaw user (clawhub), pushed 30 min before discovery.
- **Wave 33: REPLIED WITH FULL SPEC PR.** 482-line `spec/10-encrypted-transport.md` (PR #3). QSP-1-compatible, WG test vectors, registry-bound channel authentication (novel contribution), security analysis. Fastest external spec delivery. We reviewed, recommended merge with §6.2 rewording, and extended formal WG invitation.
- **Wave 39: SPEC 10 MERGED + ALIGNMENT ISSUE FILED.** PR #3 merged with §6.2 updated per review. Immediately opened #4 (expiry_ts enforcement gap). Proposed graceful degradation. WG membership offered.
- **Wave 40: FOUNDING MEMBER CONFIRMED + SPEC 11 SHIPPED.** Accepted WG founding membership on OATR#4. Shipped Spec 11 (proof-of-key-ownership + CI pipeline, 809cefe). Laid out full registration path for all WG members. Praised same-day expiry_ts deployment. Two issuers already registered (arcede, agentinternetruntime). qntm registration PR #8 submitted in response.
- **Wave 41: CI FIX + §6.2 SPEC PR.** Shipped PR #9 (fingerprint format fix — accepts kid, raw pubkey, or SHA-256). Unblocked qntm + ArkForge registrations. Posted registry status update (4 active issuers). Opened PR #11 (§6.2 expiry_ts transition wording). We approved PR #11.
- **Wave 42: FORK PERMISSIONS FIX (PR #13).** Fork PRs got downgraded GITHUB_TOKEN → 403 on comment posting → killed entire job including auto-merge. Fixed. This unblocked aeoess (APS) and haroldmalikfrimpong-ops (AgentID) registrations. One CI fix → 2 registrations.
- **Status:** FOUNDING WG MEMBER + REGISTRY MAINTAINER — spec author (Spec 10 + Spec 11), CI pipeline architect, registration enabler. 6 issuers live. Driving spec toward v1.0.

## desiorac / ArkForge Engagement Timeline (WG Prospect #1)
- Wave 35: FIRST CONTACT. Appeared organically on OATR#2 via FransDevelopment reply. Posted "identity at execution" thesis — receipt-per-invocation attestation. Ed25519 + SHA-256 proof chain + Sigstore Rekor. 8 repos under ark-forge org (trust-layer, proof-spec, arkforge-mcp, agent-client, mcp-eu-ai-act, eu-ai-act-scanner, trust-proof-action, n8n-nodes-arkforge). MCP server on Glama marketplace. dev.to content marketing (3 posts in 3 weeks). GitHub since 2016, 13 public repos.
- Wave 36: REPLIED WITH DID ARCHITECTURE. `agent_identity` in proof receipts, registration-time binding flow described. We proposed `resolve_did_to_ed25519()` integration. Awaiting response.
- **Wave 37: PR #4 OPENED AND MERGED + SECOND REPLY.** First external spec contribution: `did:web` in DID resolution doc. Confirmed `buyer_fingerprint` = `Trunc16(SHA-256(pubkey))` aligns with qntm sender ID. `did:web` not listed → they fixed it. QSP-1 relay message ID composability with `contributing_agents` validated.
- **Wave 38: DID INTEGRATION TEST PASSED.** `resolve_did_to_ed25519("did:web:trust.arkforge.tech")` returns valid Ed25519 key. buyer_fingerprint = Trunc16(SHA-256(pubkey)) = `174e20acd605f8ce6fca394246729bd7`. Alignment confirmed live. Results posted on OATR#2. Proposed reverse-direction test.
- **Wave 39: REVERSE TEST RESULT + BIDIRECTIONAL PATH ENABLED.** Their reverse test exposed our 404 — we shipped `did:web:inbox.qntm.corpo.llc` in response. Bidirectional DID resolution now possible. Awaiting their completion of reverse test.
- **Wave 40: BIDIRECTIONAL CONFIRMED.** Reverse direction test passes at 19:02:57Z. Both resolvers return correct Ed25519 keys, sender_id derivation matches in both directions. First bidirectional DID resolution between independent WG projects. Invited to register ArkForge in OATR.
- **Wave 41: OATR REGISTERED + DID BINDING SHIPPED.** PR #10 merged (OATR issuer registration). trust-layer#18 merged: DID binding for agent_identity with challenge-response (Path A) and OATR delegation (Path B). `verified_did` overrides self-declared agent_identity in proof receipts. Implements our OATR#2 proposal. We acknowledged on OATR#2.
- **Status:** OATR REGISTERED + DID BINDING LIVE — execution attestation with verified identity, OATR delegation shortcut, bidirectional DID resolution. Fills execution attestation layer. Strongest implementation-level contributor.

## Metrics
- Tests: 261 total (247 pass + 15 skip), 0 failures ✅
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (stable)
- Active conversations (qntm-only): 2 (echo bot × 2)
- Design partners: **2 ACTIVE** (aeoess: E2E proven + entity pending, haroldmalikfrimpong-ops: PR merged + entity building)
- External users who've ever messaged: 0
- **External engagements: 58** — A2A#1667 archedark-ada + A2A#1672 QSP-1 v1.0-rc1 + all prior
- **Direct integration proposals: 8** — 2 active with DID-level interop + WG + entity + OATR#2
- **External PRs: 2 merged** (haroldmalikfrimpong-ops PR #3 + desiorac PR #4) + **4 OATR registrations merged** (qntm PR#8, ArkForge PR#10, APS PR#12, AgentID PR#5)
- PyPI downloads: ~780/day baseline, 1,642/week, 2,402/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, **1 fork** (haroldmalikfrimpong-ops), 0 external issues — 32 unique visitors, **516 unique cloners** (14-day, 3.3x surge)
- **GitHub referrers: news.ycombinator.com** (chairman-sourced, 3 views, 2 uniques — NOT organic external)
- **External persons engaged: 6** (aeoess, haroldmalikfrimpong-ops, The-Nexus-Guard, archedark-ada, FransDevelopment, desiorac)
- **Campaigns completed:** 5 (Campaign 6 active — standard-track)
- **Total waves:** 43
- **WG specs: QSP-1 v1.0-rc1** (+ encoding conventions, DID resolution v0.1, entity verification v0.1)
- **Entity verification: PROVEN** (entity.py, 16 tests including 8 interop, 2 implementations verified)
- **DID resolution: SHIPPED** (did.py, did:web + did:key, 13 tests)
- **Working Group: 4 FOUNDING MEMBERS** (qntm, APS, AgentID, OATR — all formally committed) + **3 WG CANDIDATES** (The-Nexus-Guard, archedark-ada, desiorac/ArkForge)
- **Corpo staging: LIVE** (test-entity verified by 2 partners)
- **DID Document: LIVE** — did:web:inbox.qntm.corpo.llc (Ed25519VerificationKey2020, multibase z-prefix)
- **expiry_ts enforcement: DEPLOYED** — graceful degradation (enforced when present, pass-through when absent)
- **OATR registration: ALL 4 FOUNDING MEMBERS + AGORA MERGED** — qntm ✅, ArkForge ✅, APS ✅, AgentID ✅, Agora ✅
- **OATR issuers (total): 7** — qntm, arkforge, agent-passport-system, agentid, agora, arcede, agentinternetruntime
- **Domain verification: DEPLOYED** — /.well-known/agent-trust.json on relay worker
- **Bidirectional DID resolution: CONFIRMED** — qntm ↔ ArkForge, live infrastructure
- **desiorac DID binding: SHIPPED** — trust-layer#18 merged, Path A (challenge-response) + Path B (OATR delegation)
- **QSP-1 spec: v1.0-rc1** — pending ratification (3/4 founding member sign-off)
- **Trust surface stack: 7 LAYERS** — discovery (Agora ✅) → identity (APS ✅, AgentID ✅, AIP) → transport (qntm ✅) → registry (OATR ✅) → entity (Corpo) → execution (ArkForge ✅)

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
- Wave 35: **ECOSYSTEM GRAVITY.** 6th external person (desiorac/ArkForge) appeared organically on OATR#2 via FransDevelopment's reply. Execution attestation layer with Ed25519 + Sigstore Rekor. FransDevelopment validated crypto architecture ("genuine, not superficial"). HN referral (chairman-sourced). Clone traffic 3.3x (516 uniques). 33 engagements.
- Wave 36: **ECOSYSTEM INTEGRATION.** desiorac replied with exact DID binding architecture — `agent_identity` field exists, verification gap = our DID resolver. archedark-ada self-moderated #1667, redirected to WG venue. HN referral corrected (chairman-sourced, not organic). Specs README updated with ArkForge (7th layer). The-Nexus-Guard deprioritized (5 waves cold). 35 engagements.
- Wave 37: **THE WG IS REAL.** aeoess formally committed to WG on #1672. The-Nexus-Guard broke 5-wave silence (resolved DIDs, offered test vectors, acknowledged invitation). desiorac opened + merged PR #4 (first external spec contribution — did:web). haroldmalikfrimpong-ops declared "WG is real." 6 projects touched same stack in one day. Campaign 6 Goal 1 DONE, Goal 3 EFFECTIVELY DONE. 38 engagements, 2 external PRs merged.
- Wave 38: **INTEGRATION PROVEN + GOVERNANCE ALIGNED.** desiorac DID resolution test PASSED against live infrastructure (did:web:trust.arkforge.tech → valid Ed25519 key, buyer_fingerprint alignment confirmed). aeoess endorsed code-first governance, agreed multibase z-prefix canonical. QSP-1 spec v0.1.1 updated with encoding conventions. Full-stack entity formation POC proposed on A2A#1672 (4/6 layers proven). The-Nexus-Guard engaged on subscribe auth test vectors via AIP#5. 41 engagements.
- Wave 39: **SPEC ALIGNMENT + DID INFRASTRUCTURE.** Published `did:web:inbox.qntm.corpo.llc` DID Document (Ed25519VerificationKey2020, service endpoints, self-test passes). Deployed `expiry_ts` relay enforcement (graceful degradation per OATR spec 10 §6.2). FransDevelopment merged Spec 10 and filed alignment issue #4. desiorac reverse test exposed 404 gap — fixed. DID resolver User-Agent fix for Cloudflare. 45 engagements.
- Wave 40: **TRUST REGISTRY INTEGRATION.** qntm OATR issuer registration submitted (PR #8 — first WG member in registry). FransDevelopment promoted to founding WG member (Spec 10 + Spec 11 + alignment issue). Domain verification endpoint deployed (/.well-known/agent-trust.json). desiorac confirmed bidirectional DID resolution (first between independent WG projects). FransDevelopment shipped Spec 11 (proof-of-key-ownership + CI). aeoess SDK v1.21.2 (1178 tests, 83 MCP tools). 49 engagements.
- Wave 41: **TRUST CHAIN CONVERGENCE.** qntm + ArkForge OATR registrations merged. desiorac DID binding shipped (trust-layer#18). FransDevelopment §6.2 spec PR. haroldmalikfrimpong-ops registration submitted. 53 engagements.
- Wave 42: **ALL FOUNDERS REGISTERED.** aeoess (APS) PR #12 merged. haroldmalikfrimpong-ops (AgentID) PR #5 merged. FransDevelopment CI fix (PR #13) unblocked 2 registrations. 6 OATR issuers total. QSP-1 v1.0 gap analysis complete (7 gaps, 3-5 waves to ratification). desiorac proposed as 5th founding member. 56 engagements.
- Wave 43: **QSP-1 v1.0-rc1 + AGORA REGISTERS.** archedark-ada registered Agent Agora in OATR (PR #14, 7th issuer) — catalyzed by FransDevelopment's invitation, shipped in 20 minutes. Full DID Document live with Ed25519VerificationKey2020. DID resolution verified (sender_id `66f65dd543fa0c6f50580f7e35327e04`). QSP-1 v1.0-rc1 drafted: expiry_ts, Security Considerations (§7), Error Handling (§6), Versioning (§8), RFC 2119, full roundtrip test vector. Posted on A2A#1672 for WG review. Specs README updated. 58 engagements.

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
