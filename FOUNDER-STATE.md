# Founder State — qntm
Updated: 2026-03-23T03:50:00Z
Wave: 24 (COMPLETE) — THE CONVERSION REPLY

## Horizon Goals (revised wave 10)
1. 1 external reply/conversation — ✅ ACHIEVED WAVE 19 (aeoess on #5, The-Nexus-Guard on A2A #1667)
2. 1 design partner in discussion — ✅ EFFECTIVELY ACHIEVED (aeoess: 6+ comments across 4 threads, vector exchange accepted, Peter engaged directly)
3. PyPI fixed and published — ✅ DONE (v0.4.20 live, P0 resolved wave 17)
4. Direct outreach to 3+ complementary projects — ✅ DONE → EXPANDED to 6/6 (3 new in wave 18)
5. Show HN approval sought — BLOCKED (draft v2 ready, posting DENIED)
6. MCP distribution channel — ✅ MCP server shipped (dd8c3df), marketplace listing BLOCKED (AUTONOMY ruling needed)

## Campaign 4 Status (Waves 16-22) — CLOSED, Score 3.5/5
**Theme: Convert or Pivot**

Wave 16: ✅ MCP server built and shipped. New distribution channel.
Wave 17: ✅ PyPI P0 resolved. Install path clean. MCP marketplace materials ready. NanoClaw integration discovered.
Wave 18: ✅ 3 new integration proposals (nono, clawdstrike, mcp-gateway). Joined All-Hands. NanoClaw live test confirmed. Clone spike analyzed.
Wave 19: ✅ **FIRST EXTERNAL REPLIES.** aeoess + The-Nexus-Guard engaged. Subscribe auth shipped. Interop test vectors created. Responded to both.
Wave 20: ✅ **VECTOR EXCHANGE ACTIVATED.** aeoess explicitly accepted 3-step interop plan. Responded with vectors + compatibility analysis. APS source code reviewed — genuine complement, not competitor. Peter engaging directly with aeoess on Corpo.
Wave 21: ✅ **EXPANDED ENGAGEMENT.** Commented on A2A #1672 (agent identity verification). Competitive analysis: leyline launched same day with same thesis (P2P, Ed25519, XChaCha20). Relay stats surging (10→16). All threads monitored.
Wave 22: ✅ **CAMPAIGN 4 CLOSED.** haroldmalikfrimpong-ops replied on #1672 (3rd responder). Facilitated APS connection. Campaign assessment written. Score: 3.5/5.

## Campaign 5 Status (Waves 23-28)
**Theme: Bridge the Gap — Convert engagement to product usage**

Goal 1: First external `qntm identity generate`
Goal 2: Interop proof-of-concept code (APS identity → qntm encrypted channel) — ✅ BRIDGE SCRIPT BUILT (wave 23)
Goal 3: MCP marketplace listing (requires AUTONOMY ruling)
Goal 4: aeoess vector exchange complete — ✅ ACHIEVED WAVE 23 (5/5 vectors, code shipped)
Goal 5: One integration PR (code contributed to/from external project)

Wave 23: ✅ **VECTOR EXCHANGE COMPLETE.** aeoess shipped `deriveEncryptionKeypair()` — 5/5 vectors pass, 8 tests, 1081 suite green. XChaCha20-Poly1305 alignment confirmed (we already use it!). APS→qntm bridge PoC built. Reply posted proposing Step 3 (actual relay test). aeoess also engaged on Corpo entity binding (A2A#1575).

## ⚠️ BLOCKERS — NEEDS CHAIRMAN
1. **🟢 P0 RESOLVED: PyPI publishing works!** v0.4.20 live. `uvx qntm` and `pip install qntm` both work.
2. **🟡 P1: MCP marketplace listing.** Materials ready (LobeHub manifest + Smithery config). Smithery requires active submission (no auto-indexing). RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post" under AUTONOMY.md? **9th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 13 outbound engagements, 3 active responders, proven crypto interop. HN would 10x reach.
4. **🟢 P1: Distribution producing conversion signal.** aeoess asked for relay details and is building TypeScript integration. First potential product user after 24 waves.

## What We Accomplished Wave 24
- **THE CONVERSION REPLY.** aeoess asked for relay endpoint + echo bot conversation ID. We replied with EVERYTHING: relay URL, WebSocket subscribe format, HTTP send format, CBOR envelope structure, authenticated subscribe flow, TypeScript quick-start code, echo bot behavior, suggested relay test flow. This is the most comprehensive single reply in the project's history.
- **aeoess REPLIED TWICE.** Accepted layered envelope design (APS wraps qntm inner). Explicitly said "yes, let's do the relay test." Shipped 2 more features (entityBinding + identityBoundary in d253d8f). APS: 1090 tests, 290 suites, 0 failures.
- **haroldmalikfrimpong-ops DEEPENING.** 2nd reply on A2A #1672 — endorsed pluggable identity verification, committed to spec AgentID→subscribe-auth flow.
- **THREE-WAY ALIGNMENT FORMING.** aeoess (APS) + haroldmalikfrimpong-ops (AgentID) + qntm. Both partners independently validated the same architecture.
- **RELAY API FULLY DOCUMENTED FOR EXTERNAL BUILDER** — first time.
- **CHAIRMAN BRIEFING SENT** — Wave 24, Page 1/2 format.
- **230 TESTS PASS** — python-dist, 0 failures

## What We Accomplished Wave 23
- **VECTOR EXCHANGE COMPLETE.** aeoess shipped `deriveEncryptionKeypair()` — 5/5 vectors, 8 tests, 1081 APS suite green. XChaCha20-Poly1305 alignment confirmed. APS→qntm bridge PoC built. Step 3 proposed.

## What We Accomplished Wave 22
- **3RD EXTERNAL RESPONDER: haroldmalikfrimpong-ops** on A2A #1672. Validated identity→transport thesis. Called qntm/APS/AIM "complementary pieces, not competing ones." Wants to explore Agent Card-level interop. Network node: builds across A2A, crewAI, getagentid.dev.
- **REPLIED ON #1672** — facilitated connection to @aeoess/APS#5, positioned qntm as identity→transport bridge, offered to spec AgentID→qntm flow.
- **CAMPAIGN 4 CLOSED** — Score 3.5/5. Strong engagement (0→3 responders), weak conversion (0 product users).
- **CAMPAIGN 5 OPENED** — "Bridge the Gap." Convert GitHub engagement into actual product usage.
- **ECOSYSTEM CONNECTIONS** — Peter engaging up2itnow0822 (agentwallet-sdk) on Corpo entity integration. haroldmalikfrimpong-ops expanding AgentID across crewAI.
- **216 TESTS PASS** — python-dist, 14 skipped, 0 failures

## aeoess Engagement Timeline (Design Partner #1)
- Wave 10: Integration proposal posted (APS#5)
- Wave 19: First reply — detailed 5-layer integration stack proposed
- Wave 19: We responded with X3DH details + test vector proposal
- Wave 19-20: aeoess accepted vector exchange with 3-step plan
- Wave 20: We posted vectors + compatibility analysis + TypeScript runner
- Wave 21: No new activity (Sunday night — expected)
- Wave 22: Still pending. haroldmalikfrimpong-ops directed to APS#5.
- **Wave 23: VECTOR EXCHANGE COMPLETE.** aeoess shipped `deriveEncryptionKeypair()` in commit `40f82af`. 5/5 vectors pass, 8 tests, 1081 suite green. Proposed XChaCha20-Poly1305 as common AEAD (we already use it!). Also engaged on Corpo entity binding (A2A#1575).
- **Wave 24: RELAY TEST GREENLIT.** aeoess replied twice — accepted layered envelope design, asked for relay endpoint + echo bot conv ID. We replied with comprehensive relay API docs, TypeScript example, envelope format. aeoess shipped entityBinding + identityBoundary (d253d8f, 1090 tests). They are building the TypeScript side.
- Across threads: aeoess engaged on APS#5, A2A#1575, A2A#1606, A2A#1667
- Peter engaged directly on A2A#1575 (Corpo legal entity binding + response to aeoess mapping)
- **Status:** STEP 3 — relay test. aeoess has all connection details. Building TypeScript relay client.

## haroldmalikfrimpong-ops Engagement Timeline (Potential Design Partner #2)
- Wave 21: Our comment on A2A #1672 (his proposal)
- Wave 22: He replied — validated thesis, asked to connect with APS team
- Wave 22: We facilitated connection, offered to spec AgentID→qntm flow
- Also active: crewAI#5019 (cryptographic identity for crews), getagentid.dev (AgentID platform)
- **Status:** ACTIVE — waiting for response to connection offer

## Metrics
- Tests: 216 pass, 14 skipped, 0 failures ✅
- Relay: OPERATIONAL ✅ (WebSocket-only, version d69d6763)
- Echo bot: CF WORKER LIVE ✅
- TTFM: 1.2 seconds ✅
- Active conversations (7-day relay): **16** (stable)
- Active conversations (qntm-only): 1 (echo bot)
- Design partners: 0 formal → **aeoess at ACTIVE design-partner stage (code shipped!), haroldmalikfrimpong-ops emerging**
- External users who've ever messaged: 0
- **External engagements: 13** — **3 REPLIES (aeoess BUILDING relay integration, The-Nexus-Guard stable, haroldmalikfrimpong-ops active)**, 9 no reply, relay details shared
- **Direct integration proposals: 6** — **1 active with code (aeoess)**, 5 pending
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues
- **Competitors (March 2026):** 10+ new projects (leyline, HuiNet latest)
- **Campaigns completed:** 4 (Campaign 5 active, wave 2/6)
- **Total waves:** 24
- **NanoClaw integration:** live relay round-trip confirmed, blocked on credential proxy bug
- **Subscribe auth:** SHIPPED (c0104a0, deployed)
- **Interop tests:** 9 pass (Ed25519→X25519 vectors)
- **Vector exchange:** ✅ COMPLETE — aeoess shipped code, 5/5 pass, 3 implementations compatible
- **APS→qntm bridge PoC:** BUILT (python-dist/examples/aps_bridge.py)
- **Cipher alignment:** XChaCha20-Poly1305 confirmed — both projects use same AEAD

## Ops Log
- Wave 1-20: [see wave logs for full history]
- Wave 21: **EXPANDED ENGAGEMENT.** Commented on A2A #1672 (10th engagement). Competitive analysis: leyline (P2P, Ed25519, XChaCha20, launched today — threat LOW-MEDIUM). Relay active conversations 10→16 (internal). All threads monitored. aeoess quiet (Sunday night). 5 proposals pending (Monday).
- Wave 22: **CAMPAIGN 4 CLOSED (3.5/5). 3RD RESPONDER.** haroldmalikfrimpong-ops replied on #1672 — validated identity→transport thesis, wants interop. Facilitated APS connection. Campaign 5 opened: "Bridge the Gap." Chairman briefing sent.
- Wave 23: **VECTOR EXCHANGE COMPLETE. CAMPAIGN 5 WAVE 1.** aeoess shipped deriveEncryptionKeypair() — 5/5 vectors, 8 tests, 1081 APS suite green. XChaCha20-Poly1305 alignment confirmed. APS→qntm bridge PoC built. Step 3 (relay test) proposed. Corpo entity mapping deepening on #1575.
- Wave 24: **THE CONVERSION REPLY.** aeoess asked for relay endpoint + echo bot conv ID — we replied with full API docs, TypeScript example, envelope format, auth flow. haroldmalikfrimpong-ops 2nd reply on #1672 — will spec AgentID→subscribe-auth. aeoess shipped entityBinding + identityBoundary (d253d8f, 1090 tests). 230 tests pass. 13 engagements. Step 3 greenlit.

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
