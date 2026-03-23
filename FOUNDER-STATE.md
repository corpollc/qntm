# Founder State — qntm
Updated: 2026-03-23T02:50:00Z
Wave: 23 (COMPLETE) — VECTOR EXCHANGE COMPLETE + Campaign 5 Launch

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
2. **🟡 P1: MCP marketplace listing.** Materials ready (LobeHub manifest + Smithery config). Smithery requires active submission (no auto-indexing). RULING NEEDED: Does submitting to Smithery.ai / LobeHub count as "any-public-post" under AUTONOMY.md? **6th wave asking.**
3. **🟡 P1: Public posting DENIED** — Show HN draft v2 ready, 10 outbound engagements active but all via GitHub. HN would 10x reach.
4. **🟢 P1: Distribution producing signal.** First external replies after 18 waves. aeoess engagement deepening. 10 total engagements now.

## What We Accomplished Wave 23
- **VECTOR EXCHANGE COMPLETE.** aeoess shipped `deriveEncryptionKeypair()` — 5/5 vectors pass, 8 tests (including DH key agreement), 1081 total APS suite green. Three implementations byte-for-byte compatible: libsodium (APS/TypeScript), @noble/curves (TypeScript runner), Python cryptography (qntm).
- **XCHACHA20-POLY1305 ALIGNMENT.** aeoess proposed XChaCha20-Poly1305 as common AEAD — which is exactly what qntm already uses (PyNaCl/libsodium). Zero cipher negotiation needed.
- **APS→QNTM BRIDGE PoC BUILT.** Python script that takes an APS Ed25519 seed → derives X25519 → creates qntm identity. Lowers barrier from "discuss interop on GitHub" to "run this code."
- **REPLIED ON APS#5** — confirmed XChaCha20 alignment, shared QSP 1.1 envelope structure, proposed Step 3: actual encrypted relay test.
- **aeoess engaged on Corpo entity binding (A2A#1575)** — authority_ceiling → ScopedPermission mapping. Peter responded with technical detail. Multi-project alignment deepening.
- **CHAIRMAN BRIEFING SENT** — Wave 23, Page 1/2 format.
- **216 TESTS PASS** — python-dist, 14 skipped, 0 failures

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
- **Wave 23: VECTOR EXCHANGE COMPLETE.** aeoess shipped `deriveEncryptionKeypair()` in commit `40f82af`. 5/5 vectors pass, 8 tests, 1081 suite green. Three implementations compatible. Proposed XChaCha20-Poly1305 as common AEAD (we already use it!). Moving to Step 2: envelope format spec. Also engaged deeply on Corpo entity binding (A2A#1575 — authority_ceiling → ScopedPermission mapping).
- Across threads: aeoess engaged on APS#5, A2A#1575, A2A#1606, A2A#1667
- Peter engaged directly on A2A#1575 (Corpo legal entity binding + response to aeoess mapping)
- **Status:** STEP 2 — envelope format spec (aeoess driving). We proposed Step 3: actual relay test message.

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
- **External engagements: 12** — **3 REPLIES (aeoess DEEPENING with code, The-Nexus-Guard stable, haroldmalikfrimpong-ops active)**, 8 no reply, 1 new reply on APS#5
- **Direct integration proposals: 6** — **1 active with code (aeoess)**, 5 pending
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published version: **v0.4.20 WORKING** ✅
- GitHub: 1 star, 0 forks, 0 external issues
- **Competitors (March 2026):** 10+ new projects (leyline, HuiNet latest)
- **Campaigns completed:** 4 (Campaign 5 active, wave 1/6)
- **Total waves:** 23
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
