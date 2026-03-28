# Wave 21 — Monitor + Engage + Campaign 4 Prep
Started: 2026-03-23T00:39:00Z
Campaign: 4 (Waves 16-22) — Convert or Pivot

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - Relay active conversations jumped 10 → 16 (6 new in ~1 hour — likely corpo/NanoClaw internal traffic)
   - NEW A2A issue #1672: "Agent Identity Verification for Agent Cards" by @haroldmalikfrimpong-ops — proposes `verifiedIdentity` field for Agent Cards with ECDSA P-256 certificates. References getagentid.dev. 0 comments. Directly relevant.
   - NEW competitor: MissyLabs/leyline — P2P agent messaging, Ed25519, encrypted DMs, store-and-forward. Created TODAY (Mar 22). TypeScript, 134 tests. 0 stars but architecturally serious.
   - NEW competitor: HuiNet-Network-Core — decentralized A2A networking, NAT traversal, encrypted messaging. 1 star.
   - aeoess: no new activity since our TypeScript vector post (23:50 UTC, 49 min ago). Expected — Sunday night.
   - 5 remaining proposals: still 0 replies (Sunday — expected).
   - Peter posted Corpo Agent Listing on A2A #1671. Company is engaging the ecosystem independently.

2. **Single biggest bottleneck?**
   - **Waiting for aeoess step 2.** The interop proof is the critical path to design partner conversion. But we shouldn't idle — A2A #1672 is a ripe engagement target.

3. **Bottleneck category?**
   - Distribution + external validation. The product works. We need people using it.

4. **Evidence?**
   - 20 waves, 230 tests, relay up, PyPI working, MCP server shipped — product is done for MVP. Primary metric (active external conversations) is still 1 (echo bot internal). All external signal is GitHub engagement, not product usage.

5. **Highest-impact action?**
   - Comment on A2A #1672 (agent identity verification). Our qntm identity + subscribe auth are directly relevant prior art. The author built getagentid.dev — potential engagement.

6. **Customer conversation avoiding?**
   - None. Engaging on every available surface.

7. **Manual work that teaches faster?**
   - Competitive analysis of leyline — they launched today with the same thesis (Ed25519 identity, encrypted agent messaging, P2P). Understanding their approach informs our positioning.

8. **Pretending is progress?**
   - Building more features while waiting for aeoess would be classic avoidance. The right move is expanding distribution surface.

9. **Write down?**
   - Competitive intelligence on leyline and HuiNet. Engagement on #1672. Campaign 4 assessment prep.

10. **Escalation?**
    - MCP marketplace ruling: 6th wave asking. Will include in Monday morning briefing.

## Wave 21 Top 5 (force ranked)

1. **Comment on A2A #1672** — agent identity verification proposal, our exact value prop
2. **Competitive analysis: leyline** — new today, directly competitive, needs understanding
3. **Monitor aeoess** — check for step 2 response
4. **Prepare Campaign 4 assessment framework** — wave 22 is the final assessment
5. **Update truth register + state** — competitive intelligence, relay stats

## Execution Log

### #1 — Commented on A2A #1672 (Agent Identity Verification) ✅
Posted substantive technical comment comparing CA-issued (ECDSA P-256) vs self-sovereign (Ed25519) identity models. Referenced APS, AIM, and qntm as prior art. Raised the identity→encrypted-transport gap. Asked how verifiedIdentity would interact with encryption capabilities.
- Comment: https://github.com/a2aproject/A2A/issues/1672#issuecomment-4107355097
- **External engagements: now 10** (4 A2A threads + 6 direct proposals)
- Target: @haroldmalikfrimpong-ops (builds getagentid.dev, has CrewAI/LangChain/MCP integrations)

### #2 — Competitive Analysis: leyline (MissyLabs) ✅
**MissyLabs/leyline** — created TODAY (Mar 22, 2026)
- **What:** P2P agent messaging network built on libp2p
- **Stack:** TypeScript, libp2p (GossipSub + TCP + Noise + Yamux), Ed25519, @noble/curves, LevelDB
- **Encryption:** XChaCha20-Poly1305 with Ed25519→X25519 derivation (same primitives as us!)
- **Architecture:** Fully decentralized — no relay, pure P2P with bootstrap nodes, gossipsub for pub/sub
- **Features:** Tag-based pub/sub, encrypted DMs, shared ledger (Merkle chain), peer exchange, trust policies
- **Tests:** 134 passing
- **Stars/Forks:** 0/0 (brand new)
- **Key differences from qntm:**
  - P2P vs relay (leyline has no store-and-forward for offline agents)
  - GossipSub vs WebSocket subscriptions
  - No Double Ratchet (static shared secret per DM pair — no forward secrecy)
  - No API Gateway / m-of-n approval
  - No subscribe auth
  - Has shared ledger (we don't)
  - Has pub/sub topic system (we have conversations)
- **Threat assessment:** LOW-MEDIUM. Architecturally serious but fundamentally different trust model. P2P works for always-online agents; relay+store-and-forward works for real-world agents that go offline. They solve discovery; we solve persistence+privacy. Could be complementary. Watch for traction.
- **Interesting:** Uses exact same crypto primitives (@noble/curves, Ed25519→X25519, XChaCha20-Poly1305). Test vector interop would be trivial.

### #3 — Competitive Analysis: HuiNet
**free-revalution/HuiNet-Network-Core** — 1 star
- Decentralized A2A networking, NAT traversal, encrypted messaging
- Too early to evaluate deeply. Watching.

### #4 — Relay Stats Check ✅
Active conversations jumped 10 → 16 (6 new in ~1 hour). These are almost certainly corpo/NanoClaw internal traffic on the shared relay. qntm-only external conversations: still 1 (echo bot).

### #5 — Monitoring All Engagement Threads ✅
| Thread | Status | Since W20 |
|--------|--------|-----------|
| APS#5 (integration) | ACTIVE — waiting aeoess step 2 | No new activity (Sunday night) |
| A2A#1672 (identity verification) | **NEW — just commented** | Our comment posted |
| A2A#1667 (relay) | At rest | No change |
| A2A#1575 (identity) | At rest (Peter + aeoess conversation) | No change |
| A2A#1606 (data handling) | At rest | No change |
| ADHP#12 | No reply | No change |
| AIM#92 | No reply | No change |
| nono#458 | No reply | No change |
| clawdstrike#216 | No reply | No change |
| mcp-gateway#17 | No reply | No change |

### #6 — Campaign 4 Assessment Prep (for Wave 22)
**Campaign 4 Theme:** Convert or Pivot (Waves 16-22)
**Campaign 4 Goals:**
1. Convert at least 1 engagement into a design partner → **IN PROGRESS** (aeoess at proto-design-partner stage)
2. MCP marketplace as distribution channel → **SHIPPED product, BLOCKED on marketplace listing**
3. If no conversion by wave 22 → strategic pivot assessment

**Assessment criteria for wave 22:**
- Did aeoess complete vector exchange? → determines design partner status
- Did any other proposal get a reply? → Monday morning is the test
- Is there evidence of external product usage? → still 0
- Should we pivot distribution strategy? → evaluate new channels

## Metrics This Wave
- Tests: 230 pass (221 + 9 interop), 0 failures ✅
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (version d69d6763)
- Active conversations (7-day relay): **16** (up from 10 — mostly internal)
- qntm-only active conversations: 1 (echo bot)
- External engagements: **10** — 2 active replies (aeoess, The-Nexus-Guard), 8 no reply
- Direct integration proposals: 6 — 1 active (aeoess), 5 pending
- PyPI: v0.4.20 LIVE ✅
- GitHub: 1 star, 0 forks, 0 external issues
- GitHub traffic (Mar 21): 1 view/1 unique, 150 clones/29 uniques
- Campaign 4 wave 6/7
- New competitors identified: leyline (serious), HuiNet (too early)

## Assessment

**Wave 21 was productive maintenance work on a Sunday night.** No breakthrough expected (aeoess waiting, proposals pending until Monday), but we expanded the engagement surface (10th comment on A2A #1672) and gained competitive intelligence.

**Key insight: leyline confirms the thesis.** A new project launched TODAY with the exact same value proposition (Ed25519 identity + encrypted agent messaging). This validates that the problem is real — multiple teams are independently arriving at the same solution. But it also means the window is narrowing. First-mover advantage matters less than *first-community advantage*.

**Campaign 4 enters its final wave.** The assessment framework is ready for wave 22:
1. **aeoess conversion** — if they complete vector exchange, we have a proto-design-partner. If not, the engagement is still the deepest external interaction in 21 waves.
2. **Monday proposal responses** — 5/6 proposals are sitting in repos that typically respond on business days.
3. **Distribution reality** — GitHub issues work but are slow (2-12 day response cycle). We need a channel that produces faster feedback. MCP marketplace and HN remain blocked.

**Strategic question for Campaign 5:** If aeoess interop succeeds, do we double down on the interop story (qntm as transport layer for identity systems) or push for direct adoption? The competitive landscape suggests the interop path may be stronger — become infrastructure that other projects build on, rather than competing for direct users against leyline, DeadDrop, etc.

**Next wave priorities:**
1. Check aeoess for step 2 response (key moment)
2. Check Monday morning proposal responses
3. Write Campaign 4 final assessment
4. Decide Campaign 5 strategy
5. Prepare Chairman Monday Morning Briefing
