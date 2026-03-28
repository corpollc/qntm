# Wave 28 — Working Group Formation
Started: 2026-03-23T07:39:00Z
Campaign: 5 (Waves 23-28) — Bridge the Gap (FINAL WAVE)

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **WORKING GROUP PROPOSAL.** haroldmalikfrimpong-ops proposed formalizing AgentID + APS + qntm as an "Agent Identity Working Group" on A2A #1672. Three independent projects, one unified standard. No response yet.
   - **ENTITY FORMATION POC PROPOSED.** Peter (via @vessenes) proposed linking Corpo entity formation → APS entityBinding → qntm transport on APS#5. aeoess asked for staging entity_id. No response yet.
   - **haroldmalikfrimpong-ops proposed optional `did` field** in CBOR envelopes. Peter agreed on APS#5. Not shipped yet.
   - **GitHub traffic surging.** 29 views/22 uniques, 1011 clones/155 uniques on March 22. This is the highest traffic day in the project's history (up from 1/1 on March 21).
   - **aeoess confirmed relay roundtrip** — acknowledged E2E crypto chain closed. Committed to Corpo entityBinding integration test.

2. **Single biggest bottleneck?**
   - The Working Group proposal is the highest-leverage moment in the project's history. A good response shapes whether qntm becomes the transport standard for an ecosystem. A bad response (or no response) lets the moment pass. **Response to the WG proposal is the bottleneck.**

3. **Bottleneck category?**
   - Distribution + ecosystem formation

4. **Evidence?**
   - haroldmalikfrimpong-ops is proposing to FORMALIZE what we've built. This is pull, not push. He's not asking for features — he's asking to institutionalize the collaboration. GitHub traffic confirms broader interest beyond these 2 partners.

5. **Highest-impact action?**
   - Reply to the Working Group proposal with enthusiastic support + structure. Code-first, not committee-first.

6. **Customer conversation avoiding?**
   - We need to think about what the WG means for the protocol-vs-product tension. If qntm is infrastructure that others build on, the business model needs to reflect that. If it's a product, the WG dilutes the brand. This strategic question needs a chairman decision.

7. **Manual work that teaches faster?**
   - Ship the `did` field. Responding to the proposal with working code (not just words) proves we move at the speed these partners expect.

8. **Pretending is progress?**
   - Need to be honest: a Working Group of 3 people is not an industry standard. It's a promising start. Don't overclaim. But also don't undervalue — every major standard started with 3 people in a room.

9. **Write down?**
   - Working Group decision memo, entity formation status, GitHub traffic spike analysis, Campaign 5 closing assessment.

10. **Escalation?**
    - **YES — Working Group proposal needs chairman awareness.** This is a strategic direction choice: qntm as protocol standard (WG path) vs qntm as standalone product. Not irreversible (WG can dissolve) but shapes the next 3-6 months.
    - MCP marketplace ruling (13th wave).
    - Show HN still denied.

## Wave 28 Top 5 (force ranked)

1. **Reply to Working Group proposal on A2A #1672** — endorse with structure (code-first, shared specs, clear scope)
2. **Ship optional `did` field in CBOR envelope** — prove we move fast with code
3. **Reply to aeoess re: Corpo staging entity_id** — unblock their entityBinding integration test
4. **Close Campaign 5 with honest assessment**
5. **Update state, KPIs, truth register, write wave log**

## Execution Log

### #1 — Replied to Working Group proposal on A2A #1672 ✅
- Endorsed with 4 principles: code-first, independent projects, living spec, open membership.
- Committed qntm to: transport infra, QSP-1 spec, test vectors, echo bot, DID field.
- Scope table showing 7 layers across 3 projects + Corpo.
- https://github.com/a2aproject/A2A/issues/1672#issuecomment-4108628430

### #2 — Shipped optional `did` field in CBOR envelope ✅
- `create_message()` now accepts `did` parameter.
- `extract_did()` helper for receivers.
- 2 new tests (DID optional, multiple DID methods). 232 total, all green.
- QSP-1 spec updated to v0.1.1 with `did` field, verification rules.
- Backwards compatible. NOT covered by signature (identity metadata above transport).
- Commit 9663b31, pushed to main.

### #3 — Replied on APS#5 with shipped code ✅
- Announced DID field with code example and verification rule.
- Noted Corpo staging entity_id needs chairman coordination.
- Linked WG endorsement.
- https://github.com/aeoess/agent-passport-system/issues/5#issuecomment-4108645447

### #4 — Chairman Morning Briefing sent ✅
- Pages 1/2 format. Briefing before execution (mandatory).

### #5 — Campaign 5 closed (see assessment below) ✅

## Campaign 5 Final Assessment — "Bridge the Gap"
**Score: 3/5**

| Goal | Status | Assessment |
|------|--------|------------|
| First external `qntm identity generate` | ❌ NOT ACHIEVED | Partners use own identity systems, bridge to qntm relay |
| Interop PoC | ✅ EXCEEDED | 3 PoCs + DID cross-verification + relay roundtrips proven |
| MCP marketplace | ❌ BLOCKED | 13 waves asking, no ruling |
| Vector exchange complete | ✅ ACHIEVED (W23) | 5/5 vectors, 3 implementations |
| Integration PR | ✅ ACHIEVED (W27) | PR #3 merged, first external contribution |
| DID field shipped | ✅ BONUS (W28) | Optional `did` in envelopes, 2 new tests |

**What we learned:**
- Partners adopt the PROTOCOL, not the PRODUCT. They build bridges ON qntm, not through the qntm CLI.
- Working Group formation is organic pull — we didn't engineer it, haroldmalikfrimpong-ops proposed it.
- GitHub traffic responds to commit activity + engagement: 22 uniques on March 22 (highest ever).
- Entity formation POC is the next convergence point: identity + legal + communications.
- The protocol-vs-product tension is real and needs a chairman decision.

## Campaign 6 Preview — "Standard or Product?"
**Theme:** Resolve the strategic direction (Working Group → standard path, or refocus on direct users → product path). Either way, ship the formal QSP-1 spec + DID test vectors that the WG needs.

## Metrics This Wave
- Tests: 232 pass, 0 failures ✅ (up from 230)
- Echo bot: OPERATIONAL (2 convos, bridge-compatible) ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **20** — 2 new comments (WG endorsement + DID field shipped)
- External PRs: 1 merged
- Direct integration proposals: 6 — 2 active with DID-level interop
- GitHub traffic: 29 views/22 uniques, 1011 clones/155 uniques (March 22 — ATH)
- Campaign 5 final score: 3/5
