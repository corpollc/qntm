# Wave 37 — THE WG IS REAL + FIRST EXTERNAL SPEC PR
Started: 2026-03-23T16:40:00Z (Mon 9:40 AM PT)
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions

1. **What changed since last wave?**
   - **aeoess FORMALLY COMMITTED TO WG on A2A #1672.** Full deliverables: self-sovereign identity, delegation chains, governance layer (32 constitutional modules), TypeScript ref impl (1122 tests), MCP server (72 tools), qntm bridge live, shared test vectors. Proposed multibase encoding standardization.
   - **The-Nexus-Guard BROKE 5-WAVE SILENCE.** Independently resolved archedark-ada's DIDs from their side. Confirmed interop path. Flagged `did:aip` → `did:agip` rename (Aries collision). Offered subscribe auth test vectors. Acknowledged our aip#5 invitation.
   - **desiorac OPENED AND MERGED PR #4 on corpollc/qntm.** First external spec contribution — documenting `did:web` in DID resolution spec. 8 additions, clean diff. Also confirmed `buyer_fingerprint` aligns with qntm sender ID derivation (Trunc16(SHA-256(pubkey))).
   - **haroldmalikfrimpong-ops declared "The WG is real" on #1672.** Three projects, three commitments, shared specs.
   - **archedark-ada + The-Nexus-Guard connecting DIRECTLY.** Phase 2 verificationMethod alignment happening without moderation. archedark-ada adopted The-Nexus-Guard's format as target.
   - **6 projects touched the same stack in ONE DAY.** qntm, APS, AgentID, AIP, ArkForge, Agent Agora.

2. **Single biggest bottleneck?**
   - Strategic: protocol vs product decision. The WG is real. The company must decide what it IS.

3. **Bottleneck category?**
   - Strategy (chairman-level). Not product, not distribution. Identity.

4. **Evidence?**
   - 37 waves, 6 external persons, 2 external PRs merged, WG committed by 3 projects, 3 candidates aligning — but 0 standalone users. The standard is forming. The product has no users.

5. **Highest-impact action?**
   - Respond to all new threads (done). The momentum is partner-driven — our job is to keep the pace and quality high.

6. **Customer conversation avoiding?**
   - Anyone outside the WG ecosystem.

7. **Manual work that teaches faster?**
   - desiorac running `resolve_did_to_ed25519('did:web:trust.arkforge.tech')` — would be first external user of the DID module directly (not through the relay).

8. **Pretending is progress?**
   - No. This wave is objectively the best day in the company's history. 4 independent actors took action on qntm infrastructure in 90 minutes.

9. **Write down?**
   - Campaign 6 Goal 1: DONE. First external contribution to specs (desiorac PR #4).
   - Campaign 6 Goal 3: EFFECTIVELY DONE. The-Nexus-Guard broke silence and is engaging with the WG.
   - aeoess committed formally — not just building, but declared WG membership with scope.
   - `buyer_fingerprint` = `Trunc16(SHA-256(pubkey))` alignment with ArkForge is accidental and validates the sender ID derivation design.
   - The-Nexus-Guard's `did:aip` → `did:agip` rename risk. Don't hardcode method name.

10. **Escalation?**
    - **NEW: WG governance question for chairman.** Should we formalize (charter, decision process) or stay code-first?
    - Same 4 existing blockers.

## Wave 37 Top 5 (force ranked)

1. ✅ **Merge desiorac PR #4** — first external spec contribution → MERGED
2. ✅ **Respond to aeoess on A2A #1672** — acknowledge WG commitment, propose multibase standardization, declare WG roster
3. ✅ **Respond to desiorac on OATR#2** — buyer_fingerprint alignment, propose integration test, confirm scope table
4. ✅ **Respond to The-Nexus-Guard on A2A #1667** — welcome back, confirm relay auth docs, note rename, keep door open
5. ✅ **Write wave log, update state, commit**

## Execution Log

### #1 — desiorac PR #4 ✅ (MERGED — 2nd EXTERNAL PR)
- 8-line addition: `did:web` section in DID resolution spec
- Three key encoding formats documented (publicKeyMultibase, publicKeyBase58, publicKeyJwk)
- Both URL resolution patterns (root + path-based)
- Reference back to existing `qntm/did.py` implementation
- Approved and merged within wave

### #2 — A2A #1672 Reply ✅ (ENGAGEMENT 36)
- Acknowledged aeoess WG commitment
- Proposed `z`-prefixed base58btc as canonical multibase encoding
- Posted updated WG roster table (3 committed members)
- Noted desiorac PR #4 as milestone
- Noted The-Nexus-Guard breaking silence
- Raised governance question for chairman

### #3 — OATR#2 Reply ✅ (ENGAGEMENT 37)
- Confirmed buyer_fingerprint = Trunc16(SHA-256(pubkey)) alignment
- Confirmed PR #4 merged
- Validated contributing_agents + QSP-1 composition pattern
- Proposed concrete integration test: `resolve_did_to_ed25519('did:web:trust.arkforge.tech')`
- ArkForge already in scope table

### #4 — A2A #1667 Reply ✅ (ENGAGEMENT 38)
- Welcomed The-Nexus-Guard back
- Validated their DID Document format as WG gold standard
- Accepted subscribe auth test vector offer
- Acknowledged did:aip → did:agip rename (won't hardcode)
- Pointed to specs repo + desiorac's merged PR as evidence of WG activity

## Key Discoveries

- **CAMPAIGN 6 GOAL 1: DONE.** desiorac opened PR #4 — first external contribution to WG spec directory. This was "1 PR/issue from non-qntm member." Achieved wave 37 (9th campaign wave).
- **CAMPAIGN 6 GOAL 3: EFFECTIVELY DONE.** The-Nexus-Guard broke silence and is actively resolving DIDs, offering test vectors, considering WG participation. They didn't just reply — they DID WORK (resolved archedark-ada's endpoints independently).
- **THE WG HAS 3 COMMITTED MEMBERS AND 4 ACTIVE CANDIDATES.** This is not a mailing list. Three projects have shipped interop code. Two more (ArkForge, AIP) are contributing specs and test vectors. One (Agent Agora) is building discovery infrastructure.
- **CROSS-POLLINATION WITHOUT MODERATION.** The-Nexus-Guard resolved archedark-ada's DIDs. archedark-ada adopted The-Nexus-Guard's format. desiorac opened a PR on qntm. haroldmalikfrimpong-ops cross-linked APS and AgentID interop. None of this was orchestrated by us.
- **ArkForge `buyer_fingerprint` ALIGNMENT IS ACCIDENTAL.** They independently chose `Trunc16(SHA-256(pubkey))` as their fingerprint derivation — same as qntm's sender ID. This validates the design choice and lowers integration cost to near-zero.
- **did:aip RENAME RISK.** The-Nexus-Guard flagged a W3C Aries name collision. `did:aip` may become `did:agip`. Our resolver is method-agnostic so it's a one-line change, but worth tracking.

## Metrics This Wave
- Tests: **261 pass**, 1 skip, 0 failures ✅ (stable)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **38** (3 new: A2A #1672 + OATR#2 + A2A #1667)
- External persons engaged: **6** (stable — but ALL active today)
- External PRs merged: **2** (haroldmalikfrimpong-ops PR #3 + desiorac PR #4)
- WG Committed Members: **3** (qntm, APS, AgentID)
- WG Active Candidates: **4** (The-Nexus-Guard, archedark-ada, FransDevelopment, desiorac/ArkForge)
- Repo: 1 star, 1 fork
- PyPI: 781/day, 1,642/week, 2,402/month (stable)
- Commits: 1 merge (PR #4)
- Campaign 6: Goal 1 ✅ DONE, Goal 2 ✅ DONE, Goal 3 🟡 EFFECTIVELY DONE, Goal 4 IN PROGRESS, Goal 5 PENDING
