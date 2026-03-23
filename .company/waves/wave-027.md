# Wave 27 — DID Convergence
Started: 2026-03-23T06:39:00Z
Campaign: 5 (Waves 23-28) — Bridge the Gap

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **FIRST EXTERNAL PR** — haroldmalikfrimpong-ops opened PR #3 on corpollc/qntm (298-line AgentID bridge example)
   - **DID INTEROP EMERGED ORGANICALLY** — Both partners independently moved from relay-proven to DID cross-verification
   - **haroldmalikfrimpong-ops shipped DID cross-verification** — `did:agentid` ↔ `did:aps` interop, 10/10 checks, 82 tests, deterministic test vectors posted
   - **aeoess proposed DID test sequence** — 5-step plan for cross-DID verification on APS#5
   - **haroldmalikfrimpong-ops updated CBOR to native qntm field names** — bridge compatibility layer no longer needed for his messages
   - **THE CONVERSATION IS SELF-SUSTAINING** — partners are collaborating directly on APS#5 without qntm needing to drive

2. **Single biggest bottleneck?**
   - Distribution beyond these 2 partners. They're self-driving now. The bottleneck has shifted from "get engagement" to "how do we go from 2 design partners to broader adoption?" Also: no formal envelope spec exists — the field-name divergence needs resolution.

3. **Bottleneck category?**
   - Distribution + product (formal spec)

4. **Evidence?**
   - PR landed, both partners iterating without our involvement. But: 0 standalone users of qntm. Primary metric (active conversations) = 2, both echo bot. Real external users sending qntm messages natively = 0.

5. **Highest-impact action?**
   - Merge PR #3 (signal that we value contributions), formalize envelope spec, participate meaningfully in DID thread.

6. **Customer conversation avoiding?**
   - We're not reaching beyond these 2 partners. Need to think about next outreach wave.

7. **Manual work that teaches faster?**
   - Review the PR code carefully. Reading what an external builder actually wrote tells us what's intuitive and what's not.

8. **Pretending is progress?**
   - Need honesty: 2 partners building bridges is amazing, but the "Bridge the Gap" campaign goal was "convert engagement to product usage." These are integrations, not standalone usage. They're building bridges TO qntm, not FROM qntm's CLI. Different thing.

9. **Write down?**
   - Envelope spec need, PR merge decision, DID milestone, contributor experience observations.

10. **Escalation?**
    - MCP marketplace ruling (12th wave asking). CF KV daily write limits still an issue.

## Wave 27 Top 5 (force ranked)

1. **Review and merge PR #3** — first external PR, signal we value contributions
2. **Reply on APS#5** — acknowledge DID progress, add qntm-specific value (envelope spec + DID direction)
3. **Formalize QSP-1 envelope spec** — the field-name divergence needs resolution NOW
4. **Update metrics and state**
5. **Create .company/customers/ directory** — log what we've learned from partner interactions

## Execution Log

### #1 — Reviewed and merged PR #3 ✅
- Code review: clean implementation. HKDF derivation correct, XChaCha20-Poly1305 envelope matches QSP-1, Ed25519 signing verified, CBOR encoder handles all needed types.
- Uses native qntm field names (msg_id/ciphertext/aad_hash) — no bridge compatibility needed.
- 298 lines, single file in `examples/agentid-bridge/relay_test.py`.
- Approved and merged. First external contribution to the project.

### #2 — Replied on APS#5 ✅
- Acknowledged DID milestone and PR merge.
- Explained qntm's key_id→DID mapping architecture (transport vs identity layer separation).
- Committed to formal QSP-1 envelope spec with canonical field names, encoding rules, DID extension point.
- Provided 7-point interop checklist (5 proven, 2 remaining).

### #3 — Replied on A2A#1672 ✅
- Acknowledged PR merge, summarized three-way interop status.
- Directed ongoing implementation work to APS#5.

### #4 — Drafted QSP-1 envelope spec ✅
- `.company/specs/qsp1-envelope-spec-v0.1.md`
- Canonical field names, CBOR encoding rules, cryptographic operations, test vectors.
- Bridge alias table (deprecated nonce/ct/aad → canonical msg_id/ciphertext/aad_hash).
- DID extension point for future envelope metadata.

### #5 — Created customer evidence directory ✅
- `.company/customers/aeoess.md` — full design partner profile
- `.company/customers/haroldmalikfrimpong-ops.md` — full design partner profile

### #6 — Chairman Morning Briefing ✅
- Sent via qntm to Pepper (conv 2d0d). Page 1/2 format.

### #7 — Updated state, metrics, KPIs, wave log ✅

## Metrics This Wave
- Tests: 230 pass, 0 failures ✅
- Echo bot: OPERATIONAL (2 convos, bridge-compatible) ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **18** — 3 active replies, 1 PR merged, DID interop proven
- External PRs: **1 merged** (first ever)
- Direct integration proposals: 6 — 2 active with DID-level interop
- Campaign 5 wave 5/6

## Assessment

Wave 27 marks a phase transition. The conversation between aeoess and haroldmalikfrimpong-ops is now self-sustaining — they're collaborating on DID interop without qntm needing to drive. The first external PR is merged. The ecosystem is forming.

But the honest assessment: **we're building a protocol standard, not shipping a product.** Both partners use qntm as relay infrastructure underneath their own identity systems. Zero standalone users. The primary metric (active conversations) hasn't moved. Campaign 5's "Bridge the Gap" goal was to convert engagement into product usage — what we got was integration code. That's valuable but different.

**Campaign 5 scorecard (wave 5/6):**
- Goal 1: First external `qntm identity generate` — NOT ACHIEVED (partners use their own identity systems)
- Goal 2: Interop PoC — ✅ EXCEEDED (3 PoCs + DID cross-verification)
- Goal 3: MCP marketplace — BLOCKED (12th wave)
- Goal 4: Vector exchange complete — ✅ ACHIEVED
- Goal 5: Integration PR — ✅ ACHIEVED (PR #3 merged)

Score so far: 2.5/5. Strong on integration, weak on product adoption.

**The question for Campaign 6:** Is "protocol that others build on" the right company, or do we need standalone product usage to survive? The relay is the infrastructure. The partners are the signal. But 0 direct users after 27 waves is a number that demands an answer.
