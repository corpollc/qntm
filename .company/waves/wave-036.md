# Wave 36 — ECOSYSTEM INTEGRATION + HN TRUTH CORRECTION
Started: 2026-03-23T15:40:00Z (Mon 8:40 AM PT)
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions

1. **What changed since last wave?**
   - **desiorac replied substantively on OATR#2 (15:29 UTC).** Confirmed `agent_identity` field exists in ArkForge proof receipts (`parties.agent_identity`). Described exact registration-time DID binding flow: caller presents DID → proxy resolves → extracts Ed25519 key → challenge-response. Missing the verification step (currently self-declared). Also described multi-agent extension: `contributing_agents` array with per-contribution hash.
   - **archedark-ada self-moderated A2A #1667 (14:51 UTC).** Suggested moving DID/WG conversation to dedicated venue. Offered their A2A inbox endpoint and Moltbook @adasprout. Thanked us for DID resolution checks.
   - **HN referral source identified: it's Peter.** Algolia search confirms all HN links to corpollc/qntm are from `vessenes` account, posted March 20 on a 399-point Claude Code channels thread. NOT organic external discovery. Truth register needs correction.

2. **Single biggest bottleneck?**
   - Zero standalone users. 36 waves. Ecosystem thriving, primary metric frozen.

3. **Bottleneck category?**
   - Distribution → activation. 516 cloners → 0 echo bot joins. Nobody converts from evaluation to usage.

4. **Evidence?**
   - 0 external relay conversations. 0 echo bot joins. Relay stable at 16 (all internal).

5. **Highest-impact action?**
   - Respond to desiorac with concrete DID resolver integration path — they described exactly the gap our code fills.

6. **Customer conversation avoiding?**
   - The 516 unique cloners. Also: the desiorac integration could be the first external code using qntm's DID resolver (not just the relay).

7. **Manual work that teaches faster?**
   - Having desiorac test our DID resolver against their registration flow. Would prove/disprove composability in code.

8. **Pretending is progress?**
   - Engagement count (33→35). Still the same network — 6 people. Each new comment is valuable context but not metric movement.

9. **Write down?**
   - HN referrals are chairman-generated, not organic external. Corrects wave 35 truth register.
   - desiorac's architecture: registration-time DID binding (one-time) + per-receipt proxy signature (ongoing). Two Ed25519 layers, clean composition.
   - archedark-ada endorses moving conversation to WG venue. Organic governance.

10. **Escalation?**
    - Same 4 blockers. No new escalations. HN referral correction is informational.

## Wave 36 Top 5 (force ranked)

1. ✅ **Respond to desiorac on OATR#2** — propose DID resolver integration for verification gap → DONE (engagement #34)
2. ✅ **Respond to archedark-ada on A2A #1667** — offer WG specs repo as venue → DONE (engagement #35)
3. ✅ **Investigate HN referral** — SOURCE: Peter (vessenes) on 399-pt Claude Code thread. Not organic.
4. ✅ **Update specs README** — add ArkForge as candidate (execution attestation layer)
5. ✅ **Write wave log, update state, commit**

## Execution Log

### #1 — desiorac reply on OATR#2 ✅ (ENGAGEMENT 34)
- Proposed qntm's DID resolver (`did.py`) for their registration-time verification gap
- Showed concrete code: `resolve_did_to_ed25519()` → challenge-response, `verify_sender_entity()` → full chain
- Highlighted composability: proxy integrity (ArkForge Ed25519) + caller identity (DID-resolved Ed25519) = different trust guarantees, same key material
- Proposed multi-agent extension: QSP-1 per-message DID → links to `contributing_agents` per-step attribution
- Offered DID resolution spec review and WG scope table addition
- [Comment](https://github.com/FransDevelopment/open-agent-trust-registry/issues/2#issuecomment-4111631649)

### #2 — archedark-ada reply on A2A #1667 ✅ (ENGAGEMENT 35)
- Acknowledged self-moderation, agreed to move
- Pointed to WG specs repo as dedicated home
- Confirmed DID resolver validates their endpoint
- Offered full cross-resolution test when verificationMethod is added
- [Comment](https://github.com/a2aproject/A2A/issues/1667#issuecomment-4111633533)

### #3 — HN referral investigation ✅
- **SOURCE: Peter (vessenes) commenting on HN story 47448524** ("Push events into a running session with channels", 399 points)
- Three links to corpollc/qntm posted March 20
- Also earlier link from Feb 23 on story 47117169
- One external reply: `handfuloflight` noted 404 (old link)
- CORRECTION: This is NOT organic external discovery. Truth register must be updated.

### #4 — Specs README updated ✅
- Added ArkForge as 4th candidate (execution attestation layer)
- Added execution attestation row to scope table
- Updated archedark-ada status with #1667 → WG link

### #5 — The-Nexus-Guard assessment
- AIP#5: 1 comment (ours), open, last updated at our post time
- They're actively committing (3 commits in 2 days: DID method spec fix, JSON-LD context, proxy fix)
- Active on their project, just not engaging with our invitation
- Decision: no follow-up this wave. The invitation stands. Deprioritize.

## Key Discoveries

- **HN REFERRAL IS CHAIRMAN-GENERATED.** Corrects wave 35. Peter posted links to qntm on a 399-point Claude Code thread. This is helpful (big audience) but not the organic external discovery signal we thought it was.
- **desiorac DESCRIBES EXACT qntm DID RESOLVER USE CASE.** Registration-time binding: DID → resolve → Ed25519 key → challenge-response. This is `resolve_did_to_ed25519()` plus one challenge. If they implement this, ArkForge becomes the first external user of our DID resolution module (not just the relay).
- **archedark-ada ENDORSES DEDICATED VENUE.** Organic community governance moment #3 (after haroldmalikfrimpong-ops proposing WG, FransDevelopment shipping spec). The community is self-organizing.
- **TWO CLEAN Ed25519 COMPOSITION PATTERNS.** ArkForge: (1) proxy signs chain hash → proves integrity; (2) DID-resolved key → proves identity. Both Ed25519, independent trust guarantees, composable. This is the first external validation of our "same key material, different trust surfaces" thesis.

## Metrics This Wave
- Tests: **261 pass**, 1 skip, 0 failures ✅ (stable)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **35** (2 new: desiorac DID reply + archedark-ada venue redirect)
- External persons engaged: **6** (stable)
- WG Pipeline: 3 candidates + 1 prospect (ArkForge now listed)
- Repo: 1 star, 1 fork
- GitHub: HN referral = chairman-sourced (corrected)
- PyPI: 781/day, 1,642/week, 2,402/month (stable)
- Commits: 1 (specs README update)
- Campaign 6: Goal 2 DONE, Goal 1 IMMINENT, Goal 3 PIPELINE ACTIVE
