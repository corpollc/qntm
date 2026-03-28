# Wave 35 — ECOSYSTEM GRAVITY + ARKFORGE DISCOVERY
Started: 2026-03-23T14:40:00Z (Mon 7:40 AM PT)
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions

1. **What changed since last wave?**
   - **6TH EXTERNAL PERSON: desiorac (ArkForge).** Appeared organically on OATR#2 via FransDevelopment's reply thread — not from our outreach. Posted about "identity at execution" — receipt-per-invocation attestation with Ed25519 + Sigstore Rekor. They have real infrastructure: 8 repos under ark-forge org, MCP server on Glama, EU AI Act compliance scanner, n8n nodes, dev.to content marketing. trust.arkforge.tech is a live service.
   - **FransDevelopment's OATR#2 reply is strong validation.** Called our Ed25519→X25519 mapping "genuine, not superficial." Full technical endorsement. Their PR #3 (encrypted transport spec) awaits review.
   - **HN referral traffic detected.** `news.ycombinator.com` appeared in GitHub referrers (3 views, 2 uniques). Source page unknown — likely a comment, not a post.
   - **Clone traffic 3.3x.** 3,940 clones / 516 uniques (14-day), up from 1,011/155. Referral mix: HN (tiny), organic, WG members cloning for integration.
   - **Deep page reads continue.** MCP docs (5 uniques), API gateway (6 uniques), QSP spec (4 uniques), LICENSE (4 uniques). People seriously evaluating.

2. **Single biggest bottleneck?**
   - **Still zero standalone users.** Ecosystem growing organically but primary metric (active conversations) hasn't moved. WG is a developer community, not a user base.

3. **Bottleneck category?**
   - Distribution → activation. Organic discovery exists (HN referral, clone surge, deep page reads) but nobody converts from reading to messaging.

4. **Evidence?**
   - 0 external conversations on relay (unchanged for 10+ waves). 516 unique cloners → 0 echo bot joins. HN referral → 0 visible engagement.

5. **Highest-impact action?**
   - Engage desiorac (execution attestation layer — new trust surface). Review FransDevelopment PR #3 (community service). Both deepen ecosystem.

6. **Customer conversation avoiding?**
   - Talking to any of the 516 unique cloners. Who are they? What were they looking for?

7. **Manual work that teaches faster?**
   - Reviewing the HN thread that generated the referral. Finding who linked to us.

8. **Pretending is progress?**
   - Engagement count (31→33) looks like growth but these are all the same 6 people + us. The number of unique external persons is the meaningful metric.

9. **Write down?**
   - desiorac/ArkForge: real infrastructure, execution attestation layer, Ed25519 + Sigstore, MCP-first. 6th person. Fills "identity at execution" gap.
   - FransDevelopment validated our crypto architecture explicitly ("genuine, not superficial").
   - HN referral exists but tiny (3 views). Not a major traffic source yet.
   - Three trust surfaces framework (desiorac): identity at rest (registry) → identity in transit (qntm) → identity at execution (ArkForge). Clean composability thesis.

10. **Escalation?**
    - Same 4 blockers. CF KV ($5/mo), MCP marketplace ruling, public posting, protocol vs product decision. No new escalations.

## Wave 35 Top 5 (force ranked)

1. **Respond to desiorac on OATR#2** — engage technically, validate ArkForge architecture, ask about DID binding
2. **Respond to FransDevelopment on OATR#2** — review spec, recommend merge with §6.2 adjustment
3. **Investigate clone traffic spike** — check referrers, HN source
4. **Update specs README with desiorac/ArkForge** — 6th layer (execution attestation)
5. **Write wave log and update state**

## Execution Log

### #1 — desiorac reply on OATR#2 ✅ (ENGAGEMENT 32)
- Validated three trust surfaces framework (identity at rest / in transit / at execution)
- Pointed out Ed25519 key material composability across all three layers
- Asked concrete question: does proof-spec support DID-bound agent_identity?
- Mentioned Sigstore/Rekor transparency log alignment with EU AI Act Article 14
- Asked about multi-agent session proof chains
- [Comment link](https://github.com/FransDevelopment/open-agent-trust-registry/issues/2#issuecomment-4111177466)

### #2 — FransDevelopment reply + spec review on OATR#2 ✅ (ENGAGEMENT 33)
- Validated §2.2 Key Identifier Continuity, §3.3 Registry-Bound Auth (novel contribution), §4.3 Nonce Derivation
- Flagged §6.2 wording: MUST NOT → SHOULD NOT for relay authentication (qntm's optional subscribe auth is an optimization, not a requirement)
- Endorsed desiorac's execution attestation as potential §9 appendix
- Recommended merge with §6.2 adjustment
- [Comment link](https://github.com/FransDevelopment/open-agent-trust-registry/issues/2#issuecomment-4111186138)

### #3 — Clone traffic investigation ✅
- **Referrers:** news.ycombinator.com (3 views, 2 uniques) — first HN referral ever!
- **Top paths:** repo root (22/15), API gateway docs (6/6), MCP docs (5/5), LICENSE (4/4), QSP spec (4/4)
- **Clone surge:** 3,940 / 516 uniques (14-day) vs 1,011/155 last period — 3.3x
- HN source page not identifiable (not indexed yet). Likely a comment rather than a post.
- Deep page reads (LICENSE + gateway docs) indicate serious evaluation, not casual browsing.

### #4 — Ecosystem scan ✅
- No new A2A issues since wave 34
- #1672 (AgentID verification) at 22 comments — haroldmalikfrimpong-ops active
- ArkForge org has 8 repos: trust-layer, proof-spec, arkforge-mcp, agent-client, mcp-eu-ai-act, eu-ai-act-scanner, trust-proof-action, n8n-nodes-arkforge
- ArkForge on Glama marketplace (MCP server listing)
- desiorac profile: "arkforge", 13 public repos, 1 follower, GitHub since 2016

## Key Discoveries

- **ECOSYSTEM GRAVITY IS REAL.** desiorac found OATR via FransDevelopment's repo — not through qntm or A2A. The WG is generating its own discovery funnel. This is the hallmark of a real ecosystem vs a managed community.
- **THREE TRUST SURFACES FRAMEWORK.** desiorac's framing (identity at rest / in transit / at execution) maps perfectly to registry (OATR) → transport (qntm) → attestation (ArkForge). Each uses Ed25519 at a different trust boundary. This is a 6-layer stack: discovery → identity → transport → registry → entity → execution.
- **HN IS NOTICING.** First HN referral ever. Tiny (3 views) but proves organic awareness outside the A2A GitHub ecosystem. We didn't post anything — someone else linked to us.
- **ARKFORGE IS REAL INFRASTRUCTURE.** Not vaporware. 8 repos, MCP server on Glama, Sigstore/Rekor integration, EU AI Act scanner with agent client, dev.to content marketing. They're building the execution attestation layer the WG was missing.

## Metrics This Wave
- Tests: **247 pass**, 15 skip, 0 failures ✅ (stable)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **33** (2 new: desiorac reply + FransDevelopment spec review)
- External persons engaged: **6** (NEW: desiorac/ArkForge)
- WG Pipeline: **3 candidates** + **1 new prospect** (desiorac/ArkForge — execution attestation)
- Repo: 1 star, 1 fork
- GitHub: 54 views / 32 uniques (14-day), 3,940 clones / 516 uniques (14-day, 3.3x surge)
- Referrers: news.ycombinator.com (FIRST HN REFERRAL)
- PyPI: stable (~780/day baseline)
- Commits: 0 (engagement-only wave)
- Campaign 6: Goal 2 DONE, Goal 1 IMMINENT, Goal 3 PIPELINE ACTIVE
