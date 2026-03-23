# Wave 39 — SPEC ALIGNMENT + DID INFRASTRUCTURE
Started: 2026-03-23T18:40:00Z (Mon 11:40 AM PT)
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions

1. **What changed since last wave?**
   - FransDevelopment merged Spec 10 (PR #3) and immediately opened issue #4: `expiry_ts` enforcement gap between spec and qntm relay. Proposed graceful degradation (option c). This is WG-member-grade behavior — identifying real incompatibilities and proposing solutions.
   - desiorac ran reverse-direction test: `did:web:qntm.corpo.llc` returns 404. We don't publish a DID Document. This is a real gap — we're asking others to dogfood specs we don't implement ourselves.
   - desiorac clarified infrastructure: proxy DID is live (`did:web:trust.arkforge.tech`), per-agent DIDs are registration-time binding (proposed). Two-tier architecture.

2. **Single biggest bottleneck?**
   - **Credibility gap: we don't implement our own specs.** We built the DID resolver, tested it against everyone else's DID Documents, but don't publish one ourselves. This undermines the WG's code-first principle.

3. **Bottleneck category?**
   - Product / Infrastructure. This one the CEO can fix directly.

4. **Evidence?**
   - desiorac's 404 on `did:web:qntm.corpo.llc`. FransDevelopment's #4 showing spec-vs-implementation gap.

5. **Highest-impact action?**
   - Reply to OATR #4 (expiry_ts alignment) — validates FransDevelopment's WG-grade work and keeps spec convergence moving.
   - Reply to desiorac on OATR#2 — acknowledge the 404 and commit to publishing.

6. **Customer conversation avoiding?**
   - Same as always: anyone outside the WG ecosystem.

7. **Manual work that teaches faster?**
   - Publishing our own DID Document would teach us about did:web serving gaps.

8. **Pretending is progress?**
   - Proposing full-stack POCs without publishing our own DID is exactly this. Ship the basics first.

9. **Write down?**
   - FransDevelopment is now WG-member-grade (opened alignment issue, proposed resolution, merged spec)
   - qntm has a credibility gap: no did:web:qntm.corpo.llc DID Document published
   - expiry_ts needs relay-side implementation (graceful degradation path agreed)

10. **Escalation?**
    - Same 5 blockers (protocol vs product, MCP marketplace, CF KV, public posting, WG governance).
    - NEW: Publishing `did:web:qntm.corpo.llc` may require DNS/worker setup for the domain — checking if relay worker can serve it.

## Wave 39 Top 5 (force ranked)

1. **Reply to FransDevelopment OATR #4** — agree with graceful degradation, commit to relay-side implementation
2. **Reply to desiorac on OATR #2** — acknowledge 404, commit to DID publishing, validate two-tier architecture
3. **Investigate + publish `did:web:qntm.corpo.llc` DID Document** — close the credibility gap
4. **Implement expiry_ts relay-side enforcement** — relay checks field when present, falls back to seq windowing
5. **Update state + wave log**

## Execution Log

### #1 — Reply to OATR #4 (expiry_ts alignment)

### #2 — Reply to desiorac on OATR #2

### #3 — Investigate DID publishing infrastructure

### #4 — Relay expiry_ts implementation

### #5 — State updates
