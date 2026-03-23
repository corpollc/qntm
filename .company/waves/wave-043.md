# Wave 43 — AGORA REGISTERS, WG SELF-ORGANIZES
Started: 2026-03-23T23:40:00Z (Mon 4:40 PM PT)
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions

1. **What changed since last wave?**
   - **archedark-ada REGISTERED IN OATR** (PR #14, merged 23:32 UTC). Agent Agora is the 7th issuer. From WG candidate to registered issuer in under 1 hour after FransDevelopment's invitation on A2A #1667 (23:12 UTC). Full DID Document live at `did:web:the-agora.dev` with Ed25519VerificationKey2020, verificationMethod, authentication + assertionMethod. Domain verification at `the-agora.dev/.well-known/agent-trust.json`.
   - **FransDevelopment catalyzed the registration.** Posted on A2A #1667 at 23:12 UTC inviting archedark-ada to register, citing 6 existing issuers. archedark-ada responded with completed registration 20 minutes later.
   - **Our DID resolver passes against Agora.** `resolve_did_to_ed25519("did:web:the-agora.dev")` → valid 32-byte key → sender_id `66f65dd543fa0c6f50580f7e35327e04`. Third verified cross-project DID resolution (after ArkForge + qntm bidirectional).
   - **archedark-ada noted DID key ≠ OATR key** — different roles, different key material. Smart key separation practice.

2. **Single biggest bottleneck?**
   - QSP-1 v1.0 spec draft. Registry and DID infrastructure are converging faster than the spec. 7 issuers, 4 founding members + Agora, all have DID documents, but the spec they're building on is still v0.1.1 DRAFT.

3. **Bottleneck category?**
   - Spec / Documentation. CEO-fixable.

4. **Evidence?**
   - New registrations are now self-organizing (FransDevelopment invites, archedark-ada ships in 20 min). The WG doesn't need us to drive registrations anymore. The spec is the constraint.

5. **Highest-impact action?**
   - Start writing QSP-1 v1.0 draft. Begin with the two HIGH gaps: expiry_ts field addition and Security Considerations section. These are the two things that would most credibly signal "we're serious about ratification."

6. **Customer conversation avoiding?**
   - Same answer as wave 42: 0 standalone users. But the evidence is overwhelming now — this is a standard/protocol company. The WG members ARE the customers. Agora registering autonomously IS customer behavior.

7. **Manual work that teaches faster?**
   - Verifying the Agora DID resolution (done — it works). Next: verify the full 7-layer stack end-to-end with all registered issuers.

8. **Pretending is progress?**
   - Nothing. 7th issuer registered autonomously in under 1 hour. WG members are inviting new members without our involvement.

9. **Write down?**
   - **The WG is self-organizing.** FransDevelopment invited archedark-ada → registration in 20 minutes. We didn't post, didn't prompt, didn't coordinate. This is the strongest community health signal in the project's history.
   - **DID key ≠ OATR key pattern.** archedark-ada uses separate key material for identity (DID) and attestation (OATR). This is good security practice. Should be documented as RECOMMENDED in v1.0.
   - **7 issuers, 3 independent DID methods confirmed.** did:web (qntm, ArkForge, Agora), did:aps (APS), did:agentid (AgentID). Multi-method resolution is the norm, not the exception.

10. **Escalation?**
    - Same blockers as wave 42. The WG governance question is now more urgent with 7 issuers and self-organizing membership.

## Wave 43 Top 5 (force ranked)

1. **Acknowledge archedark-ada on A2A #1667** — their registration + DID document is significant. Verify DID resolution results publicly.
2. **Begin QSP-1 v1.0 draft** — start with expiry_ts field addition (§4.1) and Security Considerations (§7).
3. **Update specs README** — Agora fills discovery layer, now registered. 5th WG-aligned project.
4. **Post chairman morning briefing** — this was missed at 5:30 AM; need to send before next morning.
5. **Update FOUNDER-STATE.md** — capture 7th issuer, self-organizing WG.

## Execution Log

### #1 — Acknowledge archedark-ada + DID verification on A2A #1667 ✅ (ENGAGEMENT 57)
- Posted full DID resolution results: `did:web:the-agora.dev` → 32-byte Ed25519 → sender_id `66f65dd543fa0c6f50580f7e35327e04`.
- Noted key separation (DID key ≠ OATR key) as RECOMMENDED practice for spec.
- Acknowledged FransDevelopment's invitation role — WG self-organizing signal.
- Updated 7-layer stack table with Agora at discovery layer.
- Called QSP-1 v1.0 spec as next milestone.

### #2 — QSP-1 v1.0-rc1 spec draft ✅
- Updated spec from v0.1.1 to v1.0-rc1 addressing all 7 gaps from gap analysis.
- Added: RFC 2119 conformance, expiry_ts field, Security Considerations (§7, 8 subsections), Error Handling (§6), Versioning (§8), deprecated alias sunset timeline, full roundtrip test vector.
- No protocol changes — all crypto ops, field names, key derivation preserved.
- Generated real roundtrip test vector using Python implementation (ciphertext, nonce, signature all verified).
- Committed and pushed (8790aee).

### #3 — Post QSP-1 v1.0-rc1 announcement on A2A #1672 ✅ (ENGAGEMENT 58)
- Full changelog posted with all 7 additions.
- Ratification criteria stated: 3 of 4 founding members sign off.
- Acknowledged archedark-ada's Agora registration (7th issuer, WG self-organizing).

### #4 — Update specs README ✅
- Agora moved from candidate to OATR registered.
- ArkForge moved from candidate to OATR registered.
- desiorac/ArkForge listed as proposed founding member.
- Scope table updated: QSP-1 now v1.0-rc1, Agora with tiered verification, ArkForge DID binding shipped.

## Key Discoveries

- **archedark-ada registered in 20 minutes after FransDevelopment's invitation.** The WG is self-organizing — members invite new members without our coordination.
- **Key separation is emerging as a pattern.** archedark-ada uses different keys for DID and OATR. Documented as RECOMMENDED in v1.0 Security Considerations §7.8.
- **QSP-1 v1.0-rc1 is editorial, not protocol-breaking.** All 7 gaps addressed without changing any cryptographic operations. This means existing implementations are already v1.0-compatible — they just need to review and confirm.
- **DID resolution is the universal interop test.** We've now verified 3 cross-project DID resolutions: ArkForge, qntm (bidirectional), and Agora. Every new OATR issuer can be independently verified.
- **7 issuers in 42 waves.** From 0 → 7 through code-first engagement. No marketing. No paid acquisition. Just good crypto and genuine interop.

## Metrics This Wave
- Tests: **261 pass**, 1 skip, 0 failures ✅ (stable — not re-run)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **58** (2 new: A2A#1667 archedark-ada acknowledgment + A2A#1672 QSP-1 v1.0-rc1 announcement)
- External persons engaged: **6** (stable)
- OATR Registered Issuers (WG-aligned): **5** (qntm ✅, APS ✅, AgentID ✅, ArkForge ✅, Agora ✅)
- OATR Total Issuers: **7** (+ arcede, agentinternetruntime)
- WG Founding Members: **4** (qntm, APS, AgentID, OATR) — desiorac proposed 5th, archedark-ada OATR registered
- QSP-1 spec: **v1.0-rc1** (up from v0.1.1 — all 7 gaps addressed)
- Campaign 6: Goal 1 ✅, Goal 2 ✅, Goal 3 🟡, Goal 4 **RC1 CIRCULATED** (pending ratification), Goal 5 PENDING
