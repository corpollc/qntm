# Wave 29 — The WG Gets a Home
Started: 2026-03-23T08:39:00Z
Campaign: 6 (Waves 29+) — Standard or Product?

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **CHAIRMAN UNBLOCKED ENTITY API.** Peter (@vessenes) posted Corpo staging entity at `api.corpo.llc/api/v1/entities/test-entity/verify` on APS#5. This is the P1 blocker from the last 5 waves — resolved by chairman action.
   - **haroldmalikfrimpong-ops CONFIRMED ENTITY API WORKING.** Already building `verify_agent_full(did)` — chains DID → AgentID certificate → Corpo entity verification. Moving faster than we can track.
   - **WG ENDORSED BY BOTH PARTNERS.** haroldmalikfrimpong-ops committed CA-issued identity, DID resolution, Python SDK, DID field support, framework integrations. qntm committed transport, QSP-1 spec, test vectors, echo bot, DID field. Waiting on aeoess.
   - **aeoess active but quiet on APS#5.** Last comment was Wave 27 timeframe. But committed relay/WebSocket tests (1122 tests, 302 suites). Building, not talking.
   - **232 tests pass.** Relay healthy. All green.

2. **Single biggest bottleneck?**
   - **The WG has no home.** I committed to creating a shared repo/directory for specs, test vectors, and DID resolution interface on A2A #1672. Both partners are waiting. Without a central location, the WG is just talk.

3. **Bottleneck category?**
   - Coordination infrastructure (code + specs)

4. **Evidence?**
   - Both partners committed to the WG on A2A #1672. haroldmalikfrimpong-ops is already building entity integration code. aeoess committed relay tests. They need a canonical place for shared specs, not scattered GitHub comments.

5. **Highest-impact action?**
   - Create the WG specs directory in corpollc/qntm with: QSP-1 spec, test vectors, WG README, entity verification interface. Then post links on A2A #1672.

6. **Customer conversation avoiding?**
   - The strategic direction question: standard vs product. Chairman's actions (entity API, @vessenes participating directly) strongly signal "standard" path. But no explicit ruling. I'll operate under "standard path" assumption and flag for confirmation.

7. **Manual work that teaches faster?**
   - Build the entity verification helper. Prove the DID → key → entity chain works in Python. Ship code, not specs.

8. **Pretending is progress?**
   - Creating a spec directory is necessary but not sufficient. The spec must be accurate and reflect what implementations actually do, not aspire to.

9. **Write down?**
   - WG spec structure, entity verification design, Campaign 6 goals.

10. **Escalation?**
    - **Strategic direction:** Chairman is acting on the standard/WG path (entity API, direct participation on APS#5, WG endorsement). Interpreting this as implicit approval for Campaign 6 as standard-track. Will confirm in next briefing.
    - **MCP marketplace:** 14th wave asking. Deprioritizing — the WG path may make this less relevant (framework maintainers integrate directly, not through marketplaces).

## Wave 29 Top 5 (force ranked)

1. **Create WG specs directory** — QSP-1 spec, test vectors, WG README with scope/membership/principles
2. **Build entity verification module** — `verify_entity(entity_id)` calling Corpo staging API
3. **Post WG spec links on A2A #1672** — fulfill the commitment
4. **Set Campaign 6 goals** (standard-track path)
5. **Update state, KPIs, truth register, wave log**

## Execution Log
