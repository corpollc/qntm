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

## Campaign 6 Goals — "Standard or Product?" (Waves 29-34)
**Theme:** Lean into the standard path. Build the WG infrastructure. Ship specs and tools that make qntm the transport layer every agent identity project uses.

**Strategic assumption:** Chairman's actions (entity API, direct participation, WG endorsement) signal "standard" path. This campaign tests whether that's correct by measuring whether WG artifacts attract new members.

1. **WG shared repo/specs used by both partners** — at least 1 PR or issue from a non-qntm member on the specs directory
2. **Entity verification integration complete** — aeoess or haroldmalikfrimpong-ops ships code calling Corpo entity API through qntm's interface
3. **One new WG member** — someone new ships compatible code (from A2A ecosystem, not existing partners)
4. **QSP-1 spec ratified at v1.0** — all three implementations agree on field names, crypto ops, verification rules
5. **Chairman strategic direction confirmed** — explicit ruling on standard vs product path

## Execution Log

### #1 — Created WG specs directory ✅
- `specs/` at repo root: README (members, principles, scope), 3 spec docs, 3 test vector files
- QSP-1 envelope v0.1.1, DID resolution interface v0.1, entity verification interface v0.1
- Test vectors: 5 Ed25519→X25519, HKDF derivation, entity API format
- Commit f4f2f87, pushed to main

### #2 — Built entity verification module ✅
- `entity.py`: `verify_entity()`, `verify_sender_entity()`, `EntityVerification` dataclass
- Full chain: DID → resolve key → verify sender key ID → verify Corpo entity
- 8 tests with mock HTTP server (active, suspended, dissolved, not found, key mismatch, full chain)
- 240 total tests pass (up from 232)

### #3 — Posted WG spec links on A2A #1672 ✅
- https://github.com/a2aproject/A2A/issues/1672#issuecomment-4108942690
- Linked all specs, test vectors, integration infrastructure

### #4 — Posted entity module on APS#5 ✅
- https://github.com/aeoess/agent-passport-system/issues/5#issuecomment-4108943717
- Code example for both partners, integration guidance

### #5 — Campaign 6 goals set ✅ (see above)

## Metrics This Wave
- Tests: 240 pass, 0 failures ✅ (up from 232, +8 entity tests)
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅ (16 active conversations)
- External engagements: **22** (2 new: WG specs + entity module)
- External PRs: 1 merged
- GitHub traffic: ATH on March 22 (22 uniques)
- Campaign 6: LAUNCHED (standard-track)
- New code: entity.py + test_entity.py + specs/ directory (835 lines)
- Corpo staging API: LIVE and verified
