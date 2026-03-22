# Wave 17 — PyPI P0 Resolved + MCP Distribution Push
Started: 2026-03-22T19:34:00Z
Campaign: 4 (Waves 16-20) — Convert or Pivot

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - **P0 RESOLVED**: Peter published qntm to PyPI — v0.4.0 through v0.4.20 are live. The 11-wave escalation is OVER. `uvx qntm` installs a working CLI with WebSocket support. `pip install 'qntm[mcp]'` gets the MCP server.
   - Peter committed 2 changes: OpenClaw qntm routing fix (session key honoring) + v0.4.20 release.
   - Relay active conversations: 8 (stable from wave 16).
   - All 6 engagements: still 0 replies (Sunday — expected).
   - A2A#1575: 13 comments total, no replies to us.
   - GitHub: 1 star, 0 forks, 0 external issues (unchanged).

2. **Single biggest bottleneck?**
   - **Distribution via MCP marketplaces.** PyPI is working. MCP server is built and on PyPI. The only thing between us and the #1 new distribution channel is AUTONOMY.md ambiguity on marketplace listings.

3. **Bottleneck category?**
   - Distribution. Specifically: getting listed where agent developers discover MCP tools.

4. **Evidence?**
   - DeadDrop: 2 LobeHub installs with zero marketing (vs our 0 installs from 6 GitHub issues).
   - LobeHub has 14,000+ MCP server listings — this is where agent developers look.
   - PyPI 0.4.20 includes MCP server — we're marketplace-ready.
   - GitHub outreach: 6 engagements, 0 responses in 24h. Channel is saturated.

5. **Highest-impact action?**
   - Prepare MCP marketplace listing materials (LobeHub manifest, Smithery config) so we're ready the instant approval comes. Then: find distribution channels that DON'T require "public posting" approval.

6. **Customer conversation avoiding?**
   - All of them. 17 waves, 0 customer conversations. MCP marketplace would at least create a self-service discovery path.

7. **Manual work that teaches faster?**
   - Research how LobeHub and Smithery listings actually work (PR process, auto-indexing, manifest format). Understand the submission mechanics.

8. **Pretending-is-progress?**
   - More GitHub issues without a new channel would be repeating wave 10-16 patterns.

9. **Write down today?**
   - PyPI P0 resolution. MCP listing preparation. Wave 17 log.

10. **Escalation needed?**
    - MCP marketplace listing ruling (is it "public posting"?). Already in briefing.

## Wave 17 Top 5 (force ranked)

1. **Chairman briefing** ✅ — Sent via qntm
2. **Prepare MCP marketplace listing materials** — LobeHub manifest, Smithery smithery.yaml, README optimized for marketplace
3. **Research Smithery auto-indexing** — Does Smithery auto-index PyPI packages? If so, we might already be listed.
4. **Update all install instructions** — PyPI is working again. Switch everything back from git install to `pip install qntm`.
5. **Investigate relay activity spike** — Are any of the 8 conversations external?

## Execution Log

### #1 — Chairman Briefing ✅
Sent 2-page briefing to Pepper via qntm (conv 2d0d). Key points: P0 resolved, MCP marketplace ruling needed, 0 engagement responses.

### #2 — Install Instructions Updated ✅
Commit eed1f60: switched all install instructions from git install workaround back to `pip install qntm` / `uvx qntm` now that v0.4.20 is live on PyPI.

### #3 — MCP Marketplace Listing Materials ✅
Prepared two marketplace listing files at `.company/marketplace/`:
- `lobehub-listing.json` — LobeHub manifest with tags, description, config
- `smithery.yaml` — Smithery MCP server config with stdio transport, configSchema for configDir and relayUrl

### #4 — Smithery Publishing Research ✅
Smithery supports two publishing paths:
1. **CLI publish:** `smithery mcp publish <url> -n <name>` — publishes to registry. Requires `smithery auth login`.
2. **Web UI:** https://smithery.ai/new — sign in and submit via form.
3. **API:** `PUT /servers/{namespace}/{server}` — programmatic creation.
Smithery does NOT auto-index from PyPI. We must actively submit. This requires creating an account and namespace.
**Key finding:** Smithery's `mcp publish` takes a URL, not a package name. Our server runs via `python -m qntm.mcp` (stdio), so listing requires proper smithery.yaml in the repo.

### #5 — Relay Activity Investigation ✅
8 active conversations on relay. Analysis:
- `48055654` — Echo bot (known)
- `95de8270` — Pepper original conversation (known)
- `2d0d3ec2` — Pepper CEO channel (known)
- `128fea2c`, `be96bcc5`, `0050a49f`, `755f317a`, `988386e3` — **5 unknown conversations**

The 5 unknown conversations are NOT qntm-identity conversations (not in our config). They are corpo internal traffic on the shared relay infrastructure. The NanoClaw integration (`nanoclaw-qntm/`) tracks a separate conversation `ac4b77a0` which isn't in relay stats at all.

**Conclusion:** 0 external users. All 8 relay conversations are internal (qntm team + corpo).

### #6 — NanoClaw Integration Discovery ✅
**MAJOR:** Peter committed a NanoClaw qntm integration plan (`docs/nanoclaw-qntm-plan.md`, commit cc1af17) AND built a working implementation scaffold (`nanoclaw-qntm/`). This includes:
- Full TypeScript channel implementation (QntmChannel class)
- WebSocket subscriptions for inbound messages
- Cursor persistence for reliable delivery
- Self-message suppression
- JID format: `qntm:<conv-id>`
- Tests passing

This means Peter is actively investing in qntm as a NanoClaw channel — the same distribution path that made Telegram/WhatsApp/Discord work in NanoClaw. This is potentially a much bigger distribution channel than MCP marketplaces because it brings qntm to every NanoClaw user.

### #7 — Tests Verified ✅
221 tests pass (207 python-dist + 14 MCP server). 0 failures.

## Metrics This Wave
- Tests: 221 pass ✅
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅
- Active conversations (7-day relay): 8 (all internal)
- qntm-only active conversations: 1 (echo bot)
- External engagements: **6** — **0 replies** (Sunday, Monday is test)
- Direct integration proposals: **3** — **0 replies**
- PyPI: v0.4.20 LIVE ✅ (P0 RESOLVED)
- PyPI downloads: 26/day, 862/week, 1,625/month
- GitHub: 1 star, 0 forks, 0 external issues
- **Install path:** `pip install qntm` / `uvx qntm` — WORKING ✅
- **MCP install path:** `pip install 'qntm[mcp]'` — WORKING ✅
- **NanoClaw integration:** scaffold built, tests passing (Peter-initiated)
- **MCP marketplace listings:** materials prepared, submission BLOCKED (AUTONOMY ruling pending)
- **Total waves:** 17
- **Campaigns completed:** 3 (Campaign 4 active)

## Assessment

This wave's biggest signal isn't the MCP marketplace prep — it's Peter building the NanoClaw integration. The chairman is investing engineering time into making qntm a first-class messaging channel for NanoClaw. This is:

1. **Product validation from the chairman himself** — he's using qntm, building on it
2. **A distribution channel** — NanoClaw users get qntm as a built-in option
3. **Dogfooding** — the best way to find rough edges

Combined with the P0 PyPI resolution, qntm's install story is now clean: `pip install qntm` works, MCP server included, NanoClaw integration in progress.

**Remaining bottleneck:** Still zero external users. MCP marketplace listing and NanoClaw launch are the two distribution plays. Both need to ship this week.

**Next priorities:**
1. Get MCP marketplace ruling from chairman (is it "public posting"?)
2. Support NanoClaw integration if chairman needs help
3. Monday engagement check — are any of the 6 GitHub outreach getting responses?
4. Prepare MCP demo content for marketplace description
