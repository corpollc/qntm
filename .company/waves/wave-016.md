# Wave 16 — MCP Server Build + Competitive Intelligence
Started: 2026-03-22T18:36:00Z
Campaign: 4 (Waves 16-20) — Convert or Pivot

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - 1 hour since wave 15.
   - Relay active conversations jumped from 4 to 8 — 4 new conversations. Most likely corpo internal (shared relay), but a notable signal.
   - All 6 engagements: 0 replies, 0 reactions (Sunday — expected).
   - NEW COMPETITOR DISCOVERED: DeadDrop (yksanjo/deaddrop-v2) — MCP server for encrypted AI agent messaging, listed on LobeHub. 2 installs, very early, but proves the MCP-as-distribution thesis.
   - GitHub: 1 star, 0 forks, 0 external issues (unchanged).
   - Tests: 207 pass. Relay: healthy. Echo bot: operational.

2. **Single biggest bottleneck?**
   - **Distribution.** Still. But with a new angle: MCP servers have distribution channels (LobeHub, Smithery, Claude Desktop) that GitHub issues don't.

3. **Bottleneck category?**
   - Distribution. But now there's an actionable fix within ALLOWED permissions: build an MCP server and get listed on marketplaces.

4. **Evidence?**
   - DeadDrop is on LobeHub marketplace with 2 installs from zero marketing. That's 2 more installs from that channel than we've gotten from 6 GitHub outreach efforts.
   - MCP is the de facto standard for AI tool integration (Google, GitHub, Microsoft all have MCP servers now).
   - Agent developers browsing MCP marketplaces ARE our target segment.

5. **Highest-impact action?**
   - Build a qntm MCP server. This is the first new distribution channel in 16 waves that's (a) within ALLOWED permissions, (b) goes directly to our target audience, and (c) has proof of concept (DeadDrop).

6. **Customer conversation avoiding?**
   - All of them. An MCP server at least puts us where developers discover tools.

7. **Manual work that teaches faster?**
   - Looking at DeadDrop's implementation teaches us the MCP integration pattern. Then build ours.

8. **Pretending-is-progress?**
   - More GitHub issues without MCP distribution would be repeating a low-conversion pattern.

9. **Write down today?**
   - Competitive intel on DeadDrop. MCP server design decision. Wave 16 log.

10. **Escalation needed?**
    - Same P0s (PyPI, public posting). New P1: MCP marketplace listing approval may be needed.

## Wave 16 Top 5 (force ranked)

1. **Chairman briefing** ✅ — Sent via qntm
2. **Build qntm MCP server** — The #1 priority. New distribution channel.
3. **Competitive deep-dive on DeadDrop** — Understand their approach, our differentiation
4. **Design decision memo: MCP server scope** — What tools to expose
5. **Update state + truth register**

## Execution Log

### #1 — Chairman Briefing ✅
Sent 2-page briefing to Pepper via qntm (conv 2d0d). Includes DeadDrop competitive intel and MCP server as top priority.

### #2 — Competitive Analysis: DeadDrop ✅
- **DeadDrop** (yksanjo/deaddrop-v2): Zero-knowledge agent mailbox with Redis Streams, NaCl encryption, and MCP integration
- GitHub repo exists but was 404 at time of check (may be private/renamed)
- Listed on LobeHub marketplace with 2 installs
- Uses Redis for storage (vs our Cloudflare Durable Objects)
- NaCl encryption (vs our XChaCha20-Poly1305 + Ed25519)
- Key difference: DeadDrop is point-to-point mailbox, qntm has persistent conversations + API Gateway
- **Our advantages:** More mature protocol (QSP v1.1), 221 tests, WebSocket subscriptions, API Gateway (m-of-n approval), groups, governance, announcements
- **Their advantage:** Already on LobeHub marketplace. MCP-native distribution.
- **Conclusion:** Build our own MCP server to compete on the same channel, then differentiate on protocol depth.

### #3 — qntm MCP Server ✅
- Built complete MCP server at `python-dist/src/qntm/mcp_server.py`
- **9 tools:** identity_generate, identity_show, conversation_create, conversation_join, conversation_list, send_message, receive_messages, conversation_history, protocol_info
- **2 resources:** qntm://identity, qntm://conversations
- **1 prompt:** setup_agent_messaging
- **Entry points:** `python -m qntm.mcp` or `qntm-mcp` console script
- **Optional dependency:** `pip install 'qntm[mcp]'`
- **14 tests written and passing**
- **All 221 tests pass** (207 existing + 14 MCP)
- **Committed:** 64cbbae (MCP server) + dd8c3df (README updates)
- **Both pushed to main**
- Full docs at docs/mcp-server.md with Claude Desktop and Cursor config examples

### #4 — Decision Memo ✅
Written at `.company/decisions/2026-03-22-mcp-server.md`

### #5 — State Updates ✅
- FOUNDER-STATE.md updated
- Truth register updated with 3 new entries
- Wave log completed
- KPIs appended

## Metrics This Wave
- Tests: 221 pass (207 python-dist + 14 MCP server) ✅
- Echo bot: OPERATIONAL ✅
- Relay: OPERATIONAL ✅
- Active conversations (7-day relay): 8 (up from 4)
- qntm-only active conversations: 1 (echo bot)
- External engagements: **6** (unchanged) — 0 replies
- Direct integration proposals: **3** (unchanged) — 0 replies
- PyPI downloads: 26/day, 862/week, 1,625/month
- Published CLI: **BROKEN** (workaround: git install)
- GitHub: 1 star, 0 forks, 0 external issues
- **Code shipped:** MCP server (64cbbae + dd8c3df) — 9 tools, 2 resources, 1 prompt
- **Competitors discovered:** DeadDrop (LobeHub MCP server, 2 installs)
- **Total waves:** 16
- **Campaigns completed:** 3 (Campaign 4 active)

## Assessment

MCP server is the first new distribution channel in 16 waves. Unlike GitHub issue comments (proven 0% response rate in <24h), MCP marketplaces:
1. Put us where agent developers actively browse for tools
2. Provide a self-service install path (no human response needed)
3. Compete directly with DeadDrop on the same channel

**Next priority:** Get listed on LobeHub/Smithery (may need AUTONOMY approval), then monitor MCP + engagement channels Monday.
