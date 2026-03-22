# Decision Memo: Build qntm MCP Server

## DECISION MEMO
- **Problem:** Distribution is the existential bottleneck. 16 waves, 0 customer contact. GitHub issue-based outreach has 0% response rate after 24+ hours. Need a new distribution channel.
- **Target customer:** AI agent developers using MCP-compatible tools (Claude Desktop, Cursor, OpenClaw, etc.)
- **Evidence:**
  - DeadDrop (yksanjo/deaddrop-v2) launched an encrypted agent messaging MCP server and got listed on LobeHub marketplace with 2 installs from zero marketing
  - MCP is the de facto standard for AI tool integration (Google, GitHub, Microsoft all ship MCP servers)
  - LobeHub and Smithery are active marketplaces where agent developers discover tools
  - 6 GitHub outreach efforts = 0 responses; MCP marketplace is a different, unblocked channel
  - Agent developers browsing MCP marketplaces ARE our exact target segment
- **Options considered:**
  1. Build MCP server (new distribution channel, within ALLOWED) ← CHOSEN
  2. More GitHub issues (proven low conversion, diminishing returns)
  3. Wait for PyPI approval (blocked for 11 waves)
  4. Build framework-specific integrations (LangChain/CrewAI — higher effort, narrower reach)
- **Recommended option:** Build qntm MCP server
- **Expected effect on primary metric:** Opens a new funnel: MCP marketplace → install → identity → conversation. If even 1% of MCP marketplace browsers try qntm, that's more activation than all GitHub outreach combined.
- **Cost/impact:** ~1 wave of development time. Optional dependency (mcp[cli]). No infrastructure changes.
- **Reversible or irreversible:** Reversible. It's a module that can be removed without affecting core functionality.
- **Confidence:** 0.7 — DeadDrop proves the pattern works. Unclear how much traffic MCP marketplaces drive.
- **DRI:** CEO (Founder)
- **Review date:** Wave 18 (check if MCP server generates installs/conversations)
- **Escalation needed?** Yes — marketplace listing may need approval if it counts as "public posting" under AUTONOMY.md

## Outcome
- Built and shipped in wave 16
- 9 tools, 2 resources, 1 prompt
- 14 tests, all 221 tests pass
- Committed dd8c3df, pushed to main
- Both READMEs updated with MCP section
- Full docs at docs/mcp-server.md
