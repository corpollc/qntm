# Truth Register — qntm
Last updated: 2026-03-22 (Wave 4)

## TRUE (we have evidence)
- TTFM is 1.2 seconds (measured wave 1) — crushes <10s target
- E2E encryption works: send + recv verified end-to-end with JSON output
- Relay is fully operational (poll fixed wave 2, healthz OK, send OK, recv OK)
- 465 tests green across all suites (client 193, UI 43, TUI 12, integration 217)
- CF deploy works (token valid via wrangler despite verify endpoint returning false)
- Agent developers ARE asking about agent-to-agent encrypted comms (Reddit threads found in research)
- At least one competitor (claweb.ai) is already in market, posting in r/AI_Agents
- Google A2A launched but has NO encryption focus
- CLI produces JSON by default — good for LLM/agent integration
- Organic pull exists. 823 real (without-mirrors) PyPI downloads on March 20 with ZERO marketing or public posting.
- PyPI spikes correlate with GitHub commit activity. Feb 15 (353), Feb 27 (234), Mar 10 (229), Mar 20 (823) — all align with commit bursts.
- Echo bot works. Full round-trip: user sends → bot decrypts → bot echoes encrypted → user receives. E2E verified.
- Activation path exists. 3 commands from install to seeing encryption work: identity generate → convo join → send → recv echo.
- **NEW: Echo bot survives reboots.** launchd plist installed and verified. Auto-restarts on crash.
- **NEW: PyPI README is the activation bottleneck.** 862 weekly downloads → 0 echo bot joins. The published PyPI page has a bare-bones README with NO echo bot mention, NO value prop. Users who `pip install qntm` or `uvx qntm` never discover the demo.
- **NEW: Published package (v0.3) wraps Go binary.** Dev version (v0.4.2) is pure Python CLI. Both work but are different codebases. The PyPI README belongs to the Python package.
- **NEW: Full first-run flow works with published v0.3.** Tested: identity generate → convo join → send → recv echo. All 4 commands succeed with the Go binary.

## FALSE (we believed but evidence contradicts)
- "CF token is invalid" — FALSE. Token works with wrangler.
- "Poll returns 1101" — FALSE as of Wave 2. Fixed via DO SQLite migration.
- "Nobody is finding qntm" — FALSE. 2,029+ real downloads in 35 days with zero marketing.
- **NEW: "Echo bot in README is enough for discoverability" — FALSE.** The echo bot is only mentioned in the GitHub README, not the PyPI README. Most downloaders come from PyPI and never see it.

## UNRESOLVED (we don't know yet)
- Do agent developers care enough about encryption to adopt a new tool? (No customer evidence beyond downloads)
- Does the API Gateway concept resonate before they try it?
- Where do agent developers actually discover tools? (Research says r/AI_Agents, HN, framework Discords — untested)
- What pricing model works for agent-to-agent messaging?
- Will existing messages in KV (stored before SQLite migration) be readable? (Old messages won't appear via poll)
- Is QNTM_HOME env-based identity isolation sufficient for multi-agent setups?
- What causes the PyPI download spikes? Best hypothesis: GitHub commit activity → GitHub trending/search → PyPI installs. But unconfirmed.
- **UPDATED: What happens after people download?** 862 weekly downloads → 0 echo bot joins. Now we know the PyPI README is the gap. New question: will an updated PyPI README convert downloaders to echo bot users?

## ASSUMPTIONS (beliefs without evidence, ranked by risk)
1. **HIGH RISK:** r/AI_Agents is the #1 distribution channel → untested, posting blocked
2. **HIGH RISK:** "Signal for agents" positioning will resonate → no customer feedback yet
3. **HIGH RISK → ELEVATED:** Updating PyPI README will convert downloads → conversations → must test with next release
4. **MEDIUM RISK:** API Gateway is the differentiator vs pure messaging → no customer evidence
5. **MEDIUM RISK:** Free tier → design partners → paid conversion is viable path
6. **LOW RISK:** E2E encryption is a real need (not just nice-to-have) for agent developers
7. **CONFIRMED:** Organic discovery happens without marketing — 862/week baseline with zero marketing
