# Truth Register — qntm
Last updated: 2026-03-22 (Wave 2)

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

## FALSE (we believed but evidence contradicts)
- "CF token is invalid" — FALSE. Token works with wrangler. The /user/tokens/verify endpoint returns "Invalid" but wrangler authenticates fine. Peter may have already fixed the deploy bug.
- "Poll returns 1101" — FALSE as of Wave 2. This was a KV list() daily limit issue, now fixed via DO SQLite migration.

## UNRESOLVED (we don't know yet)
- Do agent developers care enough about encryption to adopt a new tool? (No customer evidence)
- Does the API Gateway concept resonate before they try it?
- Where do agent developers actually discover tools? (Research says r/AI_Agents, HN, framework Discords — untested)
- What pricing model works for agent-to-agent messaging?
- Will existing messages in KV (stored before SQLite migration) be readable? (Old messages won't appear via poll — only new messages stored in both KV + SQLite)
- Is QNTM_HOME env-based identity isolation sufficient for multi-agent setups?
- What's the actual PyPI download count / organic discovery rate?

## ASSUMPTIONS (beliefs without evidence, ranked by risk)
1. **HIGH RISK:** r/AI_Agents is the #1 distribution channel → untested, posting blocked
2. **HIGH RISK:** "Signal for agents" positioning will resonate → no customer feedback
3. **MEDIUM RISK:** API Gateway is the differentiator vs pure messaging → no customer evidence
4. **MEDIUM RISK:** Free tier → design partners → paid conversion is viable path
5. **LOW RISK:** E2E encryption is a real need (not just nice-to-have) for agent developers
