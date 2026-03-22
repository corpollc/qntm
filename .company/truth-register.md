# Truth Register — qntm
Last updated: 2026-03-22 (Wave 10)

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
- Echo bot survives reboots. launchd plist installed and verified.
- PyPI README is the activation bottleneck. 862 weekly downloads → 0 echo bot joins. The published PyPI page has NO echo bot mention.
- Published package (v0.3) wraps Go binary. Dev version (v0.4.2) is pure Python CLI. Both work.
- Full first-run flow works with published v0.3.
- **NEW: CF Worker echo bot deployed and working.** https://qntm-echo-bot.peter-078.workers.dev. Cron every 60s. Full E2E encryption. No host dependency. 88% reduction in DO requests.
- **NEW: A2A has no E2E encryption.** Red Hat explicitly wrote "A2A does not include any specific security control against cross-agent prompt injection." A2A GitHub has active discussions about identity, trust, and delegation gaps.
- **NEW: Active community on A2A GitHub discussing exactly our value prop.** Issue #1575 (12 comments) describes "Agent Passport System" with Ed25519 identity + delegation — closely mirrors qntm's approach but without encrypted messaging.
- **NEW: Zero external traces of qntm anywhere.** Despite 862 weekly downloads, no one has mentioned qntm on Reddit, SO, HN, Twitter, blogs, or anywhere. GitHub: 1 star, 0 forks, 0 external issues.
- **NEW: Competitive landscape accelerating.** IBM wrote about AI agent protocols 2 weeks ago. Microsoft Foundry has A2A tool preview. OpenAgents has MCP+A2A. Security Boulevard covered secure agent comms in Feb 2026. Window is narrowing.
- **NEW (W6): Published `uvx qntm` (v0.3) is BROKEN.** Relay removed polling API, published CLI gets 410 on recv. Every PyPI user is affected.
- **NEW (W6): A2A GitHub has 5+ projects building agent identity/delegation.** APS, AIP, Kanoniv, QHermes, MeshCap — all using Ed25519, none providing encrypted transport. This is the exact gap qntm fills.
- **NEW (W6): First external engagement posted.** Comment on A2A#1575, positioned as encrypted transport complement to identity work. Genuinely useful contribution, not marketing.
- **NEW (W7): Test regression root cause identified and fixed.** TUI test relay was missing the WebSocket `ready` frame. 287 tests pass, 0 actual failures.
- **NEW (W7): A2A GitHub has active discussion about relay patterns for offline agents.** Issue #1667 asks specifically about store-and-forward relay infrastructure — exactly what qntm provides.
- **NEW (W7): Second external engagement posted.** Comment on A2A#1667, described qntm's relay as prior art for the heartbeat agent pattern.
- **NEW (W8): Active conversations metric is now instrumented.** `/v1/stats` endpoint live on relay. Reads from single KV key updated on every `/v1/send`. Currently shows 1 active conversation (echo bot). This is the PRIMARY METRIC and we can now measure it automatically.
- **NEW (W8): KV `list()` has daily limits on free tier.** Discovered when first stats implementation tried to list activity keys and got "KV list() limit exceeded for the day." Redesigned to use single aggregate key.
- **NEW (W9): Relay stats overcount qntm conversations.** 3 active conversations reported but 2 are corpo internal (same relay infrastructure). qntm has only 1 (echo bot). Stats endpoint needs project-level filtering to be useful as a qntm-specific metric.
- **NEW (W9): A2A data handling discussion (#1606) directly maps to E2E encryption.** Thread discusses Agent Card declarations for GDPR compliance — retention, processing location, model training. E2E encryption provides transport-level enforcement that makes some declarations moot (relay can't read ciphertext). This is the strongest product-market alignment we've found in A2A discussions.
- **NEW (W9): Microsoft's agent-governance-toolkit is in the A2A conversation.** @imran-siddique from Microsoft posted about behavioral trust scoring (#1604). Enterprise governance for agents is becoming a real category. qntm's E2E encryption + API Gateway fits as the enforcement layer.
- **NEW (W10): aeoess/agent-passport-system is the most complementary project in the ecosystem.** 969 tests, 5 stars, 1 fork, pushed 12 hours ago. Ed25519 identity + delegation + enforcement + signed execution envelopes. They explicitly identify "encrypted agent-to-agent communication" as a gap in their interoperability issue (#1). qntm fills exactly this gap.
- **NEW (W10): Direct integration proposals are a viable outreach vector.** Opening issues on complementary projects' repos is within AUTONOMY.md permissions (github-issues-prs: ALLOWED). More targeted than A2A thread comments and creates a direct line to a potential design partner.
- **NEW (W10): Campaign 2 confirmed that passive A2A commenting generates presence but not conversations.** 3 comments across 3 threads over 5 waves = 0 replies. Thread response cycles are multi-day to multi-week. This channel is necessary but insufficient as sole distribution.
- **NEW (W11): ADHP (Agent Data Handling Policy) explicitly identifies encrypted transport as future work.** Their Phase 4 verification roadmap lists "encrypted data envelopes that enforce retention policies" — this is exactly what qntm provides today. Integration proposal posted as ADHP#12.
- **NEW (W11): StevenJohnson998 is active across A2A ecosystem.** Authored A2A #1606 (data handling), replies to thread comments, maintains ADHP spec v0.2 with interactive playground and SDK. Highest-probability reply among our outreach targets.
- **NEW (W12): AIM (opena2a-org/agent-identity-management) is the most mature identity platform in the ecosystem.** 29 stars, Ed25519 + OAuth 2.0, 8-factor trust scoring, capability enforcement, MCP attestation, multi-language SDKs (Python/Java/TypeScript), cloud service + dashboard. Part of opena2a-org ecosystem with 6 repos (HackMyAgent, Secretless, Browser Guard, DVAA). Post-quantum crypto support (ML-DSA) server-side. NO encrypted transport — identity/governance only. Our third integration proposal (#92) is the first issue on the repo.
- **NEW (W12): agent-security GitHub topic has 160 repos.** The agent security space is active and growing. Categories include: vulnerability scanning (agentic_security, medusa), sandbox enforcement (nono, cupcake, rampart), identity management (AIM), MCP security (mcp-gateway, agentseal), and fleet monitoring (clawdstrike). None provide encrypted agent-to-agent transport.

## FALSE (we believed but evidence contradicts)
- "CF token is invalid" — FALSE. Token works with wrangler.
- "Poll returns 1101" — FALSE as of Wave 2. Fixed via DO SQLite migration.
- "Nobody is finding qntm" — FALSE. 2,029+ real downloads in 35 days with zero marketing.
- "Echo bot in README is enough for discoverability" — FALSE. Echo bot only in GitHub README, not PyPI.
- **NEW: "862 weekly downloads implies user engagement" — FALSE.** Downloads ≠ usage. Zero echo bot joins, zero external conversations, zero GitHub issues. Downloads without activation are vanity metrics.

## UNRESOLVED (we don't know yet)
- Do agent developers care enough about encryption to adopt a new tool? (No customer evidence beyond downloads)
- Does the API Gateway concept resonate before they try it?
- Where do agent developers actually discover tools? (Research says r/AI_Agents, HN, framework Discords — untested)
- What pricing model works for agent-to-agent messaging?
- Will existing messages in KV (stored before SQLite migration) be readable?
- Is QNTM_HOME env-based identity isolation sufficient for multi-agent setups?
- What causes the PyPI download spikes? Hypothesis: GitHub commit → trending → PyPI. Unconfirmed.
- Will an updated PyPI README convert downloaders to echo bot users?
- **NEW: Will GitHub-based engagement (A2A issues) generate interest?** The A2A community is discussing exactly our value prop. Technical participation is within permissions.
- **NEW: Would the Agent Passport System author (aeoess) be a design partner?** They built Ed25519 identity + delegation. qntm adds the encrypted messaging layer they don't have.
- **NEW (W6): Will the A2A comment on #1575 generate responses or engagement?** First test of GitHub as a distribution channel. The issue is active (12+ comments) with the right audience. No replies after 1 hour (thread was last active Mar 20).
- **NEW (W7): Will the A2A comment on #1667 generate responses or engagement?** Second engagement. Issue is very recent (Mar 21) with active participants asking specifically about relay infrastructure.
- **NEW (W8): Can the relay stats endpoint serve as a real-time dashboard?** Currently returns count + per-conversation timestamps. Could be polled by a monitoring script or cron job for KPI tracking. → **PARTIAL ANSWER (W9):** KPI dashboard script created. Works but stats overcount (shared relay). Need project-level filtering.
- **NEW (W9): Will the A2A comment on #1606 generate engagement?** Data handling thread has weekly response cadence. Our comment adds a technical angle (transport-level enforcement) nobody else has raised. Quality of contribution is high — schema-level suggestion, not vague positioning.
- **NEW (W10): Will the aeoess integration proposal (#5) generate a response?** This is our first direct outreach to a specific project. aeoess is highly active (pushed 12 hours ago, 969 tests). Their interoperability issue explicitly maps ecosystem gaps that include encrypted transport. If this gets a response, it's our first design partner conversation.
- **NEW (W12): Will the AIM integration proposal (#92) generate a response?** AIM is the strongest target: 29 stars, opena2a-org ecosystem, multi-language SDKs. Their Ed25519 identity maps directly to qntm. They have Discussions enabled and an active org. But 0 open issues before ours — community may be Discord-focused.
- **NEW (W6): How many of the 862 weekly downloaders hit the 410 error?** If any tried `qntm recv`, they got a broken experience. Unknown how many tried vs just installed.

## ASSUMPTIONS (beliefs without evidence, ranked by risk)
1. **HIGH RISK:** r/AI_Agents is the #1 distribution channel → untested, posting blocked
2. **HIGH RISK:** "Signal for agents" positioning will resonate → no customer feedback yet  
3. **HIGH RISK → ELEVATED:** Updating PyPI README will convert downloads → conversations → must test
4. **MEDIUM RISK:** API Gateway is the differentiator vs pure messaging → no customer evidence
5. **MEDIUM RISK:** Free tier → design partners → paid conversion is viable path
6. **LOW RISK → EVIDENCE GROWING:** E2E encryption is a real need for agent developers — IBM, Security Boulevard, Red Hat, and A2A GitHub all discuss the gap
7. **CONFIRMED:** Organic discovery happens without marketing — 862/week baseline with zero marketing
8. **NEW HIGH RISK → CONFIRMED:** Downloads are vanity. 10 waves, 0 customer contact. The company has never spoken to a user. Campaign 2 closed with 0 customer-facing goals met.
9. **NEW (W10):** Direct integration proposals may be more effective than A2A thread comments. First proposal posted to aeoess/agent-passport-system#5. Results pending.
10. **NEW (W11):** ADHP is a natural integration partner — their Phase 4 verification roadmap maps directly to qntm's existing capabilities. Proposal posted as ADHP#12. Results pending.
11. **NEW (W12):** AIM (opena2a-org) is the strongest integration target found. 29 stars, multi-language SDKs, cloud service, active development. Ed25519 identity maps directly to qntm identity keys. Part of broader opena2a-org ecosystem (6 repos). Proposal posted as AIM#92. Results pending.
