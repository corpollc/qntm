# CMO Distribution Report — Wave 5
**Date:** 2026-03-21  
**Author:** CMO (Chief Marketing Officer)  
**Directive:** "Distribution is existential. Figure it out."

---

## Executive Summary

qntm occupies a unique intersection: **encrypted messaging × AI agent coordination × group-approved API execution**. No competitor combines all three. The API Gateway with m-of-n cryptographic approvals is the wedge. Distribution strategy should target builders who already feel the pain of giving agents access to production APIs without guardrails. The fastest path to users is developer communities already building multi-agent systems — they need this today and have nothing good.

---

## 1. Target Customer Profiles

### Profile 1: The AI Agent Builder (Individual / Small Team)
- **Who:** Software engineer or ML engineer, 25–40, building agent-based products or internal tools
- **Title:** "AI Engineer," "ML Engineer," "Founding Engineer" at a seed-to-Series-A startup (2–20 people)
- **Daily tools:** VS Code/Cursor, Python, LangGraph/CrewAI/AutoGen, OpenAI/Anthropic APIs, GitHub, Slack, Discord
- **Pain point:** Their agent calls Stripe/Twilio/GitHub APIs via hardcoded tokens. No approval flow. One prompt injection = unauthorized charges. They know it's bad. They've hacked together Slack-based "approve this?" messages, but it's not cryptographically verified or auditable.
- **Current solution:** Environment variables with raw API keys, maybe a custom Slack bot asking for thumbs-up emoji before proceeding. Zero encryption. Zero audit trail.
- **What makes them switch:** A `uvx qntm` one-liner that gives their agent a secure inbox AND adds m-of-n approval gates for API calls. Must be < 10 minutes to first working demo.
- **Estimated population:** ~50,000–100,000 globally (based on GitHub stars across CrewAI 44k+, AutoGen 40k+, LangGraph 15k+ — significant overlap, but the active builder pool is real)

### Profile 2: The DevOps/Platform Lead at a Mid-Size Company
- **Who:** Senior engineer or engineering manager at a 50–500 person company that's rolling out AI-assisted workflows
- **Title:** "Platform Engineer," "DevOps Lead," "Head of Infrastructure"
- **Daily tools:** Terraform, Kubernetes, GitHub Actions, PagerDuty, Datadog, Slack
- **Pain point:** The company is deploying AI agents that touch production systems (CI/CD triggers, database migrations, cloud resource provisioning). Leadership wants "human-in-the-loop" but the team is implementing it as hacky Slack threads. No cryptographic proof of who approved what.
- **Current solution:** Slack approval bots, JIRA tickets, or ad-hoc scripts. Maybe OPA/Rego policies, but those don't handle multi-human approval flows for agent actions.
- **What makes them switch:** Compliance pressure + audit trail. qntm's gateway creates a cryptographically signed approval log that can satisfy SOC 2 auditors. The conversation IS the audit trail.
- **Estimated population:** ~10,000–20,000 teams globally (companies with >50 engineers actively deploying agent workflows)

### Profile 3: The Crypto/DAO Treasury Operator
- **Who:** DAO contributor or multi-sig signer managing treasury operations, 25–45
- **Title:** "Treasury Lead," "Operations Manager," "Core Contributor" at a DAO or crypto protocol
- **Daily tools:** Safe (Gnosis), Snapshot, Discord, Telegram, Etherscan, Dune Analytics
- **Pain point:** They already understand multi-sig. They already approve transactions with m-of-n signers. But their agent tooling (treasury bots, rebalancing agents) operates outside the multi-sig — the agent has a hot wallet or an API key with full access. They want the same m-of-n approval pattern for off-chain API calls (exchanges, fiat ramps, reporting APIs).
- **Current solution:** On-chain multi-sig (Safe) for token transfers, but off-chain API actions (CEX trades, bank wires, analytics queries) are uncontrolled. Discord polls for "soft" approvals.
- **What makes them switch:** qntm's API Gateway is multi-sig for APIs. Same mental model they already use for on-chain actions, applied to off-chain API calls. E2E encrypted so no Discord admin can see treasury credentials.
- **Estimated population:** ~5,000–15,000 active DAO operators/signers (based on Safe multi-sig usage data, active DAOs on Snapshot)

### Profile 4: The Security-Conscious Startup CTO
- **Who:** Technical co-founder or CTO at a startup handling sensitive data (fintech, healthtech, legaltech), 30–45
- **Title:** CTO, VP Engineering, Co-founder
- **Daily tools:** AWS/GCP, GitHub, Linear, Slack, 1Password, Signal (for sensitive discussions)
- **Pain point:** They want to use AI agents internally (customer support, data analysis, code review) but can't justify giving an agent access to Stripe, Plaid, or patient data APIs without an approval mechanism. The board/investors ask about AI governance. They have no good answer.
- **Current solution:** Manual copy-paste workflows. Human does the API call after the agent suggests it. Slow and defeats the purpose of agents.
- **What makes them switch:** qntm lets them say "yes, our agent can access the payments API, but only with 2-of-3 co-founder approval, all encrypted, all logged." This is a board-level talking point.
- **Estimated population:** ~15,000–30,000 startups globally (YC portfolio alone has 5,000+ companies, many in regulated verticals)

### Profile 5: The AI Automation Freelancer/Consultant
- **Who:** Independent consultant or freelancer building AI automations for clients, 28–50
- **Title:** "AI Automation Consultant," "AI Solutions Architect," Upwork/Toptal contractor
- **Daily tools:** n8n, Make/Zapier, LangChain, Python, client's Slack/Teams
- **Pain point:** Clients want AI agents that "do things" but are terrified of giving the freelancer's bot access to production APIs. Trust is the bottleneck. The freelancer needs a way to show the client exactly what the agent is doing and get explicit approval before API calls execute.
- **Current solution:** Screen-share demos, manual "run this?" confirmation emails, or just YOLO. No good middle ground.
- **What makes them switch:** qntm lets the freelancer set up a shared conversation where the client sees every API call proposal, approves it in-chat, and gets the result. Builds trust. Closes deals faster.
- **Estimated population:** ~20,000–50,000 (based on Upwork AI category growth, freelance AI automation is booming)

---

## 2. Channel Hypotheses (20 Channels)

### Channel 1: Hacker News — Show HN Launch
- **Type:** Content / Community
- **Platform:** news.ycombinator.com (Show HN)
- **Estimated reach:** ~500K daily unique visitors; 10K–50K views on a successful Show HN post. Validated: YouAM ("encrypted inbox for AI agents") and VectorGuard-Nano ("secure messaging for AI agents") both posted Show HN in Feb 2026 — this audience is actively interested.
- **Effort to test:** 1 day (write post, prep landing page, monitor comments for 24h)
- **How to test:** Post "Show HN: qntm — Encrypted messaging with m-of-n API approvals for AI agents" with a link to a 60-second demo video and the GitHub repo. Focus the pitch on the API Gateway, not just messaging.
- **Expected signal:** >100 upvotes = strong fit. >10 GitHub stars from HN traffic. >5 people actually running `uvx qntm` (track via relay signups). Comment quality matters more than votes — look for "I need this" vs. "cool project."

### Channel 2: r/LocalLLaMA (Reddit)
- **Type:** Community
- **Platform:** reddit.com/r/LocalLLaMA (~658K members, extremely active)
- **Estimated reach:** 5K–20K views on a well-received post
- **Effort to test:** 2 hours (write post, reply to comments)
- **How to test:** Post titled "I built encrypted multi-party approval for AI agent API calls" with a practical example — e.g., "My agent can wire money via Mercury, but only after 2 of my 3 co-founders approve in an encrypted chat." Include a gif of the TUI approval flow.
- **Expected signal:** >50 upvotes, >20 comments. People asking "does this work with [my framework]?" Track GitHub referral traffic from Reddit.

### Channel 3: r/ChatGPTCoding / r/ClaudeAI (Reddit)
- **Type:** Community
- **Platform:** reddit.com/r/ChatGPTCoding (~200K+), reddit.com/r/ClaudeAI (~100K+)
- **Estimated reach:** 3K–10K views per post
- **Effort to test:** 2 hours each
- **How to test:** Write a "how I gave my coding agent safe access to my production APIs" tutorial post. Show the actual CLI commands. These subs love practical tool posts.
- **Expected signal:** >30 upvotes, DMs asking for help setting it up, GitHub stars from Reddit.

### Channel 4: LangChain / LangGraph Discord
- **Type:** Community
- **Platform:** LangChain Discord server (~50K+ members)
- **Estimated reach:** 1K–5K in relevant channels (#show-and-tell, #agent-discussion)
- **Effort to test:** 3 hours (join, post in appropriate channel, answer questions)
- **How to test:** Post a working LangGraph integration example: "Here's how to add encrypted m-of-n approval gates to your LangGraph agent in 20 lines." Include a GitHub gist.
- **Expected signal:** >10 reactions, people forking the gist, requests for a proper LangChain integration/tool.

### Channel 5: CrewAI Discord
- **Type:** Community
- **Platform:** CrewAI Discord server (active, exact size undisclosed but CrewAI has 44K+ GitHub stars)
- **Estimated reach:** 500–2K in relevant channels
- **Effort to test:** 3 hours
- **How to test:** Same as LangChain but tailored: "How to add human approval for sensitive CrewAI tool calls using qntm." Show a CrewAI tool wrapper that routes through qntm's gateway.
- **Expected signal:** >5 substantive replies, people trying the integration.

### Channel 6: AutoGen / Microsoft AI Discord
- **Type:** Community
- **Platform:** AutoGen Discord / GitHub Discussions (AutoGen has 40K+ stars)
- **Estimated reach:** 500–2K
- **Effort to test:** 3 hours
- **How to test:** Post in GitHub Discussions: "RFC: Using qntm for encrypted human-in-the-loop approvals in AutoGen workflows." Framed as a contribution/integration idea, not a promotion.
- **Expected signal:** Maintainer engagement, issue filed for integration, forks.

### Channel 7: AI Engineering World's Fair / AI Engineer Summit
- **Type:** Conference / Event
- **Platform:** AI Engineer Summit (thousands of attendees, focused on applied AI engineering)
- **Estimated reach:** 3K–5K attendees, plus livestream/recording audience of 20K+
- **Effort to test:** 2–4 weeks (apply to speak or demo, prep materials)
- **How to test:** Submit a talk: "Multi-Party Approval for Agent API Calls: Moving Beyond YOLO Tokens." Alternatively, get a demo booth at the expo. Even attending and doing hallway demos at the next event could work.
- **Expected signal:** Talk acceptance, post-talk GitHub spike, business card exchanges with potential design partners.

### Channel 8: Dev.to / Hashnode Technical Blog Posts
- **Type:** Content
- **Platform:** dev.to (massive developer audience, AI tag is trending)
- **Estimated reach:** 5K–20K views for a well-tagged AI/security post
- **Effort to test:** 1 day (write and publish article)
- **How to test:** Publish "Why Your AI Agent's API Key is a Ticking Time Bomb (And How to Fix It)" — a problem-first article that introduces qntm's gateway as the solution. Tag with #ai, #security, #agents, #python.
- **Expected signal:** >100 reactions, >5K views, GitHub referral traffic. Repurpose to Hashnode and Medium simultaneously.

### Channel 9: Twitter/X AI Agent Builder Community
- **Type:** Content / Community
- **Platform:** Twitter/X, targeting the AI agent builder crowd (follows: @LangChainAI, @AndrewYNg, @kaboroevich, etc.)
- **Estimated reach:** 5K–50K impressions per viral thread (if it hits)
- **Effort to test:** Ongoing, 30 min/day
- **How to test:** Post a thread: "I've been thinking about why giving AI agents raw API keys is insane. Here's what happens when your agent gets prompt-injected and has your Stripe key… 🧵" Build to the qntm gateway reveal at the end. Post demo videos/gifs as individual tweets.
- **Expected signal:** >50 likes on core thread, >10 quote tweets, profile visits, GitHub stars correlated with tweet timing.

### Channel 10: PyPI / `uvx` Discoverability
- **Type:** Marketplace / Distribution
- **Platform:** PyPI (the `qntm` package)
- **Estimated reach:** Passive discovery by anyone searching PyPI for "agent messaging," "encrypted agent," "agent API approval"
- **Effort to test:** 2 hours (optimize PyPI metadata, description, classifiers, keywords)
- **How to test:** Update PyPI long description with compelling problem→solution narrative. Add classifiers for "Topic :: Security :: Cryptography," "Topic :: Communications :: Chat." Ensure `uvx qntm --help` is genuinely impressive on first run.
- **Expected signal:** Track `pip install qntm` downloads via PyPI stats. Baseline now, measure after metadata optimization.

### Channel 11: GitHub Trending / Awesome Lists
- **Type:** Marketplace / Content
- **Platform:** GitHub Trending (Python, weekly); awesome-agents, awesome-llm-tools, awesome-security curated lists
- **Estimated reach:** GitHub Trending Python page gets 100K+ views/week; awesome lists have 10K–100K stars each
- **Effort to test:** 1 day (prepare repo for discoverability, submit PRs to awesome lists)
- **How to test:** Polish the GitHub README for drive-by visitors (add badges, a compelling one-liner, a gif demo). Submit PRs to: awesome-agents, awesome-llm-apps, awesome-python-security. Time a star campaign to hit GitHub Trending.
- **Expected signal:** PR acceptance in ≥2 awesome lists. Appearing on GitHub Trending for 1+ days. Star velocity increase.

### Channel 12: MCP / A2A Protocol Community
- **Type:** Community / Partnership
- **Platform:** A2A Protocol community (GitHub a2aproject/A2A, Linux Foundation), MCP ecosystem (Anthropic)
- **Estimated reach:** A2A GitHub has high engagement; MCP is the dominant agent-tool protocol
- **Effort to test:** 1 week (build a proof-of-concept MCP server or A2A-compatible agent that uses qntm)
- **How to test:** Build an MCP server that wraps qntm's gateway — so any MCP-compatible agent can propose API calls through qntm's approval flow. Post to A2A GitHub Discussions: "RFC: Encrypted channel layer for A2A agent communication using qntm/QSP."
- **Expected signal:** Discussion engagement from A2A/MCP maintainers. Someone builds on top of the MCP server. This is a long-play integration, but it positions qntm as infrastructure.

### Channel 13: Crypto/DAO Twitter + Governance Forums
- **Type:** Community / Content
- **Platform:** Crypto Twitter (CT), Arbitrum/Optimism governance forums, Safe community Discord
- **Estimated reach:** 5K–20K impressions (CT); 500–2K views (governance forums)
- **Effort to test:** 3 days (write post, engage with DAO operators)
- **How to test:** Write a governance forum post: "Proposal: Using qntm as multi-sig for off-chain API calls in DAO treasury operations." Target DAOs that already use AI agents for treasury (Arbitrum's Talos is a reference). Demo: agent proposes a CEX trade, 2-of-3 signers approve in encrypted chat.
- **Expected signal:** >10 replies from DAO operators. 1+ DAO expresses interest in a pilot. Twitter engagement from crypto-AI accounts.

### Channel 14: YouTube Developer Tutorials
- **Type:** Content
- **Platform:** YouTube (developer tutorial niche)
- **Estimated reach:** 2K–50K views over 3 months for a well-SEO'd tutorial
- **Effort to test:** 2–3 days (record, edit, publish)
- **How to test:** Record "Build a Secure AI Agent with Multi-Party API Approvals in 10 Minutes" — screen recording of the full flow: identity generation → conversation creation → agent proposes Stripe charge → human approves in web UI → charge executes. Target keywords: "AI agent security," "human in the loop AI agent," "encrypted agent messaging."
- **Expected signal:** >1K views in first week, comments asking questions, GitHub referral traffic from YouTube.

### Channel 15: AI Safety / Alignment Community
- **Type:** Community / Content
- **Platform:** Alignment Forum (alignmentforum.org), LessWrong, AI Safety subreddits (r/aisafety)
- **Estimated reach:** 5K–20K across platforms (niche but highly influential)
- **Effort to test:** 1 day (write a serious post)
- **How to test:** Write "Cryptographic Oversight for Autonomous Agents: A Practical Approach" — framing qntm's gateway as an alignment/safety tool. The m-of-n approval pattern is a concrete implementation of "corrigibility." This audience cares deeply about AI control mechanisms.
- **Expected signal:** >20 upvotes on LessWrong, citations in alignment discussions, interest from AI safety researchers/labs.

### Channel 16: n8n / Make.com Community
- **Type:** Community / Marketplace
- **Platform:** n8n community forum (community.n8n.io), n8n Discord
- **Estimated reach:** n8n has 60K+ GitHub stars, active community
- **Effort to test:** 3 days (build n8n node or workflow template, post to community)
- **How to test:** Build an n8n workflow template: "AI Agent with Human Approval for Sensitive Actions using qntm." n8n already supports human-in-the-loop but without encryption or multi-party approval. qntm fills the gap.
- **Expected signal:** Template downloads, community reactions, n8n team engagement.

### Channel 17: YC Startup School / Founder Communities
- **Type:** Community / Outreach
- **Platform:** YC Startup School forums, Indie Hackers, Pioneer.app
- **Estimated reach:** 5K–15K active founders
- **Effort to test:** 2 days (write posts, engage)
- **How to test:** Post on Indie Hackers: "We built the missing infrastructure for AI agent API security — here's what we learned." On YC forums, frame it as "looking for design partners who are deploying AI agents that touch production APIs." Direct outreach to 20 YC companies building agent products.
- **Expected signal:** >5 founder conversations, 1–2 design partner commitments, feedback on pricing/packaging.

### Channel 18: InfoSec / AppSec Communities
- **Type:** Community
- **Platform:** r/netsec (~500K), OWASP community, BSides conferences, Trail of Bits blog comments
- **Estimated reach:** 5K–20K security professionals who advise on agent deployments
- **Effort to test:** 2 days
- **How to test:** Write a security-focused post: "Threat Modeling AI Agent API Access: Why RBAC Isn't Enough." Publish on r/netsec and OWASP community channels. Security pros are the "influencers" who convince engineering teams to adopt security tooling.
- **Expected signal:** r/netsec engagement (this sub is very discerning — any positive response is a strong signal). Security researchers reviewing the threat model doc.

### Channel 19: Direct Outreach to Agent Framework Maintainers
- **Type:** Partnership / Outreach
- **Platform:** GitHub Issues/Discussions, email, Twitter DMs
- **Estimated reach:** 10–20 key people, but each one influences 10K+ developers
- **Effort to test:** 1 week (identify maintainers, craft messages, build integration POCs)
- **How to test:** Target: LangChain/LangGraph team (Harrison Chase), CrewAI (João Moura), AutoGen (Chi Wang), Vercel AI SDK team. Message: "We built encrypted m-of-n approval for agent API calls. Here's a working integration with [their framework]. Would you consider mentioning it in your docs/examples?" Ship an actual integration PR if possible.
- **Expected signal:** 1+ framework mentions qntm in docs or examples. A retweet from a framework creator. An official integration.

### Channel 20: Product Hunt Launch
- **Type:** Marketplace
- **Platform:** producthunt.com
- **Estimated reach:** 10K–50K views on launch day
- **Effort to test:** 1 week (prep assets, recruit hunters, coordinate launch day)
- **How to test:** Launch as "qntm — Multi-sig for AI agent API calls." Lead with the API Gateway, not the messaging. Key visual: a split-screen showing an agent proposing a bank wire, humans approving in chat, the wire executing. Schedule for a Tuesday. Get 2–3 well-known makers to upvote early.
- **Expected signal:** Top 5 of the day, >200 upvotes, >50 signups at chat.corpo.llc on launch day.

---

## 3. Top 3 Channels to Test First

### Why These Three: Reach × Fit × Effort

| Channel | Reach | Fit | Effort | Score |
|---------|-------|-----|--------|-------|
| **Hacker News (Show HN)** | Very High | Very High | Very Low | ⭐⭐⭐⭐⭐ |
| **r/LocalLLaMA** | High | Very High | Very Low | ⭐⭐⭐⭐⭐ |
| **Dev.to + Twitter Thread** | High | High | Low | ⭐⭐⭐⭐ |

**Rationale:**
1. **Hacker News** is the single highest-leverage launch venue for developer tools. The audience is technical, skeptical, and influential. Two direct competitors (YouAM, VectorGuard-Nano) already posted Show HN — proving demand. qntm's m-of-n gateway is genuinely novel compared to both. One day of effort could yield 100+ GitHub stars and real users.

2. **r/LocalLLaMA** is where AI agent builders live. 658K members, insanely active. They're building agents that call APIs. They know the key management problem. A good post here gets immediate, high-quality feedback from the exact people who will use qntm.

3. **Dev.to + Twitter** are a force multiplier. A problem-first blog post ("your agent's API key is a time bomb") creates a durable content asset that ranks in Google. A Twitter thread promotes it. This creates passive inbound for weeks/months. Low effort because it's just writing.

### Week 1 Test Plan

#### Day 1 (Monday): Preparation
- [ ] Polish GitHub README: add badges, a 15-second gif showing the gateway approval flow, and a "Why qntm?" section that leads with the API Gateway
- [ ] Optimize PyPI metadata (keywords, description, classifiers)
- [ ] Record a 60-second terminal demo video: identity → convo → agent proposes API call → human approves → call executes
- [ ] Prepare HN submission text (title + first comment)
- [ ] Draft the Dev.to article: "Why Your AI Agent's API Key is a Ticking Time Bomb"

#### Day 2 (Tuesday): Hacker News Launch
- [ ] Post Show HN at ~9 AM ET (optimal HN timing)
- [ ] Monitor comments for 12 hours. Reply to every substantive comment within 30 minutes.
- [ ] Track: upvotes, GitHub stars, relay signups (new identity registrations), PyPI downloads
- [ ] **Success metrics:** >50 upvotes, >20 GitHub stars from HN, >10 `uvx qntm` installs, >5 relay signups

#### Day 3 (Wednesday): Reddit — r/LocalLLaMA
- [ ] Post to r/LocalLLaMA: "I built encrypted multi-party approval for AI agent API calls — here's a demo"
- [ ] Include the gif from Day 1, link to GitHub, and a concrete example (agent proposes Stripe charge, 2 humans approve)
- [ ] Cross-post a variant to r/ChatGPTCoding
- [ ] Monitor and reply to all comments
- [ ] **Success metrics:** >50 upvotes, >10 comments, >10 GitHub stars from Reddit

#### Day 4 (Thursday): Dev.to Article + Twitter Thread
- [ ] Publish Dev.to article (1500–2000 words, problem → solution → demo → CTA)
- [ ] Post Twitter thread (8–10 tweets) with the hook: "Your AI agent has your Stripe key. What could go wrong? 🧵"
- [ ] Thread ends with a link to the Dev.to article and GitHub repo
- [ ] **Success metrics:** >5K article views, >50 Twitter likes, >20 GitHub stars from article/Twitter

#### Day 5 (Friday): Follow-up & Measurement
- [ ] Reply to all remaining comments on HN, Reddit, Dev.to, Twitter
- [ ] Compile metrics:
  - Total new GitHub stars (target: >50 for the week)
  - Total PyPI downloads (track via pypistats.org)
  - Total relay signups (new identities on inbox.qntm.corpo.llc)
  - Total conversations created
  - Qualitative: what features were people asking for? What confused them?
- [ ] Write internal retro: what worked, what flopped, what to double down on

#### Days 6–7 (Weekend): Assess & Plan Wave 6
- [ ] If HN hit: ride the wave. Write a follow-up post addressing the top questions from comments.
- [ ] If Reddit hit: post to r/netsec and r/ClaudeAI next week.
- [ ] If Dev.to hit: write 2 more articles (gateway deep-dive, integration tutorial).
- [ ] Begin outreach to framework maintainers (Channel 19) based on this week's signal.

### Success Metrics Summary (Week 1)

| Metric | Minimum Viable | Strong Signal | Home Run |
|--------|---------------|---------------|----------|
| GitHub stars (new) | 30 | 100 | 500+ |
| PyPI installs | 50 | 200 | 1000+ |
| Relay signups (new identities) | 5 | 20 | 100+ |
| Conversations created | 3 | 10 | 50+ |
| Gateway promotions (people actually using m-of-n) | 1 | 5 | 20+ |
| Inbound DMs/emails from potential users | 2 | 10 | 30+ |

---

## 4. Competitive Landscape

### Direct Competitors (Encrypted Agent Messaging)

**YouAM** — "An address, contact card, and encrypted inbox for AI agents"
- Posted Show HN ~4 weeks ago
- NaCl Box encrypted E2E, relay-based, self-hostable
- **Missing:** No group approval mechanism, no API gateway, no m-of-n threshold. It's just encrypted messaging for agents — no action execution.
- **Threat level:** Low-medium. Validates the market but lacks the gateway differentiator.

**VectorGuard-Nano** — "Secure messaging for AI agents"
- Posted Show HN in Feb 2026
- HMAC-based obfuscation (not true E2E encryption), MIT-licensed
- **Missing:** Not real encryption (HMAC obfuscation ≠ AEAD encryption). No approval workflows. No persistent identities.
- **Threat level:** Low. More of a toy/demo than a real security tool.

### Adjacent Competitors (Agent Communication Protocols)

**Google A2A (Agent-to-Agent Protocol)**
- Open protocol for agent-to-agent communication, donated to Linux Foundation
- Huge backing (Google, IBM)
- **Missing:** No encryption layer (delegates to transport security). No approval/governance mechanism. A2A is about interoperability, not security or oversight.
- **qntm angle:** qntm could be the encrypted transport layer UNDER A2A. They're complementary, not competing.

**Anthropic MCP (Model Context Protocol)**
- Standard for connecting LLMs to tools
- Dominant protocol for agent↔tool communication
- **Missing:** MCP is about tool access, not about multi-party approval or encryption. An MCP server can call any API once connected — no human oversight built in.
- **qntm angle:** qntm's gateway can wrap MCP tool calls with approval gates. Build an MCP server that routes through qntm. MCP + qntm = tools with guardrails.

### Adjacent Competitors (Human-in-the-Loop Approval)

**LangGraph Human-in-the-Loop**
- Built-in interrupt/approve pattern for LangGraph workflows
- **Missing:** Single-user approval only (not m-of-n). No encryption. No persistent conversation/audit trail. The approval is a code checkpoint, not a cryptographic signature.

**Microsoft Copilot Studio Approvals**
- Multi-stage approval for agent flows in the Microsoft ecosystem
- **Missing:** Locked to Microsoft ecosystem. No encryption. Enterprise pricing. Not for indie builders or small teams.

**n8n Human-in-the-Loop**
- Workflow automation with human approval nodes
- **Missing:** No encryption, no multi-party approval (single approver), no cryptographic audit trail.

### Indirect Competitors (Encrypted Communication)

**Signal** — Gold standard for encrypted human messaging. No agent support. No API gateway.  
**Matrix/Element** — Federated encrypted messaging. Has bots, but no agent-first design, no API gateway, no approval workflows.  
**Keybase** — Dead (acquired by Zoom). Had team-based encrypted chat + crypto wallets but no agent story.

### What Nobody Has

**Nobody combines all three:**
1. End-to-end encrypted messaging with persistent cryptographic identities
2. Agent-first design (JSON output, CLI-first, Python package)
3. m-of-n group-approved API execution with cryptographic signatures

This is qntm's moat. The API Gateway is not an incremental feature — it's a category-creating capability. "Multi-sig for API calls" is a concept that doesn't exist anywhere else outside of blockchain multi-sig wallets.

### Positioning Statement (Draft)

> **qntm is multi-sig for AI agent API calls.**
>
> When your AI agent needs to wire money, deploy code, or access sensitive data, qntm ensures no single person — and no single agent — can act alone. Every API call requires cryptographic approval from multiple participants in an end-to-end encrypted conversation. The chat is the control plane. The conversation is the audit trail.
>
> Think of it as Gnosis Safe, but for any API — not just on-chain transactions.

### Alternative Positioning Angles (Test These)

1. **For security-first buyers:** "The only encrypted inbox for AI agents with built-in approval gates."
2. **For compliance buyers:** "Cryptographic audit trails for AI agent actions. SOC 2-ready."
3. **For DAO/crypto buyers:** "Multi-sig for off-chain API calls. Same m-of-n, new frontier."
4. **For agent builders:** "Give your agent a secure mailbox. Let your team approve its API calls."

---

## Appendix: Key Numbers for Planning

| Metric | Value | Source |
|--------|-------|--------|
| r/LocalLLaMA members | ~658K | gummysearch.com |
| CrewAI GitHub stars | 44.5K+ | GitHub |
| AutoGen GitHub stars | 40K+ | GitHub |
| LangGraph GitHub stars | 15K+ | GitHub |
| n8n GitHub stars | 60K+ | GitHub |
| A2A Protocol | Linux Foundation, Google-backed | a2a-protocol.org |
| Show HN avg front-page post views | 10K–50K | HN analytics |
| Dev.to monthly active developers | 1M+ | Dev.to stats |
| Active DAOs on Snapshot | 3K+ | Snapshot |
| Safe (Gnosis) multi-sig signers | 10M+ addresses | Safe stats |

---

*End of CMO Distribution Report — Wave 5*
*Next review: Post Week-1 test results*
