# Distribution Channel Research v1 — qntm
Created: 2026-03-22
DRI: CMO
Status: Initial hypotheses from web research

## Key Finding: The Market Is HOT
Multiple Reddit threads in r/AI_Agents specifically ask about agent-to-agent communication, encrypted messaging between agents, and distributed agent protocols. Google launched A2A protocol (April 2025). A competitor (claweb.ai) is already posting in r/AI_Agents project display threads. This validates the market but means we need to move fast.

## Channel Hypotheses (ranked by likely impact)

### Tier 1: High Probability (test immediately)
1. **r/AI_Agents** (Reddit) — THE subreddit for our audience
   - Active threads: "How are you handling agent-to-agent communication?" (Jan 2025)
   - Active threads: "We tried building actual agent-to-agent protocols" (Apr 2025)
   - Active threads: "Agent2Agent protocol experience" (May 2025)
   - Weekly project display thread — competitors already posting here
   - Action: Post in project display thread, answer communication questions

2. **r/LangChain** (Reddit) — LangGraph users building multi-agent systems
   - High traffic, framework comparison discussions
   - Action: Answer questions about agent coordination/communication

3. **Hacker News (Show HN)** — Developer tool launches get engagement
   - Action: "Show HN: qntm – End-to-end encrypted messaging for AI agents"
   - Timing: After echo bot is live (need demo-ready product)

4. **LangChain Discord** — Direct access to multi-agent developers
   - Large community, active discussion
   - Action: Join, contribute, mention qntm when relevant

5. **CrewAI Discord** — 44.5K GitHub stars, active community
   - Multi-agent focus = our exact audience
   - Action: Same as LangChain

### Tier 2: Medium Probability (test week 2-3)
6. **Dev.to / Medium** — Technical blog posts
   - "How to add encrypted communication to your multi-agent system"
   - Action: Write tutorial using qntm with LangChain/CrewAI

7. **Twitter/X #AIAgents** — Developer community discussion
   - Action: Share TTFM demo, quick-start code

8. **r/MachineLearning** — Broader AI community
   - More research-focused but high visibility
   - Action: Technical post about protocol design

9. **AutoGen Discord (Microsoft)** — Multi-agent conversation focus
   - Action: Join, contribute

10. **GitHub Awesome Lists** — awesome-agents, awesome-ai-agents
    - Action: Submit PR to add qntm

### Tier 3: Lower Probability / Longer Term
11. **AI agent conferences** (per Reddit thread listing 2026 events)
12. **Anthropic MCP community** — tool ecosystem adjacent
13. **Product Hunt** — once we have polished demo
14. **YC Hacker News "Who's Hiring"** — design partner recruiting
15. **OpenAI Developer Forum** — API builders
16. **Moltbook.com** — AI agent social network (novel but unproven)

### Tier 4: Direct Outreach
17. **GitHub Issues on framework repos** — propose qntm integration
18. **Framework maintainer DMs** — propose official integration
19. **Agent infra company founders** — LinkedIn/Twitter DMs
20. **Developer advocates at agent companies** — warm intros

## Competitor Alert: claweb.ai
Found in r/AI_Agents project display thread (3 weeks ago):
- Go CLI (`aw`), Ed25519 signing, did:key identity
- NO end-to-end encryption yet (they say "coming soon")
- We have encryption NOW — this is our advantage
- They have did:claw registry — we don't have decentralized ID yet

## Competitor Alert: Google A2A Protocol
- Launched April 2025, open standard
- 138 upvotes on Reddit announcement
- Focused on interop between different agent frameworks
- NOT focused on encryption or privacy
- Our positioning: "A2A handles interop, qntm handles security"

## Next Steps
1. Create r/AI_Agents post for project display thread (BLOCKED: public posting DENIED in autonomy — need Chairman approval OR post via Pepper)
2. Draft 3 positioning messages for testing
3. Identify 5 specific individuals to DM on Reddit/Twitter
4. Write "How to add E2E encryption to your LangChain agents" tutorial
