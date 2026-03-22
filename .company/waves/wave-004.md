# Wave 4 — Echo Bot Persistence + Activation Funnel
Started: 2026-03-22T05:35:00Z

## 10 Questions (answered before execution)

1. **What changed since last wave?**
   - Echo bot DEAD — nohup process died exactly as predicted. Primary metric back to 0.
   - Relay still healthy (healthz OK, ts: 1774157789896)
   - PyPI: 26 downloads yesterday, 862 last week, 1,625 last month — organic pull continues but at lower baseline than the March 20 spike.
   - Echo bot conversation (480) has 2 participants: bot + test identity. ZERO new joins. 862 weekly downloads → 0 new conversation participants.
   - No new messages on the echo bot conversation since it went down.

2. **Single biggest bottleneck?**
   - **Activation path is broken AND undiscoverable.** The echo bot died (predicted, not prevented). But even when it was alive, nobody new joined the conversation. 862 weekly PyPI downloads → 0 new conversation participants = the funnel is broken at BOTH "process survival" and "user discovery of demo."

3. **Bottleneck category?**
   - Activation (product) + Discovery (distribution). Dual failure: (a) the demo server is unreliable, (b) users who download don't find the demo.

4. **Evidence?**
   - Echo bot conversation: 2 participants only (bot + test identity). Nobody external has joined.
   - PyPI stats: 862 downloads last week, continuing organic pull.
   - Bot process dead — `ps aux` shows no bot.py running.
   - No new messages in echo bot conversation since wave 3 test.

5. **Highest-impact action?**
   - Make echo bot persistent (launchd plist) so the activation path stays alive. Then address discoverability — the fact that 0 out of 862 downloaders found and used the echo bot means the README "Try it now" section isn't reaching them.

6. **Which customer conversation are we avoiding?**
   - All of them. Still 0 outbound. Still blocked by AUTONOMY for public posting.

7. **Manual work that teaches faster?**
   - Look at `uvx qntm` first-run output — what does a new user SEE after generating identity? Is there ANY pointer to the echo bot? If not, that explains the 0 join rate.

8. **Pretending-is-progress?**
   - Making the echo bot more robust without fixing discoverability. A persistent bot that nobody knows about is still useless.

9. **Write down today?**
   - Funnel gap: 862 downloads → 0 echo bot joins. Launchd persistence design. First-run experience gap. Show HN draft.

10. **Escalation needed?**
    - Public posting still DENIED. New evidence: 862 weekly downloads + 0 conversations = distribution block is actively wasting inbound interest. Every downloader who gets bored and leaves is a lost potential design partner.

## Wave Top 5 (force ranked)
1. **Restart echo bot + create launchd plist** — get activation path alive and persistent
2. **Diagnose first-run discoverability** — what does a new user see? Where does the funnel break?
3. **Improve CLI first-run output** — add echo bot pointer to identity generate output (if feasible without release)
4. **Draft Show HN post** — we have enough: working encryption, echo bot, <2s TTFM
5. **Design CF Worker echo bot** — the permanent solution that eliminates host dependency

## Execution Log

### #1 — Restart Echo Bot + launchd Persistence ✅ DONE
- Restarted echo bot immediately at wave start
- Created launchd plist: `~/Library/LaunchAgents/llc.corpo.qntm.echo-bot.plist`
- Fixed PATH issue (uvx at ~/.local/bin not in launchd's default PATH)
- Verified: launchd shows PID 87219, exit code 0, bot echoing messages
- Tested: sent message from both bot identity and default identity → echo received
- **KeepAlive: SuccessfulExit=false** — auto-restarts on crash, survives reboots
- Decision memo written: `.company/decisions/2026-03-22-echo-bot-persistence.md`
- Primary metric: back to 1 active conversation

### #2 — Diagnose First-Run Discoverability ✅ DONE
**KEY FINDING: The PyPI README is the problem.**
- The published PyPI package (v0.3) shows a bare-bones README: "Secure messaging protocol CLI. qntm identity generate. qntm version." That's it.
- 862 weekly PyPI downloaders see NO echo bot mention, NO value prop, NO "Try it now" on the PyPI page
- After `qntm identity generate`, the JSON output has NO next-step hint
- The echo bot is ONLY discoverable by reading the full GitHub README — which PyPI downloaders are unlikely to do
- **This is the primary conversion gap.** Downloads → conversation joins fails because the entry point (PyPI page) gives no indication of what to do next.

### #3 — Improve CLI + PyPI README ✅ DONE (pending release)
- Added `next_step` field to `identity.generate` JSON output in Python CLI
- Rewrote `python-dist/README.md` with: value prop, echo bot "Try It" section, Python usage example, links
- **BLOCKED:** Both changes require a PyPI publish (REQUIRES_APPROVAL per AUTONOMY)
- The README change alone could convert a significant percentage of the 862 weekly downloaders

### #4 — Show HN Draft ✅ DONE
- Wrote `.company/research/show-hn-draft-v1.md`
- 4 title options with recommendation
- Full post body with code snippet, differentiator, and discussion questions
- Expected Q&A prepared
- **BLOCKED:** Posting requires approval (any-public-post DENIED)

### #5 — CF Worker Echo Bot Design ✅ DESIGNED
- Decision memo covers 3-phase plan: launchd (now) → CF Worker Cron (next) → WebSocket (later)
- CF Worker approach: Cron Trigger every 60s, poll relay, echo, reduces DO load from 17K/day to 1.5K/day
- Can use existing TypeScript client library from `client/` package
- **Deferred to Wave 5** — launchd solution is sufficient for now

## Key Insights This Wave
1. **The funnel breaks at PyPI, not at the CLI.** 862 downloads → 0 echo bot joins because the PyPI page says nothing useful.
2. **The published package (v0.3) is Go binary, our dev (v0.4.2) is Python CLI.** Both work, but they're different codebases. Release coordination matters.
3. **launchd persistence is the right immediate fix.** No infrastructure cost, auto-restart, survives reboots.
4. **A new PyPI release would be the highest-leverage single action.** The README change alone could 10x activation.
5. **Distribution and activation are intertwined.** Even organic downloads can't activate without a good first-run experience.
