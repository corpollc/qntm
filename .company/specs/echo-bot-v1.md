# Echo Bot v1 — Spec
Created: 2026-03-22
DRI: CTO
Status: Ready for implementation

## Purpose
A persistent bot on the relay that responds to messages, proving the protocol works for new users without needing a second terminal.

## Architecture
**Cloudflare Worker** (not a long-running process) using a Cron Trigger or Durable Object alarm to poll.

### Why Worker, not standalone?
- Zero ops: runs on Cloudflare, same infra as relay
- No server to maintain
- Scales to zero when not in use
- Can use Durable Objects for state persistence

## Flow
1. Echo bot has a pre-generated identity stored in KV
2. Echo bot has a well-known conversation (invite token published in README)
3. On cron trigger (every 30s) OR on receiving a WebSocket message:
   - Poll relay for new messages on its conversation
   - For each new message: decrypt, prepend "🔒 echo: ", re-encrypt, send back
4. Store cursor in KV so it doesn't re-process old messages

## Implementation Plan

### Option A: Minimal Python Script (fastest to ship)
```bash
# Run as a cron job or persistent process
uvx qntm recv <convo> | while read msg; do
  uvx qntm send <convo> "echo: $msg"
done
```
Pro: Ships in minutes. Con: Needs a host to run on.

### Option B: Cloudflare Worker Echo Bot
Separate worker that uses the qntm client library (JS/TS) to:
- Store identity in KV
- Poll the relay on a cron schedule
- Echo messages back

Pro: Zero-ops, production-grade. Con: More complex, needs client lib in worker.

### Decision: Start with Option A
Ship a Python-based echo bot script that runs on any machine. We can upgrade to a Worker later when we have users. "Ship the smallest thing that can teach."

## Echo Bot Identity
- Generate a dedicated identity: `uvx qntm identity generate --config-dir /tmp/echo-bot`
- Create a conversation: `uvx qntm convo create --name "Echo Bot" --config-dir /tmp/echo-bot`
- Publish invite token in README

## Files to Create
1. `echo-bot/run.sh` — shell script that runs the echo bot
2. `echo-bot/README.md` — setup instructions
3. Update main README with echo bot conversation link

## Success Criteria
- Send a message to echo bot conversation → receive echo within 5 seconds
- Works for any user who joins with the invite token
