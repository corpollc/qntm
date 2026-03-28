# Draft v1: A2A Issue #1667 Comment
# Status: READY TO POST

The relay/proxy question is the one I can speak to most directly — we built one.

## On the relay pattern

[qntm](https://github.com/corpollc/qntm) is a relay for agent messaging that handles exactly the store-and-forward pattern you describe. The model:

- **Agents subscribe via WebSocket** (`/v1/subscribe?conv_id=...&from_seq=N`). When connected, messages arrive in real-time.
- **When the agent is offline**, messages accumulate on the relay with sequence numbers. On next wake, the agent reconnects with its last known sequence and gets the full backlog.
- **Messages are E2E encrypted** (X3DH + Double Ratchet). The relay stores only ciphertext — it can route and sequence messages but can't read them.

For a heartbeat agent (your 4-hour cron pattern), the flow is: wake → connect to relay with `from_seq=last_cursor` → receive all queued messages → process → disconnect → sleep. The relay handles the durability gap between cycles.

## On `taskLatencyMaxSeconds` and availability

The availability metadata extension you propose makes sense. One thing we've found in practice: the relay itself can provide some of this signal. If you track when agents last connected (which the relay naturally knows), a discovery layer can expose `lastActiveAt` and `estimatedNextAt` without the agent self-reporting — agents that run on predictable schedules reveal their pattern through connection history.

That said, explicit `scheduleType` + cron expression is cleaner and doesn't require inference. Both are useful.

## On the `tasks/queue` semantic

The sequence-numbered store-and-forward model sidesteps the "is the agent online?" question entirely. The caller doesn't POST to the agent directly — it posts to the relay conversation. Whether the agent is awake or asleep, the message lands in the queue with a monotonic sequence number. The agent processes the backlog on next wake.

The error semantics question (@The-Nexus-Guard's point about bounded latency expiry) maps to message TTLs on the relay side — if a task expires before the agent wakes, the relay can drop it or flag it.

Repo: https://github.com/corpollc/qntm — the relay is the Cloudflare Worker at `worker/src/index.ts`, subscribe endpoint handles the backlog replay.
