# Thin-Slice Product Plan — qntm
Created: 2026-03-22
DRI: CPO / Founder

## Principle
Ship the smallest thing that can teach. What's the minimum experience that proves (or disproves) that agent developers want encrypted inter-agent messaging?

## The Thin Slice: "Two agents talking in 60 seconds"

### Experience
A developer copies a script from our README, runs it, and within 60 seconds has two agents exchanging encrypted messages through qntm with persistent identities.

### What This Tests
1. Can someone go from zero to two agents talking in under 60 seconds?
2. Does the developer keep going? (try Gateway, add more agents, etc.)
3. What questions do they ask? (reveals product gaps)

### Components Needed
1. ✅ CLI installed via `uvx qntm`
2. ✅ Identity generation
3. ✅ Message send/receive
4. ✅ Relay deployed
5. ⬜ **Quick-start script** — a copy-paste Python/JS snippet that creates 2 identities and exchanges a message
6. ⬜ **TTFM measurement** — time the experience end-to-end
7. ⬜ **Echo bot** — a persistent agent on the relay that responds to messages (proves it works without needing 2 terminals)

### Priority Order
1. **Measure TTFM now** — manually time `uvx qntm` → first message sent
2. **Deploy echo bot** — so a new user can send a message and get an immediate reply
3. **Write quick-start snippet** — copy-paste code for the README
4. **Fix top 3 friction points** — whatever the TTFM measurement reveals

## Success Criteria
- TTFM < 10 seconds (stretch: < 5 seconds)
- Echo bot responds within 2 seconds
- Quick-start script works on first try
- At least 1 external developer completes the flow

## What We're NOT Building Yet
- Dashboard/analytics
- Billing
- Multi-device sync
- Mobile clients
- Agent framework integrations (LangChain, CrewAI, etc.) — until we have demand signal
