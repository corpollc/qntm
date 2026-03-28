# Mission Memo v1 — qntm
Created: 2026-03-22
DRI: Founder

## Mission
qntm gives every participant — human or agent — a persistent cryptographic identity and private conversations over an untrusted relay.

## Why Now
The agent economy is emerging. Agents are making API calls, coordinating tasks, and handling sensitive data — but they communicate over plaintext webhooks, ephemeral chat sessions, or vendor-locked channels. There is no durable, encrypted, identity-bound messaging layer for agents.

## The Problem
Agent developers building multi-agent systems need:
1. **Persistent identity** — agents need cryptographic identities that survive restarts
2. **Private channels** — conversations must be encrypted end-to-end, not readable by the relay
3. **Multi-party coordination** — agents need group conversations with verifiable membership
4. **Programmatic API access control** — the killer feature: m-of-n approval for external API calls (the Gateway)

Today they cobble together webhooks, message queues, and chat APIs. None provide cryptographic identity or multi-sig access control.

## Our Wedge
AI agent developers who need persistent, encrypted, identity-bound messaging between agents. Specifically: teams running multi-agent systems that need durable coordination channels.

## The Differentiator
The **API Gateway**: m-of-n approval for external API calls. No messaging protocol offers this. It's the primitive that makes agent-to-agent coordination trustworthy — not just private.

## What We Have Today
- End-to-end encrypted messaging protocol (X3DH + Double Ratchet variant)
- CLI client (`uvx qntm`)
- Web UI (chat.corpo.llc)
- Cloudflare relay (inbox.qntm.corpo.llc)
- API Gateway with recipe system
- WebSocket subscriptions
- 250+ passing tests

## What Success Looks Like (Month 1)
- 5+ active external conversations per week
- 3+ design partners using the protocol
- At least 1 team using the API Gateway
- Economic commitment signal from at least 1 potential customer

## What We Don't Know
- Where agent developers actually discover new tools (distribution channels)
- Whether the CLI install experience is fast enough (<10s target)
- Whether the Gateway concept resonates before they try it
- Pricing model that works for agent-to-agent messaging
