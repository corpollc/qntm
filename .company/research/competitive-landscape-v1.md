# Competitive Landscape v1 — qntm
Created: 2026-03-22
DRI: CMO

## Direct Competitors (agent-to-agent messaging/communication)

### 1. Google A2A (Agent-to-Agent Protocol)
- **What**: Open standard for agent interop
- **Strength**: Google backing, 138 upvotes on Reddit, growing adoption
- **Weakness**: Focused on interop/task delegation, NOT encryption/privacy
- **Our angle**: "A2A handles interop, qntm handles security"
- **Threat level**: HIGH (could add encryption later)

### 2. claweb.ai
- **What**: Go CLI for agent communication, Ed25519 signing, did:key identity
- **Strength**: Already posting in r/AI_Agents, has DID registry
- **Weakness**: NO end-to-end encryption yet ("coming soon")
- **Our angle**: We have E2E encryption NOW + API Gateway (multi-sig)
- **Threat level**: MEDIUM (same market, behind on encryption)

### 3. Anthropic MCP (Model Context Protocol)
- **What**: Protocol for connecting AI to tools/data
- **Strength**: Anthropic backing, growing ecosystem, Slack integration
- **Weakness**: Tool/context protocol, not messaging. No encryption.
- **Our angle**: Complementary — MCP for tools, qntm for secure comms
- **Threat level**: LOW (different layer)

### 4. Arch Gateway (katanemo)
- **What**: Agent gateway for communication, built by Envoy Proxy team
- **Strength**: Enterprise pedigree (Envoy), early mention in Reddit
- **Weakness**: Early stage, infrastructure-focused
- **Our angle**: Application-layer encryption vs infrastructure routing
- **Threat level**: MEDIUM

## Adjacent/Indirect Competitors

### 5. Message Queues (RabbitMQ, Kafka, NATS)
- What developers use TODAY for agent-to-agent communication
- No encryption, no identity, no multi-sig
- Our pitch: "You wouldn't use a message queue for human chat. Why use one for agents that handle sensitive data?"

### 6. Slack/Discord Agent APIs
- Growing agent support (Slack MCP, Discord bots)
- Vendor-locked, not encrypted, human-oriented
- Our pitch: "Agents deserve their own communication layer"

### 7. Agent frameworks' built-in comms (AutoGen, CrewAI)
- In-process communication, no network layer
- Works for single-machine multi-agent, not distributed
- Our pitch: "When your agents run on different machines, you need qntm"

## Our Unique Position
1. **E2E encryption** — nobody else has this for agents (claweb says "coming soon")
2. **API Gateway with multi-sig** — nobody else has this at all
3. **Persistent identity** — Ed25519 keys that survive restarts
4. **Protocol-first** — not locked to any framework
5. **Sub-2s TTFM** — fastest onboarding in the space

## Strategic Risk
Google could add encryption to A2A. Anthropic could extend MCP to include messaging. OpenAI could build agent comms into their SDK. We need design partners and lock-in (Gateway usage) before this happens.

## Positioning Statements to Test
1. "Signal for AI agents" — simple, resonant, but oversimplifies
2. "End-to-end encrypted communication + multi-sig API Gateway for AI agents" — accurate but long
3. "The security layer your multi-agent system is missing" — problem-first
4. "Agents talking over plaintext is the new HTTP without TLS" — analogy-first
5. "qntm: persistent identity, private channels, multi-sig API approval for AI agents" — feature-rich
