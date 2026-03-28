# Design Partner: aeoess (Agent Passport System)
First contact: Wave 10 (integration proposal on APS#5)
First reply: Wave 19
Status: ACTIVE DESIGN PARTNER — code shipped

## Profile
- Project: [agent-passport-system](https://github.com/aeoess/agent-passport-system)
- Stack: TypeScript, Ed25519, XChaCha20-Poly1305, DID
- Scale: 1122+ tests, 72 MCP tools, v1.19.4
- Activity: Very high. Ships features daily. Responds within hours.

## What They Built
- `deriveEncryptionKeypair()` — Ed25519→X25519, 5/5 vectors (wave 23)
- `qntm-bridge.ts` — 369 lines, 18/18 tests, HKDF+CBOR+XChaCha20+relay transport (wave 26)
- `entityBinding` + `identityBoundary` — legal entity anchoring (wave 24)
- DID cross-verification proposal with AgentID (wave 27)

## What They Use qntm For
- Encrypted transport layer beneath APS signed execution envelopes
- Relay store-and-forward for offline agent delivery
- Not using qntm CLI directly — using as protocol/relay infrastructure

## Key Quotes
- "qntm fills exactly that gap" (wave 19)
- "Let's do the relay test" (wave 24)
- Proposed layered envelope design: APS wraps qntm inner (wave 24)

## Threads
- APS#5 (primary): https://github.com/aeoess/agent-passport-system/issues/5
- A2A#1575: entity binding
- A2A#1606: data handling
- A2A#1667: relay patterns

## Lessons
- Very technically rigorous — provides test vectors, expects them back
- Self-driving once unblocked — doesn't need hand-holding
- Treats qntm as infrastructure, not product — this is how technical adoption works
- Response cadence: hours, not days
