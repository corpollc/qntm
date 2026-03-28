# DECISION MEMO — Authenticated Subscribe

## Problem
`/v1/subscribe` currently routes by `conv_id` alone with no identity verification. Any client that knows a conversation ID can connect and receive ciphertext. While E2E encryption means they can't read the content, they can observe traffic patterns (timing, frequency, message sizes).

## Target Customer/Segment
Agent developers integrating encrypted messaging into multi-agent systems. Specifically: aeoess (APS) and The-Nexus-Guard (AIP) — our first two external technical contacts.

## Evidence
- The-Nexus-Guard explicitly asked on A2A #1667: "does qntm support any form of identity for subscribers? ... is there agent-level authentication on subscribe?"
- aeoess's integration proposal on #5 implies identity-bound transport — their system binds everything to Ed25519 passport keys.
- Both represent potential design partners. Addressing their feedback directly demonstrates responsiveness and engineering quality.

## Options Considered

### Option A: Ed25519 Challenge-Response on WebSocket Handshake
```
1. Client: GET /v1/subscribe?conv_id=X&pub_key=Y
2. Server: sends {"challenge": "<32-byte-hex>"}
3. Client: sends {"signature": "<ed25519-sig-of-challenge>"}
4. Server: verifies sig against conversation participant list
5. If valid → stream messages. If not → close(4003).
```

**Pros:** Strong identity verification. Same Ed25519 primitives already in the relay (verifyAnnounceSig). Compatible with APS key derivation path.
**Cons:** Adds 1 round-trip latency to subscribe. Requires participant list to be stored on relay. Breaking change for existing clients.

### Option B: Bearer Token (Signed Subscribe Token)
```
Client pre-signs a subscribe token: sign(conv_id + timestamp + nonce, private_key)
GET /v1/subscribe?conv_id=X&token=Y&pub_key=Z
Server verifies signature in the HTTP upgrade, streams immediately.
```

**Pros:** No extra round-trip (verification happens during WebSocket upgrade). Stateless verification.
**Cons:** Token could be replayed within its TTL. Need to define TTL/nonce policy.

### Option C: Status Quo (No Auth)
**Pros:** Simplest. E2E encryption provides content confidentiality regardless.
**Cons:** Traffic analysis exposure. Doesn't meet expectations of identity-focused developers (APS, AIP). Perception of engineering incompleteness.

## Recommended Option
**Option A (Challenge-Response)** — it's the strongest identity guarantee, uses existing relay primitives, and directly addresses what both external developers asked for. The 1 round-trip cost is negligible for WebSocket connections that last minutes/hours.

Implement as OPTIONAL: if `pub_key` param is present, require challenge-response. If absent, fall through to unauthenticated subscribe (backwards compatible).

## Expected Effect on Primary Metric
- Direct: enables APS integration (identity key → subscribe auth → encrypted relay). Unblocks potential first design partner conversation.
- Indirect: demonstrates engineering quality to external evaluators. Both responders are evaluating us partly on code quality.

## Cost / Impact
- ~100 lines in worker/src/index.ts (challenge generation, signature verification, participant check)
- ~50 lines in python-dist client (send pub_key + sign challenge)
- Tests: 5-10 new integration tests
- No infrastructure cost.

## Reversible or Irreversible?
Reversible — optional parameter, backwards compatible.

## Confidence
0.85 — high confidence this is the right feature. The only risk is over-engineering for two developers who may not convert to users.

## DRI
CEO (Founder)

## Review Date
Wave 21 (after implementation + feedback from aeoess/The-Nexus-Guard)

## Escalation Needed?
No — this is a protocol enhancement within existing architectural patterns. Not a cryptographic protocol change (uses same Ed25519 primitives). Not a strategy pivot.
