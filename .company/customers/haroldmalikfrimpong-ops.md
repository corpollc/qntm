# Design Partner: haroldmalikfrimpong-ops (AgentID / getagentid.dev)
First contact: Wave 22 (reply on A2A#1672)
Status: ACTIVE DESIGN PARTNER — PR merged, relay proven

## Profile
- Project: [getagentid](https://github.com/haroldmalikfrimpong-ops/getagentid)
- Platform: getagentid.dev
- Stack: Python, Ed25519, X3DH, Double Ratchet, NaCl
- Activity: Extremely high. Ships code within hours of discussion.

## What They Built
- 809-line AgentID→qntm encrypted chat demo (wave 25)
- Relay test script: HKDF 3/3, HTTP 201, live message exchange (wave 26)
- DID cross-verification: `did:agentid` ↔ `did:aps`, 10/10 checks, 82 tests (wave 27)
- PR #3 on corpollc/qntm — AgentID bridge example (wave 27, MERGED)

## What They Use qntm For
- Encrypted relay transport for AgentID-verified agents
- Interop proof: AgentID identity → qntm encrypted channel
- Not using qntm CLI — using relay as infrastructure

## Key Quotes
- "Complementary pieces, not competing ones" (wave 22)
- "Three identity systems, one encrypted channel" (wave 26)

## Threads
- A2A#1672 (primary): https://github.com/a2aproject/A2A/issues/1672
- APS#5 (cross-pollination): https://github.com/aeoess/agent-passport-system/issues/5

## Lessons
- Fastest contributor cycle: concept → shipped code → PR in 2 waves
- Self-directed — built DID interop without being asked
- Network node — connects to crewAI, AgentID, A2A, APS simultaneously
- Prefers Python, minimal dependencies (NaCl + cryptography only)
- Updated his CBOR to native qntm field names voluntarily
