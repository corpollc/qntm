# Agent Identity Working Group — Shared Specs

Four founding projects, five OATR-registered members. One interop surface. Code-first.

## Members

| Project | Domain | Maintainer | Status | OATR |
|---------|--------|------------|--------|------|
| [qntm](https://github.com/corpollc/qntm) | Encrypted transport | @vessenes | Founding | ✅ |
| [Agent Passport System](https://github.com/aeoess/agent-passport-system) | Self-sovereign identity + delegation | @aeoess | Founding | ✅ |
| [AgentID](https://github.com/haroldmalikfrimpong-ops/getagentid) | CA-issued identity + trust scores | @haroldmalikfrimpong-ops | Founding | ✅ |
| [Open Agent Trust Registry](https://github.com/FransDevelopment/open-agent-trust-registry) | Trust registry + attestation CA | @FransDevelopment | Founding | ✅ (maintainer) |
| [ArkForge](https://trust.arkforge.tech) | Execution attestation | @desiorac | Proposed founding | ✅ |

### Candidates

| Project | Domain | Maintainer | Status | OATR |
|---------|--------|------------|--------|------|
| [AIP](https://github.com/The-Nexus-Guard/aip) | DID resolution service | @The-Nexus-Guard | Invited ([aip#5](https://github.com/The-Nexus-Guard/aip/issues/5)) | — |
| [Agent Agora](https://the-agora.dev) | Agent discovery registry | @archedark-ada | OATR registered | ✅ |

## Principles

1. **Code-first, not committee-first.** The WG produces shared specs, test vectors, and reference code — not position papers. If it can't be verified by running code, it's not ready.
2. **Independent projects, shared interfaces.** Nobody merges. Each project owns its domain. The WG defines the interop surface: envelope format, DID resolution, key derivation, relay protocol.
3. **Living spec, not frozen standard.** Specs evolve with implementations, not ahead of them.
4. **Open membership.** Anyone who ships compatible code joins. No applications, no votes. Ship and you're in.

## Scope (v1)

| Layer | Owner | Status |
|-------|-------|--------|
| Discovery | Agent Agora (OATR registered) | Live endpoints (`did:web:the-agora.dev`), tiered verification (ERC-8004 + DNS + DID) |
| Identity (CA-issued) | AgentID | Proven |
| Identity (self-sovereign) | APS | Proven |
| Identity (DID resolution) | AIP (candidate) | Live service (`did:aip` method) |
| DID cross-verification | AgentID + APS | Proven (10/10 checks) |
| Encrypted transport | qntm | Proven |
| Encrypted transport spec | OATR | [Spec 10](https://github.com/FransDevelopment/open-agent-trust-registry/blob/main/spec/10-encrypted-transport.md) — registry-bound channel auth (merged) |
| Proof of key ownership | OATR | [Spec 11](https://github.com/FransDevelopment/open-agent-trust-registry/blob/main/spec/11-proof-of-key-ownership.md) — permissionless issuer registration verification |
| Key derivation (HKDF) | Shared | 3 implementations verified |
| Envelope format (QSP-1) | qntm (with WG input) | Spec v1.0-rc1 (pending ratification) |
| Trust registry | OATR | Ed25519 attestation CA, threshold governance, proof-of-key CI |
| Entity formation | [Corpo](https://corpo.llc) | Staging API live |
| Execution attestation | [ArkForge](https://trust.arkforge.tech) (OATR registered) | Live service, Ed25519 + Sigstore/Rekor, [DID binding shipped](https://github.com/ark-forge/trust-layer/pull/18) |

## Specs

- [`qsp1-envelope.md`](./working-group/qsp1-envelope.md) — QSP-1 envelope format (CBOR wire format, crypto ops, transport)
- [`did-resolution.md`](./working-group/did-resolution.md) — DID method resolution interface
- [`entity-verification.md`](./working-group/entity-verification.md) — Legal entity verification via Corpo API

## Test Vectors

- [`ed25519-x25519-derivation.json`](./test-vectors/ed25519-x25519-derivation.json) — Ed25519 → X25519 key derivation (5 vectors, 3 implementations)
- [`hkdf-key-derivation.json`](./test-vectors/hkdf-key-derivation.json) — HKDF key derivation from invite material
- [`entity-verification.json`](./test-vectors/entity-verification.json) — Entity API response format
- [`verify_aip_interop.py`](./test-vectors/verify_aip_interop.py) — AIP ↔ qntm Ed25519→X25519 interop (3/3 known-answer vectors)

## Integration Test Infrastructure

- **Echo bot:** `https://qntm-echo-bot.peter-078.workers.dev` (Cloudflare Worker, always-on)
- **Test conversation:** `dca83b70ccd763a89b5953b2cd2ee678`
- **Entity staging API:** `https://api.corpo.llc/api/v1/entities/{entity_id}/verify`
- **Relay:** `wss://inbox.qntm.corpo.llc/v1/subscribe` / `https://inbox.qntm.corpo.llc/v1/send`

## How to Join

Ship code that implements one or more WG specs. Open an issue or PR on any member project. You're in.

## Origin

Proposed by @haroldmalikfrimpong-ops on [A2A #1672](https://github.com/a2aproject/A2A/issues/1672). Endorsed by all three founding projects.
