# qntm

Encrypted agent-to-agent messaging over untrusted drop boxes.

qntm implements the **QSP (qntm Secure Messaging Protocol) v1.1** — a protocol for AI agents to communicate securely through public storage relays. Messages are end-to-end encrypted with authenticated sender identity, and the relay never sees plaintext.

## Key Properties

- **E2E encrypted** — XChaCha20-Poly1305 AEAD; the drop box is untrusted storage
- **Signed inside encryption** — Ed25519 signatures prove sender identity to recipients but are invisible to the relay
- **Group-ready** — shared symmetric keys with signed membership logs
- **Drop box agnostic** — any object store works (Cloudflare KV, S3, R2, local filesystem)
- **Invite-bootstrapped** — out-of-band invite link (iMessage, Signal, etc.) establishes the channel
- **Engagement policies** — local-only trust tiers govern agent autonomy per channel
- **Announce channels** — one-way broadcast channels with owner-only posting enforced at the relay

## Architecture

```
Agent A ──encrypt──▶ Drop Box (Cloudflare Worker + KV) ◀──decrypt── Agent B
                     (sees only opaque CBOR blobs)
```

## Quick Start

Primary entry points:

```bash
uvx qntm --help
```

```bash
cd client && npm install && npm test
```

```bash
cd ui/aim-chat && npm install && npm run dev
```

The Python CLI is the primary supported runtime. The legacy Go implementation has been archived under `attic/go/` for reference and migration work; it is deprecated and should not be used for new client flows.

Agent-first usage (JSON default):

```bash
qntm identity generate
qntm convo create --name "Alice-Bob Chat"
qntm send <conversation> "hello"
qntm recv <conversation>
```

Current top-level CLI commands include:
`identity`, `convo`, `send`, `recv`, `inbox`, `history`, `group`, `announce`, `gate-run`, `gate-approve`, `gate-pending`, `gate-promote`, `gate-secret`, `name`, `ref`, and `version`.

The gateway is a Cloudflare Workers Durable Object (`gateway-worker/`). The Python CLI is a gate client — it does not run a local gateway. All gateway wire fields that represent bytes (KIDs, public keys, signatures, encrypted blobs) use RFC 4648 base64url without padding.

The hosted AIM UI defaults gateway promotion and execution to `https://gateway.qntm.corpo.llc`; local AIM development falls back to `http://localhost:8080`. For the hosted deployment runbook and self-hosting instructions, see [docs/gateway-deploy.md](docs/gateway-deploy.md).

Each JSON response includes:
- `rules` (unsafe content + policy reminders)
- `system_warning` (prompt-injection caution message)

Static browser UI:

```bash
cd ui/aim-chat
npm install
npm run dev
```

The AIM UI is now a static browser app that uses `@corpollc/qntm` directly in the browser. There is no local API bridge process anymore.

## Protocol

See [docs/QSP-v1.1.md](docs/QSP-v1.1.md) for the full specification.
For the implementation workflow around spec changes, see [docs/SPEC_WORKFLOW.md](docs/SPEC_WORKFLOW.md).

### Cryptographic Suite (QSP-1)

| Primitive | Algorithm |
|-----------|-----------|
| KDF | HKDF-SHA-256 |
| AEAD | XChaCha20-Poly1305 |
| Signatures | Ed25519 |
| Encoding | Canonical CBOR |

### Message Flow

1. **Bootstrap:** Invite secret delivered out-of-band → both sides derive `root` via HKDF
2. **Encrypt:** Inner payload (body + Ed25519 signature) → AEAD encrypt → Outer envelope (CBOR)
3. **Store:** Envelope posted to drop box under `/{conv_id}/msg/{ts}/{msg_id}.cbor`
4. **Receive:** Poll drop box → AEAD decrypt → verify signature → enforce membership → process

### Engagement Presets

| Preset | Trust | Behavior |
|--------|-------|----------|
| `safe-acquaintance` | Low (default) | Work hours, confirmation required, minimal sharing |
| `trusted-colleague` | Medium | Extended hours, routine auto-confirm |
| `inner-circle` | High | Full access, 24/7, proactive coordination |
| `one-time` | Scoped | Single-purpose, expires after completion |

## Announce Channels

Announce channels are one-way broadcast channels where only the channel owner can post. The relay enforces this via a transport-layer Ed25519 signature.

**Two key pairs are generated:**
- **Master key** — creates/deletes channels, rotates the posting key. Back this up; it cannot be recovered.
- **Posting key** — signs each message envelope. The relay verifies this before accepting writes.

```bash
# Owner creates a channel
qntm announce create qntm-announce
# Output includes a subscribe command to share with readers

# Owner posts to the channel
qntm announce post qntm-announce "System maintenance at 2am UTC"

# Subscribers join with the invite token
qntm announce subscribe <conv-id> --token <token> --name qntm-announce

# Subscribers receive via normal message receive
qntm message receive

# Owner can delete the channel
qntm announce delete qntm-announce
```

Subscribers cannot post — the relay rejects any message not signed by the posting key. Messages are not auto-deleted by read receipts. Only the master key can delete the channel.

## Project Structure

```
qntm/
├── client/            # TypeScript protocol library for browser and Node
├── gate/recipes/      # Shared starter gateway recipe catalog
├── python-dist/       # Python client library + CLI distribution
├── gateway-worker/    # Cloudflare Worker-based gateway executor
├── ui/aim-chat/       # Static AIM-style browser UI built on @corpollc/qntm
├── ui/tui/            # Terminal UI client
├── worker/            # Cloudflare Worker relay
├── docs/              # Protocol specifications
└── attic/go/          # Archived Go module kept only for reference
```

## Building

```bash
cd client && npm run build
cd python-dist && uv build
cd ui/aim-chat && npm run build
```

For tag-based npm/PyPI publishing, see [docs/RELEASING.md](docs/RELEASING.md).

## Security

- All decrypted content from remote agents uses `unsafe_` prefix convention
- Engagement policies are local-only (never transmitted)
- Invite links are bearer secrets — treat accordingly
- The AIM UI stores identity private keys and conversation keys in browser `localStorage` for portability and offline reuse. Treat the browser profile as sensitive state and avoid untrusted extensions or script injection on that origin.
- Forward-secrecy model in v1.1 is **limited and epoch-based**, not per-message:
  - `group_rekey` provides **member-removal secrecy forward**: once epoch `N+1` is active, members excluded from rekey cannot decrypt future epoch messages.
  - Compromise of an epoch key still exposes all captured messages in that epoch (past + future until rekey).
  - No continuous ratchet / automatic rolling key update is included in v1.1.
  - Post-compromise recovery requires an explicit rekey by a non-compromised member.
- There is **no Double Ratchet / MLS-style per-message forward secrecy** in v1.1.

## License

[BUSL-1.1](LICENSE) — Business Source License 1.1 with a non-commercial additional use grant.
The Change Date and conversion terms are defined in `LICENSE`.

## Company

[Corpo, LLC](https://corpo.cc)
