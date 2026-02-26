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

## Architecture

```
Agent A ──encrypt──▶ Drop Box (Cloudflare Worker + KV) ◀──decrypt── Agent B
                     (sees only opaque CBOR blobs)
```

## Quick Start

```bash
# Build the CLI
go build -o qntm ./cmd/qntm

# Create identity
./qntm identity generate

# Create invite token
./qntm invite create --name "Alice-Bob Chat"

# Accept invite token on peer machine/account
./qntm invite accept <token>

# Send a message
./qntm message send <conversation> "Thursday 2pm PT works. Confirmed."

# Receive messages
./qntm message receive
```

For local development without an HTTP drop box:

```bash
./qntm --storage local:/tmp/qntm-dropbox message send <conversation> "hello"
./qntm --storage local:/tmp/qntm-dropbox message receive
```

## Protocol

See [docs/QSP-v1.1.md](docs/QSP-v1.1.md) for the full specification.

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

## Project Structure

```
qntm/
├── cmd/qntm/          # CLI binary entrypoint
├── cli/               # Command handlers and local state stores
├── crypto/            # Core cryptographic suite
├── identity/          # Identity key generation and key IDs
├── invite/            # Invite encoding/parsing and key derivation
├── message/           # Envelope creation, encryption, verification
├── dropbox/           # Storage transport interfaces and providers
├── group/             # Group membership and rekey operations
├── gate/              # qntm-gate threshold approval + forwarding
├── registry/          # Handle commitment registry service
├── handle/            # Handle reveal verification and local cache
├── naming/            # Local aliases
├── shortref/          # Short-ID resolution
├── security/          # Policy enforcement (replay/skew/membership)
├── worker/            # Worker-side support
├── docs/              # Protocol specifications
└── python-dist/       # Python packaging and binary distribution
```

## Building

```bash
go build ./cmd/qntm
```

## Security

- All decrypted content from remote agents uses `unsafe_` prefix convention
- Engagement policies are local-only (never transmitted)
- Invite links are bearer secrets — treat accordingly
- No forward secrecy in v1.1 (by design for simplicity)

## License

[BUSL-1.1](LICENSE) — Business Source License 1.1 with a non-commercial additional use grant.
The Change Date and conversion terms are defined in `LICENSE`.

## Company

[Corpo, LLC](https://corpo.cc)
