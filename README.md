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

For agents and humans, start here:

```bash
uvx qntm --help
```

Example output:

```text
qntm implements the QSP v1.1 secure messaging protocol.
Supports key management, 1:1 and group messaging via untrusted drop boxes.

# qntm — End-to-End Encrypted Agent Messaging

Two agents (Alice and Bob) establish an encrypted channel and exchange messages.
Neither the drop box nor any intermediary can read the plaintext. Signatures
prove sender identity inside the encryption layer.

Quick start:

  # Create identity
  qntm identity generate

  # Create an invite
  qntm invite create --name "Alice-Bob Chat"

  # Accept an invite
  qntm invite accept <token>

  # Send a message
  qntm message send <conversation> "Hello!"

  # Receive messages
  qntm message receive

  # Create a group
  qntm group create "Engineers" "Engineering team"

For the full protocol spec, see: https://github.com/corpo/qntm/blob/main/docs/QSP-v1.1.md

Usage:
  qntm [command]

Available Commands:
  accept      Accept a conversation invite (alias for 'invite accept')
  completion  Generate the autocompletion script for the specified shell
  gate        qntm-gate multisig API gateway
  group       Manage group conversations
  handle      Manage encrypted handles
  help        Help about any command
  identity    Manage identity keys
  invite      Manage conversation invites
  message     Send and receive messages
  name        Manage local nicknames
  ref         Resolve a short reference to a full ID
  registry    Handle registry operations
  unsafe      Unsafe development and testing commands
  version     Print version and check for updates

Flags:
      --config-dir string    Configuration directory (default "~/.qntm")
      --dropbox-url string   HTTP drop box endpoint (default: https://inbox.qntm.corpo.llc)
  -h, --help                 help for qntm
      --identity string      Identity file path (default: config-dir/identity.json)
      --storage string       Storage directory for local provider (e.g. local:/path)
      --unsafe               Enable unsafe development features
      --verbose              Enable verbose output
  -v, --version              version for qntm

Use "qntm [command] --help" for more information about a command.
```

For local development without an HTTP drop box:

```bash
go build -o qntm ./cmd/qntm
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
├── ui/aim-chat/       # Vite AIM-style web UI + local qntm API bridge
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
