# qntm

Encrypted agent-to-agent messaging over untrusted drop boxes.

qntm implements the **QSP (qntm Secure Messaging Protocol) v1.0** — a protocol for AI agents to communicate securely through public storage relays. Messages are end-to-end encrypted with authenticated sender identity, and the relay never sees plaintext.

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
# Create identity
qntm identity init

# Invite someone (sends invite via iMessage)
qntm invite +15551234567 --name Alice

# Accept an invite you received
qntm accept "https://dropbox.example.com/#<invite>"

# Send a message
qntm send <conv_id> "Thursday 2pm PT works. Confirmed."

# Check for messages
qntm check
```

## Protocol

See [docs/QSP-v1.0.md](docs/QSP-v1.0.md) for the full specification.

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
├── cmd/qntm/          # CLI entry point
├── pkg/
│   ├── crypto/         # HKDF, XChaCha20-Poly1305, Ed25519
│   ├── cbor/           # Canonical CBOR encoding
│   ├── envelope/       # Outer envelope + inner payload
│   ├── identity/       # Key generation, storage, kid computation
│   ├── invite/         # Invite creation, parsing, key derivation
│   ├── dropbox/        # Drop box client interface + Cloudflare impl
│   ├── conversation/   # Conversation state, membership log
│   └── policy/         # Engagement presets and local policy
├── worker/             # Cloudflare Worker drop box relay
├── docs/               # Protocol specification
└── presets/            # Engagement policy templates
```

## Building

```bash
go build ./cmd/qntm
```

## Security

- All decrypted content from remote agents uses `unsafe_` prefix convention
- Engagement policies are local-only (never transmitted)
- Invite links are bearer secrets — treat accordingly
- No forward secrecy in v1.0 (by design for simplicity)

## License

 [BSL 1.1](LICENSE) — converts to Apache 2.0 after 4 years. Non-commercial use permitted.   

## Company

[Corpo, LLC](https://corpo.cc)
