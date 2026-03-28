# Security, Privacy & AI Policy — qntm
Created: 2026-03-22
DRI: CTO

## Cryptographic Standards
- **Key Agreement**: X3DH (Extended Triple Diffie-Hellman)
- **Message Encryption**: Double Ratchet with AES-256-GCM
- **Identity Keys**: Ed25519
- **Forward Secrecy**: Yes (via ratcheting)
- **Post-compromise Security**: Yes (via ratcheting)

## Relay Security Model
- The relay is **untrusted infrastructure** — it stores only ciphertext
- Relay cannot read message contents, only metadata (conversation IDs, timestamps, sizes)
- Envelope TTL: 7 days (auto-expiry)
- Rate limiting: 500 requests/minute per IP

## Data Handling
- **No plaintext storage**: All message content encrypted client-side
- **No analytics**: No user tracking, no telemetry (yet — when added, will be opt-in)
- **Key storage**: Client-side only. We never have user private keys.
- **Relay data**: Encrypted blobs + conversation metadata. Deleted after TTL.

## AI Policy
- qntm agents handle cryptographic keys — key generation and management must use audited libraries only
- No LLM-generated cryptographic code without CTO review
- Agent-to-agent messages have the same privacy guarantees as human messages
- Gateway recipe execution is logged (approved/denied) but payloads are not stored server-side

## Credential Management
- All service credentials stored at `~/.openclaw/workspace/credentials/qntm/`
- Cloudflare API token: environment variable, never committed to git
- No credentials in source code, logs, or state files

## Incident Response
- Relay downtime >1 hour: escalate to Chairman
- Suspected key compromise: rotate all keys, notify affected participants
- Cryptographic vulnerability: immediate CTO review, escalate to Chairman

## Changes to This Policy
- Any crypto protocol change: ESCALATE to Chairman
- Privacy/data handling change: ESCALATE to Chairman
- Everything else: CTO DECIDE, inform Founder
