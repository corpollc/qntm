# Threat Model & Data Security

This document describes what qntm protects, what it does not protect, and what each participant should expect from the system. It is organized by interface so you can jump to the section relevant to your use case.

---

## System Overview

qntm has four components that handle sensitive data:

| Component | Runs where | Stores what |
|-----------|-----------|-------------|
| **Relay** | Cloudflare Worker + KV | Encrypted CBOR envelopes (opaque blobs) |
| **Gateway** | Cloudflare Worker + Durable Object | Conversation keys, sealed API credentials, approval state |
| **Clients** (CLI, Web UI, TUI) | User's machine or browser | Identity private keys, conversation keys, decrypted message history |
| **Invite links** | Wherever the user shares them | Bearer secret that derives conversation keys |

---

## What the Relay Sees

The relay is **untrusted by design**. It is a dumb store-and-forward service.

**The relay can see:**
- Conversation IDs (which channel a message belongs to)
- Envelope timestamps and sequence numbers
- Envelope sizes
- IP addresses of senders and pollers
- Polling frequency and patterns

**The relay cannot see:**
- Message plaintext
- Sender identity (the Ed25519 signature is inside the encrypted envelope)
- Message body type (text, gate request, governance proposal, etc.)
- Which specific participant sent a message

**If the relay is compromised:** An attacker gets encrypted blobs and metadata. They learn who is talking to whom (by IP/conversation ID) and when, but not what is being said. They cannot forge messages because they lack signing keys. They cannot decrypt messages because they lack conversation keys.

---

## What the Gateway Sees

The gateway is a **trusted-but-constrained** participant. It holds conversation keys and sealed API credentials.

**The gateway can see:**
- Decrypted message content for conversations it has been promoted into
- API credentials (encrypted to its public key, decrypted at execution time)
- Request and approval signatures
- Participant public keys and key IDs

**The gateway cannot do:**
- Approve its own requests (excluded from m-of-n threshold)
- Create or refresh API credentials (only humans can provision secrets)
- Act without reaching the approval threshold
- Access conversations it has not been promoted into

**If the gateway is compromised:** An attacker gains access to decrypted messages and API credentials for all promoted conversations on that gateway instance. This is the most sensitive component. Mitigations:
- Each conversation gets an isolated gateway keypair
- API credentials can have TTLs (15min, 60min, 4hr) to limit exposure windows
- The gateway is open source and auditable
- Self-hosting is supported for high-security deployments

---

## Client Security

### Python CLI

**Stores on disk:**
- Identity private key (Ed25519, 64 bytes) in `~/.config/qntm/identity.json`
- Conversation records with symmetric keys in `~/.config/qntm/conversations.json`
- Message history in `~/.config/qntm/chats/`
- Stored invite tokens for re-sharing

**Protect by:** File permissions, full-disk encryption, treating `~/.config/qntm/` as sensitive. Do not commit this directory to version control.

### Web UI (AIM)

**Stores in browser:**
- Identity private key in `localStorage`
- Conversation keys in `localStorage`
- Message history in `localStorage`
- Stored invite tokens for re-sharing

**Protect by:** Treating the browser profile as sensitive state. Avoid untrusted extensions on the origin. The Content Security Policy blocks inline scripts, external scripts, and object embeds. All crypto runs in-browser — no server-side component.

### Terminal UI (TUI)

**Stores on disk:**
- Same as the Python CLI: identity, conversation keys, and history in a config directory

---

## Metadata Exposure

qntm encrypts message **content** but does not hide all **metadata**.

| Metadata | Visible to relay | Visible to network observers |
|----------|-----------------|------------------------------|
| Conversation ID | Yes | Yes (in request URL) |
| Message timing | Yes | Yes |
| Message size | Yes | Yes |
| Sender IP | Yes | Depends on network path |
| Sender identity | No | No |
| Message content | No | No |
| Participant count | Inferrable from polling patterns | Inferrable |

**What this means:** An observer who can see relay traffic knows that *someone* is messaging in a particular conversation at a particular time. They do not know who the sender is (within the conversation) or what is being said. If IP-level privacy is required, route through a VPN or Tor.

---

## Invite Link Security

Invite links are **bearer secrets**. Anyone who possesses an invite link can:
- Derive the conversation's symmetric keys
- Join the conversation and read all past and future messages (for that epoch)
- Send messages as a new participant

**Treat invite links like passwords.** Share them over a trusted side-channel (Signal, iMessage, in person). Do not post them publicly. If an invite link is compromised, create a new conversation and migrate.

---

## Forward Secrecy

qntm v1.1 provides **epoch-based** forward secrecy, not per-message.

- When a member is removed, a `group_rekey` rotates the conversation keys to a new epoch
- The removed member cannot decrypt messages sent after the rekey
- **Within an epoch**, all messages use the same symmetric key — compromise of that key exposes all messages in the epoch
- There is no continuous ratchet or automatic key rotation in v1.1
- Post-compromise recovery requires an explicit rekey by a non-compromised member

**What this means:** If an attacker captures encrypted traffic and later obtains an epoch key, they can decrypt all messages from that epoch. This is a known limitation of the v1.1 protocol. Per-message forward secrecy (Double Ratchet / MLS-style) is not included.

---

## What qntm Does Not Protect Against

- **Endpoint compromise:** If an attacker controls a participant's device, they have the private key and can read all messages. This is true of all E2E encryption systems.
- **Metadata analysis:** Conversation IDs, timing, and message sizes are visible to the relay and network observers.
- **Social engineering:** If someone is tricked into sharing an invite link or approving a gateway request, the cryptography cannot help.
- **Relay availability:** The relay can drop or delay messages. It cannot forge or modify them (modifications are detected by AEAD authentication), but it can deny service.
- **Side-channel attacks:** Timing attacks on the relay, browser fingerprinting, and similar side channels are not addressed by the protocol.
