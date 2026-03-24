# relay-handoff — Multi-Host Agent Pipeline Handoff via qntm

Demonstrates the exact pattern for splitting a monolithic agent pipeline
across multiple hosts with authenticated, encrypted, receipted handoffs.

## The Problem

You have a multi-agent pipeline (e.g. Scout → Analyst → Copywriter → Messenger)
running on a single host with shared SQLite + in-process function calls. Now you
need to split agents across hosts — Messenger needs to live where WhatsApp runs,
Scanner near SerpAPI for rate limits. The in-process handoff breaks. You need a
transport layer.

## The Solution

Each agent gets a persistent cryptographic identity. Handoffs are encrypted
messages through the qntm relay. The receiving agent verifies the sender's
identity before processing — no shared database required, no HTTP callbacks
to manage, no polling. Just authenticated, encrypted, receipted delivery.

## Architecture

```
Host A (DigitalOcean)              Host B (WhatsApp server)
┌──────────────────┐               ┌──────────────────┐
│  Copywriter Agent│               │  Messenger Agent  │
│  (Ed25519 key)   │               │  (Ed25519 key)    │
│                  │    relay      │                   │
│  1. Finish copy  │──────────────▶│  3. Verify sender │
│  2. Sign + send  │   encrypted   │  4. Process work  │
│                  │   handoff     │  5. Send WhatsApp  │
└──────────────────┘               └──────────────────┘
                         │
                 ┌───────┴────────┐
                 │  qntm relay    │
                 │  (sees nothing)│
                 │  E2E encrypted │
                 └────────────────┘
```

## Files

- `handoff_sender.py` — Agent A: creates work artifact, signs it, sends via relay
- `handoff_receiver.py` — Agent B: subscribes to relay, verifies sender, processes
- `shared.py` — Common key derivation, CBOR encoding, crypto utilities

## Quick Start

```bash
# Install
pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"

# Agent A: generate identity + send a handoff
python handoff_sender.py

# Agent B (different host): subscribe + receive handoffs
python handoff_receiver.py
```

## Mapping to Your Pipeline

| Your Pipeline Step | This Example | What Changes |
|---|---|---|
| Copywriter finishes copy | `handoff_sender.py` sends work artifact | Replace sample payload with your work output |
| In-process function call | qntm relay (encrypted transport) | No code change — transparent to pipeline |
| Messenger receives work | `handoff_receiver.py` verifies + processes | Replace `process_handoff()` with your logic |
| Verify it's really Copywriter | Ed25519 signature check | Automatic — built into the protocol |

## Identity Verification

Every handoff includes:
1. **Ed25519 signature** — proves the sender has the private key
2. **sender_id** — `Trunc16(SHA-256(ed25519_pub))` links to a known identity
3. **DID resolution** (optional) — `did:web:yourdomain` → Ed25519 key → verify

The receiver maintains an allowlist of trusted sender_ids. Unknown senders
are rejected before decryption — defense in depth.

## Production Considerations

- Store identity keys in a secure location (env var, secret manager, HSM)
- Use `QNTM_HOME` env var to isolate identities per agent
- The relay is untrusted — it only sees opaque CBOR blobs
- Add `expiry_ts` to messages for time-bound validity (QSP-1 v1.0 §5.2)
- For audit trails, combine with Entity Verification (Corpo API) and
  Compliance Receipts (WG draft spec)
