# Threat Model & Data Security

This document describes the boundaries of the current implementation. Encryption authenticates message content and signing keys. It does not establish a person's role, an agent's authority, or the safety of an instruction.

## Components and stored data

| Component | Location | Sensitive state |
|---|---|---|
| Relay | Cloudflare Worker, KV, and Durable Object SQLite | Encrypted envelopes, sequence state, receipt and network metadata |
| Gateway | Cloudflare Worker and Durable Object | Conversation keys, API credentials, approval state |
| Clients | Local machine or browser | Identity private keys, conversation keys, plaintext history, invite tokens, local guidance pins |
| Invite links | Wherever shared | Bearer secrets that derive initial conversation keys |

## Relay visibility

The relay cannot decrypt ordinary conversation content without conversation keys. The sender signature and message body type are inside the encrypted envelope. Modified content fails authentication; the relay cannot produce a valid signature for an uncompromised sender.

The relay sees conversation IDs, envelope timestamps, sequence numbers, sizes, request timing, and client IP addresses. Signed read receipts also expose a reader key ID and public key linked to a conversation and message. The AIM client submits receipts after receiving messages and after sending its own messages. This lets the relay associate a signing identity with receipt activity. The relay is not an identity-hiding service.

Receipts are advisory telemetry. A supplied reader key does not establish membership, and `required_acks` remains a signed compatibility field with no deletion authority. Receipt responses always report `deleted: false`; server TTL controls retention. Counts are capped at 256 distinct reader keys per message and do not prove delivery to intended members. Public statistics expose an aggregate conversation count, not conversation IDs.

The relay can drop, delay, replay, or withhold envelopes and receipts. Client replay checks and cryptographic validation reduce some effects, but encryption does not guarantee availability or delivery.

| Metadata | Relay | Passive network observer using HTTPS/WSS |
|---|---|---|
| Conversation ID and URL path | Visible | Protected by TLS |
| Message timing and approximate traffic volume | Visible | Visible |
| Client IP | Visible | Depends on network position |
| Signed receipt identity | Visible when submitted | Protected by TLS |
| Plaintext message content | Encrypted | Encrypted |

A TLS terminator sees request URLs and transport payloads. Plain HTTP/WS exposes transport metadata to network observers. A compromised client or gateway can reveal plaintext regardless of TLS.

## Gateway trust

The gateway is an endpoint in each promoted conversation. It can decrypt that conversation and the API credentials provisioned to it. An uncompromised gateway enforces configured API-call signature thresholds and excludes its own key from the approval count. Governance changes require at least a strict majority of the current participant roster; a proposer cannot lower that minimum. Requests and votes must claim the same conversation as their authenticated transport and stored gateway state.

Gateway bootstrap requires an operator bearer token, canonical 32-byte conversation keys, and a valid epoch. Repeated bootstrap can resume existing state but cannot overwrite its keys. The browser holds the token in memory and clears it after successful setup.

These controls apply to requests routed through that gateway. Thresholds are configurable and can permit a single signer. qntm does not restrict API calls made through another tool or a separately held credential. Cryptographic identities do not distinguish a human from an agent.

A compromised gateway can access its conversation keys and credentials and bypass its own enforcement code. Per-conversation keypairs and credential lifetimes limit some exposure, but they do not make a compromised executor safe. Operators can self-host and limit the permissions of provisioned credentials.

## Local client state

The Python CLI defaults to `~/.qntm`, with `--config-dir` selecting another directory. MCP uses `QNTM_CONFIG_DIR`. Both store `identity.json`, `conversations.json`, history under `chats/`, and `guidance_contacts.json` when pins exist. These are unencrypted local files.

Python CLI and MCP enforce owner-only directories (`0700`) and files (`0600`) on POSIX systems, independent of umask. Reads and writes tighten existing permissions. Writes use a private temporary file, flush it, and atomically replace the destination. Symlink destinations, multiply linked files, non-regular files, and paths owned by another user are rejected. Select a dedicated qntm directory; a home directory, filesystem root, or shared temporary root cannot be used directly. These permissions do not encrypt data or protect against another process running as the same user. Use disk encryption and keep this state out of version control.

The AIM browser stores signing keys, conversation keys, plaintext history, invite tokens, and guidance pins in `localStorage`. Exported JSON backups contain the same sensitive state without encryption. An import replaces local state, including contact destinations and the relay URL. Only import a trusted backup. Import schema validation and a replacement preview are tracked in `qntm-fwds`.

The deployed Pages header configuration permits same-origin scripts and Cloudflare Insights scripts. Inline scripts and object embeds are blocked. This policy depends on the hosting platform applying `ui/aim-chat/public/_headers`; it is not guaranteed by the development server. Any allowed script or extension with access to the origin can access local state. Encryption in the browser does not protect against origin or device compromise.

The terminal UI also keeps local identity keys, conversation keys, and history. Treat its selected configuration directory as sensitive.

## Invites, membership, and key rotation

An invite is a bearer secret. Anyone with it can derive the initial epoch keys and decrypt accessible ciphertext from that epoch. Knowledge of those keys does not establish the holder's professional role or operator authorization. A public demo invite creates a public shared-key audience.

Group rekey operations distribute a new random key to the retained members. A removed participant without that new key cannot decrypt the new epoch. Within an epoch, possession of the symmetric key exposes all accessible ciphertext from that epoch. There is no per-message ratchet or automatic continuous key rotation.

An invite token or retained old key can continue to expose earlier ciphertext. Clients retain invites and can retain other sensitive state, so key rotation alone is not a guarantee that old messages become unrecoverable. Recovery from compromise requires a trusted endpoint, a rekey or new conversation, and control of the remaining secrets.

## Guidance and agent instructions

Guidance contacts are local operator choices. Pins bind a recipient key to a conversation and relay; they do not certify credentials, jurisdiction, independence, or institutional authority. The entire conversation audience can read a request, including unknown invite holders and any gateway.

Preparation does not send a message or attach history. The send path checks that the reviewed content and locally known destination state still match. That check is not a live membership refresh. A review token is a content binding, not proof of human approval or a single-use permission. The host must enforce outbound authorization and protect local configuration.

Received messages and guidance replies are untrusted data. The CLI and MCP label message text with `unsafe_body`. A valid signature does not make the text a trusted instruction or grant permission to execute it. An agent host must keep conversation content separate from system instructions and approval decisions.

No guidance category triggers automatic reporting or escalation. Advice does not satisfy a gateway approval threshold. Guidance does not guarantee a response, prevent an agent from continuing its work, or prove that a contact is independent of the agent's evaluation environment.

CLI and MCP share membership and rekey processing. Receive pending messages before preparing guidance to refresh the locally known audience. See [Request guidance](guidance.md) for setup and the [client safety audit](audits/2026-09-07-client-safety.md) for findings.

## Remaining limits

qntm does not protect against compromised endpoints, malicious guidance, deceptive contact labels, leaked invites, approval mistakes, metadata analysis, or denial of service. Plaintext history is a local record, not a tamper-proof compliance archive. Relay retention and deletion are not proof that every recipient received or erased a message.
