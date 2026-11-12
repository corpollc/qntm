# Threat Model & Data Security

This document describes the boundaries of the current implementation. Encryption authenticates message content and signing keys. It does not establish a person's role, an agent's authority, or the safety of an instruction.

## Components and stored data

| Component | Location | Sensitive state |
|---|---|---|
| Relay | Cloudflare Worker, KV, and Durable Object SQLite | Encrypted envelopes, sequence state, receipt and network metadata |
| Gateway | Cloudflare Worker and Durable Object | Conversation keys, API credentials, approval state |
| Clients | Local machine or browser | Identity private keys, conversation keys, plaintext history, invite tokens, local guidance pins |
| Corpo guidance intake (opt-in) | Public intake relay channel + Corpo listener / Grok triage | Outer sender identity, timing, and size on the public intake channel; decrypted question, context, and private follow-up invite inside Corpo's operator and Grok triage boundary |
| Invite links | Wherever shared | Bearer secrets that derive initial conversation keys |

## Relay visibility

The [field-by-field metadata inventory](metadata-privacy.md) distinguishes what the relay can observe, what it persists, what metrics export, and what remains subject to provider logging/recovery. Aggregate dashboards do not imply that the relay holds only aggregate data.

The relay cannot decrypt ordinary conversation content without conversation keys. The sender signature and message body type are inside the encrypted envelope. Modified content fails authentication; the relay cannot produce a valid signature for an uncompromised sender.

The relay sees conversation IDs, envelope timestamps, sequence numbers, sizes, request timing, and client IP addresses. Signed read receipts also expose a reader key ID and public key linked to a conversation and message. The AIM client submits receipts after receiving messages and after sending its own messages. This lets the relay associate a signing identity with receipt activity. The relay is not an identity-hiding service.

Receipts are advisory telemetry. A supplied reader key does not establish membership, and `required_acks` remains a signed compatibility field with no deletion authority. Receipt responses always report `deleted: false`; server TTL controls retention. Counts are capped at 256 distinct reader keys per message and do not prove delivery to intended members. Public statistics expose an aggregate conversation count, not conversation IDs.

The relay source now uses expiry alarms for SQLite ciphertext and associated message-ID/reader-ID records, plus expiry checks on reads. KV ciphertext has a separate TTL. Sequence counters and announce registration metadata persist. The aggregate statistics store internally contains recent conversation IDs even though its public response is only a count. Per-isolate rate limiting also keeps IP addresses in memory; provider request logs and backups are a separate retention boundary. See [retention and rollout details](relay-operations.md#content-and-metadata-expiry), including dormant legacy objects and the distinction between logical expiry and provider recovery copies. This source change is not evidence that a hosted deployment has already applied it.

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

The gateway's `conv_state` persists its signing private key, conversation keys, participant roster and rules. `msg:` and `gov:` records persist decrypted request, approval and proposal bodies without a content TTL. API responses are read in plaintext during execution and posted back to the conversation encrypted; execution markers and write-ahead records also persist. Credentials in `vault:` are encrypted at rest under a key available to the gateway operator; credentials can have an explicit expiry, while an empty expiry currently means no expiry. Relay expiry does not erase any of this gateway state.

A company that keeps its working content outside Corpo custody should use a company-controlled executor or another operator it explicitly chooses. Adding the hosted gateway adds that operator to the company's content and credential trust boundary. Ordinary encrypted group conversation and director document review do not require a gateway.

Gateway setup requires a participant-signed invitation in the conversation and matching access material sealed to the invited gateway. The gateway validates the invitation, then signs its acceptance in chat. No operator admission token is required. Repeated setup can resume the same invitation but cannot overwrite an active conversation's keys. The invitation proves a conversation keyholder asked the gateway to join; it does not independently prove every participant consented. See [gateway invitations](gateway-invitations.md).

These controls apply to requests routed through that gateway. Thresholds are configurable and can permit a single signer. qntm does not restrict API calls made through another tool or a separately held credential. Cryptographic identities do not distinguish a human from an agent.

A compromised gateway can access its conversation keys and credentials and bypass its own enforcement code. Per-conversation keypairs and credential lifetimes limit some exposure, but they do not make a compromised executor safe. Operators can self-host and limit the permissions of provisioned credentials.

## Local client state

The Python CLI defaults to `~/.qntm`, with `--config-dir` selecting another directory. MCP uses `QNTM_CONFIG_DIR`. Both store `identity.json`, `conversations.json`, history under `chats/`, and `guidance_contacts.json` when pins exist. These are unencrypted local files.

Python CLI and MCP enforce owner-only directories (`0700`) and files (`0600`) on POSIX systems, independent of umask. Reads and writes tighten existing permissions. Writes use a private temporary file, flush it, and atomically replace the destination. Symlink destinations, multiply linked files, non-regular files, and paths owned by another user are rejected. Select a dedicated qntm directory; a home directory, filesystem root, or shared temporary root cannot be used directly. These permissions do not encrypt data or protect against another process running as the same user. Use disk encryption and keep this state out of version control.

The AIM browser stores signing keys, conversation keys, plaintext history, invite tokens, and guidance pins in `localStorage`. Settings exports password-encrypted backups; legacy JSON backups and the low-level raw export API remain plaintext. Imports undergo bounded schema/key validation and a replacement review showing identities, counts and destinations. Restore replaces messaging state, including the relay URL, only after confirmation and refuses a stale review. Validation cannot establish the authenticity of imported plaintext history or local trust decisions. Only import a trusted backup. See [browser backups](browser-backups.md) for the format and limits.

The deployed Pages header configuration permits same-origin scripts and Cloudflare Insights scripts. Inline scripts and object embeds are blocked. This policy depends on the hosting platform applying `ui/aim-chat/public/_headers`; it is not guaranteed by the development server. Any allowed script or extension with access to the origin can access local state. Encryption in the browser does not protect against origin or device compromise.

The terminal UI also keeps local identity keys, conversation keys, and history. Treat its selected configuration directory as sensitive.

## Invites, membership, and key rotation

An invite is a bearer secret. Anyone with it can derive the initial epoch keys and decrypt accessible ciphertext from that epoch. Knowledge of those keys does not establish the holder's professional role or operator authorization. A public demo invite creates a public shared-key audience.

Group rekey operations distribute a new random key to the retained members. A removed participant without that new key cannot decrypt the new epoch. Within an epoch, possession of the symmetric key exposes all accessible ciphertext from that epoch. There is no per-message ratchet or automatic continuous key rotation.

An invite token or retained old key can continue to expose earlier ciphertext. Clients retain invites and can retain other sensitive state, so key rotation alone is not a guarantee that old messages become unrecoverable. Recovery from compromise requires a trusted endpoint, a rekey or new conversation, and control of the remaining secrets.

## Guidance and agent instructions

Guidance supports two distinct destination models, both requiring explicit prepare/review/send action:

- **Operator-pinned contacts (`guidance_contacts.json`):** Local operator choices binding a label and category to a recipient key ID, an existing conversation, and a relay URL. Pins do not certify credentials, jurisdiction, independence, or institutional authority. Requests are sent as ordinary conversation messages: the entire conversation audience can read them, including unknown invite holders and any promoted gateway.
- **Built-in Corpo intake providers (`guidance_providers.json` / `CORPO_GUIDANCE_PROVIDERS`):** Shipped since v0.9.4 for `corpo_legal`, `corpo_ethical`, and `corpo_law_enforcement` on `https://inbox.qntm.corpo.llc`. Each request generates and locally retains a dedicated per-request direct reply conversation (`reply_invite`, bound to the requester's signing key), then seals `{domain, category, recipient_key_id, request_id, reply_invite, question, context}` to the category recipient's pinned public key via qntm's authenticated NaCl box (`guidance.sealed.v1`) before posting to that category's public intake conversation. Because the outer intake invitation is public, any holder of the public intake invite can decrypt the outer QSP envelope and observe the requester's `sender_ik_pk` / `sender_kid`, `guidance.sealed.v1` body type, submission timing, and approximate payload size, while they cannot decrypt the inner NaCl-boxed question, context, or private follow-up invitation. Static-key NaCl box encryption does not provide forward secrecy if either identity private key is later compromised.
- **Downstream Corpo operator and automated triage boundary:** Corpo's intake listener decrypts `guidance.sealed.v1` submissions and sends the submitted `question` and `context` to **Grok** for automated triage and summarization for the Corpo team; any follow-up occurs in the dedicated per-request direct conversation rather than the public intake channel. Selecting a built-in `corpo_*` destination places the submitted text, sender identity, and follow-up channel inside Corpo's operator custody and Grok's external model-processing trust boundary, with no legal privilege, confidentiality guarantee, emergency handling, or response SLA. See [sealed intake](guidance-intake.md).

Preparation does not send a message or attach history. The send path checks that the reviewed content and locally known destination state still match. That check is not a live membership refresh. A review token is a content binding, not proof of human approval or a single-use permission. The host must enforce outbound authorization and protect local configuration.

Received messages and guidance replies are untrusted data. The CLI and MCP label message text with `unsafe_body`. A valid signature does not make the text a trusted instruction or grant permission to execute it. An agent host must keep conversation content separate from system instructions and approval decisions.

No guidance category triggers automatic reporting or escalation. Advice does not satisfy a gateway approval threshold. Guidance does not guarantee a response, prevent an agent from continuing its work, or prove that a contact is independent of the agent's evaluation environment.

CLI and MCP share membership and rekey processing. Receive pending messages before preparing guidance to refresh the locally known audience. See [Request guidance](guidance.md) for setup and the [client safety audit](audits/2026-09-07-client-safety.md) for findings.

## Remaining limits

qntm does not protect against compromised endpoints, malicious guidance, deceptive contact labels, leaked invites, approval mistakes, metadata analysis, or denial of service. Plaintext history is a local record, not a tamper-proof compliance archive. Relay retention and deletion are not proof that every recipient received or erased a message.


### Audit hardening (October 2026)

Group membership controls received by the TypeScript session and AIM browser require
an authenticated creator/admin roster or the accepted gateway. Rekey recipients must
match that roster. The local roster checkpoint is persisted with the keys; ordinary
outbound messages are blocked during a pending membership rekey or after removal.
Old local group records without an authenticated roster must replay genesis or use
a supported authenticated recovery path before applying non-gateway group controls.
The Python CLI, MCP, guidance and gateway commands share the outbound state guard.

Announcement ownership is stored in the conversation sequencer. Registration requires
an unused ID derived from the master public key. Unbound legacy claims are
quarantined without mutation or deletion authority. Closing a channel preserves its ownership tombstone and
monotonic sequence while removing replay data. KV ciphertext cleanup is batched;
provider eventual consistency and recovery history remain separate retention limits.
Announcement posting authorization is enforced by the relay; this does not give
subscribers an end-to-end posting-key attestation against a malicious relay.

Gateway execution intent is durable before contacting an upstream service. An unknown
outcome stays blocked across restart; a failed relay publication cannot authorize a
second upstream call. Results are bounded to 8 KiB and redirects are rejected. A
durable ordered outbox retries known results and membership controls; a long outage
can outlast a signed message's expiry. Do not blindly resubmit an uncertain
non-idempotent action under a new request ID. Gateway replay records and membership
transitions commit with the relay cursor; storage failures leave the cursor
unacknowledged. Active gateways exclude concurrent standalone group controls.

`verify_entity` checks entity status only. `verify_sender_entity` now requires a DID
resolver and a trusted local `verify_binding_fn(did, public_key, entity)` proving the
entity authorizes that DID/key. It fails closed if either check is absent. Identity
HTTP reads reject redirects and oversized/mismatched documents. General `did:web`
resolution still needs caller-controlled network egress when used on untrusted input;
it is not a public-network-only resolver.
