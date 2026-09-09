# Changelog

## Unreleased

- OpenClaw now saves authenticated conversation state, current keys, pending delivery and relay progress together. A private local queue retries failed host admission and recovers after a process crash; rekeys and removal survive restart, and delayed replies use current keys. Identity/configuration parsing rejects malformed keys and epochs without echoing private input. Documented exact local plaintext fields, bounds, retention and the handoff's at-least-once limits.
- OpenClaw now targets the public 2026.9.3 SDK, with a self-contained plugin archive, generated configuration metadata, and a real-host CI smoke test for encrypted direct/group replies and restart replay. Removed the local SDK shims that could hide host API drift. This adapter revision requires a compatible Node 24 or 26 host; structured gateway actions remain unfinished.
- Normalize wrapped fragment-style invite links before URL parsing so pasted spaces do not corrupt the invite token.
- Remove historical operator identities, conversation state and the Beads credential key from tracked files; ignore local runtime state and refresh Beads hook scaffolding. Existing Git history still contains the old material; rotation assessment is tracked separately.

- Terminal gateway actions now use complete paged reviews before sending requests, approvals, vote withdrawals, sealed credentials, and governance changes. Signed chat admission establishes gateway authority; confirmation rejects expired or changed state. Terminal input no longer switches conversations while typing numeric IDs, and gateway summaries fit the viewport.
- TypeScript adds a portable authenticated conversation reducer for gateway admission, current membership, rekeys, verified workflow events, and exact replay deduplication. The terminal persists keys, state, history and cursor in one private atomic file update so restarts cannot skip a key rotation.
- Gateway subscriptions now skip prior and future epochs before decryption, advance their durable replay cursor, and ignore already-consumed sequences. Rekey/restart replay no longer produces invalid-tag noise or lets old-epoch traffic enter current authorization state. Current-epoch envelopes still require full authentication.
- Browser backup downloads now use password encryption. Restores validate identities and all stored fields, show replacement counts and contact/gateway destinations, and require confirmation before an atomic write. Legacy plaintext imports remain supported; stale reviews, malformed files, incorrect passwords and tampering fail without replacing data.
- Fixed profile startup redirecting Settings, Help and Guidance links to chat, including the reload after a restore. Settings now scrolls within the application so longer backup reviews remain reachable.
- Aligned Python and TypeScript message expiry: normal decryption rejects expired messages, both enforce the same timestamp and future-skew bounds, and saved-history verification requires an explicit option. Shared encrypted fixtures cover exact expiry boundaries and tampering in both modes. TypeScript message creation now has Python's default TTL.
- Added a private relay dashboard with Cloudflare-backed message-post totals, rolling active-conversation counts, certificate health and external encrypted messaging probes. Counts begin at deployment, distinguish synthetic traffic, and include both direct chats and groups.
- Replaced the shared KV activity update with durable aggregate telemetry. Metadata is queued atomically with an envelope, delivered in bounded batches, deduplicated on retry and expired after seven days. A dedicated read-only token protects detailed totals.
- Added an exe.dev monitor that tests live WebSocket delivery and reconnect/replay using two synthetic identities. Stale collection and failed probes are visible in Grafana; outbound notification recipients remain unconfigured.
- Fixed optional WebSocket challenge authentication rejecting valid Ed25519 public keys because its hexadecimal length check used 32 characters instead of 64. The external probe now exercises this path against the real relay.
- Documented the exact relay, telemetry, dashboard and provider metadata boundaries. Relay error handlers now emit fixed diagnostic strings and generic 500 responses instead of logging or echoing exception details that could contain request-derived metadata.

## v0.6.1 (2026-09-09)

[Full release notes](releases/v0.6.1.md)

- Added typed TypeScript gateway and governance builders, authenticated-message verification, encrypted-message construction, and history summaries. Builders derive signer rosters and approval requirements from verified current state; vote and terminal-event handling validates authorship and context.
- Adopted the shared helpers in accepted-gateway browser flows and the TypeScript integration client, with real Python/browser/gateway interoperability coverage.
- Bundled the default recipe catalog in Python wheels and source distributions. Fresh installations can use `gate-run` without a source checkout; explicit catalog overrides remain supported.
- Python `gate-run` now raises its recipe threshold to the accepted gateway's current floor and matching rules, and refuses unattainable approval counts before sending. Forged or unverified policy history cannot lower the requirement.
- Python governance approvals preserve absent versus null proposal fields, fixing signature rejection when approving TypeScript-authored proposals. Shared vectors cover both wire encodings.
- Added an isolated installed-wheel release check for CLI startup, bundled resources, and signed request construction, plus a parity check against the canonical recipe catalog.

## v0.6.0 (2026-09-09)

[Full release notes](releases/v0.6.0.md)

### Added

- Continuous `recv --watch` with JSONL, reconnects, repeatable webhooks and executable hooks, independent retries, and shared Python/TypeScript receive-event fixtures.
- Locally pinned guidance contacts and exact-message review for legal, ethical, and law-enforcement questions in the browser, CLI, and MCP.
- Experimental charter v0.2 support: TypeScript library, durable Go reference registrar (Go 1.27.1+), self-certification, parent/threshold governance, namespaced statements, and verifiable log/map evidence. The draft remains unratified; independent witnesses are not included.
- Public experimental registrar at `https://charter.qntm.corpo.llc`, with automatic TLS renewal, bounded storage/concurrency, private Prometheus/Grafana monitoring, daily consistent snapshots and encrypted off-host backup tooling.
- Full release gating across libraries, workers, adapters, Python versions, real browser/CLI journeys, terminal PTY input, and Go/TypeScript charter integration. Generated CLI help and source/lockfile versions are checked for drift.

### Fixed

- Gateway admission now completes a participant-signed invitation with the gateway's signed acceptance in chat. Sealed access material travels out of band, without an operator admission token.
- Gateway actions bind the conversation and gateway key, enforce the current roster's governance quorum, and recover sequence numbers across gateway and governance records.
- Threshold selection matches every specified service, endpoint and verb before choosing the most specific rule; an exemption for one endpoint cannot lower another endpoint's requirements. Python and TypeScript share regression fixtures, including legacy empty wildcards.
- Secret delivery requires an explicitly configured or accepted gateway key. The browser no longer guesses another participant as the recipient, and both clients reject a key that conflicts with the configured gateway.
- Relay receipts no longer delete messages. Bounded receipt metadata and ciphertext expire together, including idle cleanup. Replay spans expired sequence gaps and paginates through the captured head.
- Python private/atomic state writes, MCP identity/invite encoding, and shared receive/rekey handling; TypeScript subscription callbacks retain replay progress on failure.
- Claude notifications persist before cursor advancement and survive failed transport writes, restart, and a CLI receiver sharing the profile.
- Lost send responses recover by matching the exact ciphertext; unresolved delivery reports an unknown outcome and message ID.
- Reconciled main with the already published v0.5.1 browser fixes. Runtime dependency audit gates remain enabled; vulnerable older Vitest 3 versions were updated. Refreshed the Python runtime/MCP lock, raised security dependency floors, and added Python and Go vulnerability scans.
- Echo demo delivery no longer skips capped work; retries reuse saved encrypted responses. Removed public plaintext diagnostics and added executable README and real echo Worker tests.

### Compatibility

- Echo bot accepts authenticated native QSP text envelopes; legacy unsigned bridge envelopes are no longer echoed.
- New gateway setup requires updated clients and gateway; use `gate-promote -c CONVERSATION --gateway-url URL --threshold N`.
- MCP text fields use `unsafe_body`, with hex identifiers matching the CLI. Binary receive events use `unsafe_body_b64`.
- `required_acks` remains a signed compatibility field; receipt responses always report `deleted: false`.
- Charter APIs are opt-in TypeScript exports; Python charter support and native Codex/Grok insertion adapters remain unimplemented.

## v0.5.1 (2026-03-22)

- Corrected browser test discovery and Playwright worker serialization for the v0.5 browser release.
- Preserved conversation rename/delete, custom invite names, paste handling, and URL-based conversation navigation.

Earlier 0.3–0.5 release histories are available in [GitHub Releases](https://github.com/corpollc/qntm/releases). This changelog retains the original v0.2 notes below.

## v0.2.0 (2026-03-13)

### Web UI (qntm Messenger)
- Modernized visual design with new color system, typography, and flat surface design
- Dark mode support (follows system preference)
- Mobile-responsive layout with touch-friendly targets
- Collapsible sidebar with conversation search/filter
- Message grouping by sender with date separators and colored avatars
- First-run onboarding wizard with progressive steps
- Unread message badges on conversations
- Toast notification system replacing error banners
- Loading spinners and skeleton placeholders
- Keyboard shortcuts (Cmd+K search, Cmd+/ help, Alt+1-9 switch)
- In-app help panel with glossary and getting started guide
- API Gateway walkthrough wizard for first-time users
- Contextual tooltips on key UI elements
- Confirmation dialog for destructive actions (keypair regeneration)
- Client-side routing with browser back/forward support
- Redesigned conversation creation flow (New/Join split)
- API Gateway progressive disclosure
- Accessibility improvements (skip links, ARIA labels, keyboard navigation)
- Settings page reorganized with About section

### Terminal UI
- Transient scroll mode (no more modal confusion)
- Redesigned header with dynamic conversation name and key hints
- Conversation list with last message previews and relative timestamps
- Centralized color theme system
- Connection activity indicators (polling spinner, last message time)
- Enhanced Gate card rendering with structured layout
- Inline command help and slash command hints in composer
- Per-command /help with detailed descriptions
- /search and /grep for message history search
- Terminal bell notifications with /mute /unmute commands
- "Did you mean?" suggestions for typos

### Cross-UI
- Unified product name: "qntm Messenger"
- Standardized terminology: API Gateway, API Template, Required Approvals, API Keys
- Renamed confusing labels: New Conversation, Join Conversation, Message Relay
- Consistent "conversation" and "profile/keypair" terminology
- --relay-url flag (backward-compatible with --dropbox-url)

### Documentation
- Getting started guide (docs/getting-started.md)
- API Gateway feature documentation (docs/api-gateway.md)
- UI copy style guide (docs/ui-copy-guide.md)
