# Changelog

## Unreleased

## v0.6.3

- Add authenticated encrypted attachments in Python and TypeScript.
- Add recipient-sealed current-epoch recovery for already authorized group members, without new admission rights or historical keys.
- Preserve v0.6.2 strict signatures, legacy fragment links, gateway authority and cross-surface membership behavior.
- Keep archived governance withdrawals effective and bound rekey convergence to source authorization.

## v0.6.2 (2026-09-10)

[Full release notes](releases/v0.6.2.md)

- Added reviewed terminal gateway admission, requests, votes, credentials and governance actions, with authenticated state and atomic restart checkpoints.
- Added the optional native OpenClaw gateway tool, scoped prepare/commit reviews and a durable delivery queue. The adapter now targets the public OpenClaw 2026.9.3 SDK, with real-host and cross-client coverage.
- Added the opt-in Python charter library with canonical signing, authority replay, pinned transport and proof verification, tested against the TypeScript client and Go registrar. Independent witnesses remain unimplemented.
- Encrypted browser backup downloads and added strict restore validation, replacement previews and atomic confirmation. Legacy plaintext imports remain supported.
- Kept browser, Python and terminal invite secrets in URL fragments; added the Python URL builder and handled wrapped pasted links. Legacy query links retain their historical exposure.
- Aligned Python/TypeScript expiry, timestamp bounds and default TTL. Saved-history decryption requires an explicit option and retains signature, context and ciphertext verification.
- Aligned clients, gateway and relay with the charter's strict Ed25519 profile, rejecting weak keys and malformed signatures consistently. Valid generated keys and wire formats remain compatible.
- Bounded gateway setup duration and response size, added cancellation, rejected redirects and preserved explicit handling of uncertain POSTs. Gateway replay ignores consumed and non-current epochs before authorization.
- Fixed browser startup navigation and settings scrolling, kept collapsed controls out of keyboard and accessibility navigation, and added expandable gateway response text. Terminal input and send feedback remain visible during pending actions.
- Fixed optional relay challenge authentication rejecting valid public keys. Bounded in-memory rate-limit state and replaced request-derived exception output with fixed diagnostics.
- Added private relay totals, rolling active-conversation counts and independent encrypted delivery/replay and certificate checks. Documented exact metadata visibility, retention and synthetic-traffic accounting; outbound paging remains unconfigured.
- Added encrypted off-host charter backup scheduling with verified retention and explicit Mac availability requirements. Documented the second browser hostname and separate per-origin profiles.
- Made browser builds reproducible, refreshed and audited maintained development dependencies, and strengthened real-server startup, port isolation, terminal timing and owned-process cleanup checks. Manual browser deployment now requires the complete CI gate.
- Removed tracked historical operator state and credential material; historical Git exposure still requires separate rotation assessment. Recorded the earlier Cloudflare client-access and runtime-quota recovery as operational configuration changes.


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
