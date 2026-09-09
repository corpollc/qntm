# Changelog

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
