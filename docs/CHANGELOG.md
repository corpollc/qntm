# Changelog

## Unreleased

- Python CLI/MCP can explicitly release a stale, unproven removal retry with `group retry --release-unproven`. This preserves the uncertain ciphertext locally and sends nothing; it neither changes membership nor claims the removal was undone. Verified or still-retryable removals use ordinary retry, and incomplete history must be recovered first. Browser, terminal and OpenClaw controls are still being completed.
- Browser, Python CLI/MCP, terminal and OpenClaw can finish an accepted removal when its saved completing rotation expires, including for the sole remaining member. Retry preserves the original ciphertext, uses current membership for any replacement rotation and never removes a later readmission again. OpenClaw reviews the replacement before posting it. Standalone rotation retries also recover from expiry or recognize another member's completed rotation. Unproven expired removals remain preserved for reconciliation.

- OpenClaw groups can recover a saved operation after restart through a local `openclaw agent --channel qntm --to GROUP_ID` turn. The host must identify it as owner initiated; the agent still reviews and commits through the existing scoped tool. Inbound messages remain deferred until recovery completes.

- Completed removal and rotation retries now survive replay-cache eviction in Python, the browser and OpenClaw. Private authenticated receipts let a retry finish without reposting obsolete controls or restoring old keys, including after a later valid rotation. Competing branches and replacement welcomes invalidate prior proof; older journals without retained evidence stay preserved for reconciliation.

- Relay acceptance tests now distinguish Node's reported close event from the server's actual handshake. They check callback retry and independently verify that the server returns the correct close frame before ending the connection.

- Browser, Python CLI/MCP, terminal and OpenClaw retry actions can replace a stale generic refresh for the same current member. They authenticate the original recipient and recovery challenge, preserve prior ciphertext within private evidence bounds, and deliver current keys without turning a generic refresh into readmission. Older single-recipient journals remain recoverable when their signed intent can be verified. Real CLI/MCP, browser and installed OpenClaw journeys cover expiry, later rotation and replies.

- Python group control sends now reload the saved operation and current authority under the receive lock immediately before publication. Removal, missing history, changed journals and superseded source epochs stop stale creation/removal/rekey POSTs; exact already-accepted ciphertext is recognized without reposting. Resident-receive race tests cover these checks.

- Browser, Python CLI/MCP, terminal and OpenClaw retry actions can now finish an accepted add whose original key rotation expired or no longer matches the current roster. They save a replacement rotation, verify canonical completion through relay replay, then renew current-key delivery. OpenClaw reviews the rotation and resulting welcome in two successive prepare/commit cycles. Restart keeps uncertain ciphertext and never repeats the add. Later expiry or supersession can be reconciled again for the same admission, with bounded private delivery evidence. Removal and missing history block release.

- Browser, Python CLI/MCP, terminal and OpenClaw refresh actions now renew the recipient's proven current admission. A contact can recover an expired readmission welcome after later rotations without another add or access to excluded epochs. Founding members and checkpoints without admission proof retain generic refresh behavior; saved removal still requires proof of a later admission. Private journals and encrypted browser backups preserve the recipient, admission proof and exact retry ciphertext.

- Retry across the maintained clients now reconciles a completed pending addition against its exact current admission before retrying old controls. It keeps valid welcome ciphertext unchanged, or journals a current-key renewal after expiry, later rotation or a competing completing rekey. Removal and a different readmission block the old intent. Unknown renewal acknowledgements retain exact retry bytes; recorded welcome acknowledgements finish cleanup after restart.

- Added matching TypeScript and Python APIs to renew delivery for the same accepted group admission after later rotations. Bounded private provenance survives replay-cache eviction and follows competing-rekey rollback. The new welcome carries current keys and signed provenance, with no historical roots or new join-request step.

- Legacy `group create` now saves its exact signed genesis before posting and reports delivery failures. CLI `group retry` and MCP `group_retry` resume that ciphertext with the original identity and relay; lost acknowledgements can be reconciled from exact replay. An unfinished creation blocks conversion to contact-group mode. Restart tests cover rejected sends, lost acknowledgements and process termination before the acknowledgement is saved.

- Fixed relay WebSocket shutdown: the server now completes the close handshake, avoiding timeout delays after one-shot receives and during reconnects. TypeScript callback failures use a valid client close code. Real relay tests cover native-client failure/replay and Python-to-TypeScript messaging.

- Added ordinary-group contact workflows to the browser, Python CLI/MCP, terminal and OpenClaw. Add a verified address, rotate fresh keys and deliver a recipient-encrypted welcome over the existing group stream, then share a public link containing no keys. Addition is admission; contacts can open links in a different order. Removal and readmission exclude keys for the interval of absence. The terminal uses the matching Python receiver; OpenClaw actions require configured pins and a complete native prepare/commit review. Gateway-governed welcomes, legacy migration and automatic reconciliation of conflicting or expired pending operations remain release gaps.

- Added matching Python/TypeScript welcome, refresh and authenticated receive-state APIs. Current members can refresh delivery without readmitting a contact or rotating keys; a refresh cannot undo saved removal. Signed welcomes bind the sender's checked relay position, so an omitted rotation before welcome delivery pauses the recipient. Missing history persists a recovery challenge across restart and blocks sends and agent delivery until a fresh signed welcome answers it. No pre-admission keys or stranger-entry tokens are included.

- Client creation and membership changes persist exact outgoing ciphertext before sending. Creation verifies its signed genesis through replay; uncertain delivery uses the saved operation for retry. Browser state and encrypted backups include verified contact pins, per-group relay configuration and recovery metadata; Web Locks coordinate browser tabs. Terminal and OpenClaw checkpoints preserve receive state across restart, and terminal shutdown stops its resident receiver. Real browser, PTY and installed OpenClaw journeys cover reverse opening order, Python/TypeScript replies, refresh, retention recovery, removal and readmission.

- TypeScript relay replay now exposes each envelope's sequence and the captured head. Subscriptions provide a serialized, awaitable `onReady` callback so clients can validate complete backlog before acting. Failed ready callbacks replay the uncommitted backlog; asynchronous frame decoding preserves relay order.

- New members pause when older-source ciphertext could conceal a late competing rekey, including after initial link opening. Welcomes sign exact addition/rekey hashes, so copying message IDs cannot bypass this check. A challenged refresh can replace a losing root at the same epoch while preserving saved removal. Clients inspect complete batches before agent delivery; the documented tradeoff is that racing old-epoch traffic or injected ciphertext can also force recovery.

- Python resident receive and OpenClaw wait for complete subscription replay before waking hooks or agents, including after restart and reconnect. Browser history and agent delivery bind plaintext to exact verified ciphertext, so a reused message ID cannot revive an old branch's payload. Valid pending deliveries survive replay-cache eviction; a replacement welcome does not authorize previously queued plaintext. The terminal requires the matching safe Python receiver and uses its filtered receive results. Private archive retention, replay bounds and dispatch metadata are documented.

- Added independent one-minute HTTPS and certificate checks for both browser hostnames, with tested alert delays, missing-target detection and bounded metadata documentation. These checks do not execute the browser app or replace encrypted messaging tests; outbound paging remains unconfigured.
- Added `web.qntm.corpo.llc` as a verified HTTPS address for the existing Pages browser app. `chat.corpo.llc` remains available. The deployment guide explains DNS, certificate checks and deliberate encrypted-backup migration between browser origins; profiles do not transfer automatically.
- Aligned messaging, gateway and relay signature checks with the charter's strict Ed25519 profile. TypeScript and Python now reject weak signing keys and permissive-only signatures consistently; shared vectors also run against the Go registry. Invite, gateway and group roster validation rejects invalid member keys before admission or partial updates. Real encrypted-message and Worker tests cover synthetic forgeries. Normally generated keys and wire formats are unchanged; malformed historical signatures now fail validation.
- macOS acceptance teardown verifies that an owned process group is empty or contains only exited processes when Darwin reports `EPERM`. It continues to report permission errors for live listeners; regressions cover both cases.
- Fixed two remaining invite-secret URL exposures: Python's `convo invite` and the terminal's `/invite` now emit fragment links. Python adds `invite_to_url`; both library URL builders discard old queries. Tests exercise real CLI/terminal output and cross-client parsing. The hosted browser fix alone did not protect links produced by older clients.
- Acceptance tests now require successful HTTP health responses, bound stalled startup requests and report Worker output on failure. Fixtures isolate Wrangler discovery and use OS-assigned Worker/browser listeners, including an HTTP server for Vite's middleware mode. Restart checks retain the established endpoint; shutdown cancels stale timers and stops owned process groups so wrappers cannot leave servers behind. Failed setup no longer masks its diagnostics with a teardown error. Real-server regressions cover concurrent Vite instances and descendant cleanup.
- Collapsed browser sidebar panels now exclude their controls from keyboard focus and agent/screen-reader navigation while preserving unsent form drafts. Panel headers identify the content they expand, and browser tests cover Tab, Enter and Space navigation.
- Refreshed maintained JavaScript test and development dependencies, including Vitest 4.1.11 and Cloudflare's current CLI/type definitions, and updated the Go setup action. CI now audits complete client, browser, terminal, Worker, integration and maintained adapter dependency graphs at moderate severity, including development tools; the legacy NanoClaw adapter keeps its existing runtime-only check.
- Added a best-effort macOS schedule for encrypted off-host charter backups, with a dedicated runtime, single-operation lock, private success/failure status and authenticated retention. Missing recovery keys, tampered files and failed downloads cannot silently replace a key or prune valid history. The Mac must be awake, logged in and online; same-VM Grafana backup metrics remain separate.
- Added a manual AIM deployment path for browser fixes between package releases. It requires the complete CI suite on the selected commit, records that commit on Cloudflare Pages and serializes production deployments. Tagged releases retain their existing release gate. The operations guide covers project/credentials, verification and rollback, and makes explicit that manual branch deployments target production; automatic PR previews are not configured.
- Made browser installs reproducible across macOS and Linux: refreshed the lockfile within existing version ranges, included Rollup platform packages, and switched UI tests and deployment to `npm ci`. Removed the legacy GitHub Pages base-path override and added a full UI dependency audit covering development tools.
- Fixed browser invite links exposing their bootstrap secret in HTTP URL queries. Both copy actions now use the same fragment format as Python and TypeScript; opening a link requests confirmation and removes the token from the current address. Legacy query links remain readable, with their unavoidable initial-request exposure documented.
- Bounded the relay's in-memory IP rate-limit table to 10,000 entries per isolate and purge expired counters on subsequent requests. A full table rejects new IPs without evicting active quotas. Documented the capacity tradeoff and the fact that idle isolates do not guarantee immediate metadata deletion.
- Bounded TypeScript gateway setup and health requests with a default 30-second deadline, optional cancellation, a 64 KiB response limit and redirect rejection. Native OpenClaw setup propagates cancellation through this shared client. No setup POST is automatically retried; signed chat acceptance remains the authority.
- Added an optional OpenClaw gateway tool for requests, votes, credentials, governance and participant-initiated admission. Each action requires a complete prepare/commit review bound to the native host session and conversation, with fresh permission, membership and policy checks. Uncertain sends return a message ID without automatic retry; admission saves only sealed bootstrap for explicit retry and requires signed chat acceptance. Real OpenClaw 2026.9.3 agent-loop journeys with Python/browser/TypeScript peers verify actual gateway execution, withdrawal/quorum, governance, wrong-requester and stale-review rejection, removal and restart after rekeying. Unit tests also cover expiry, cancelled actions, bootstrap failures and immutable reviews.
- Browser gateway responses now offer expand/collapse controls instead of permanently discarding text after the 2,000-character preview. Long JSON responses remain scrollable, keyboard accessible and rendered as literal text. Cross-client tests expand the matching result before inspecting fields beyond the preview.
- CI now typechecks the complete integration project with explicit Cloudflare ambient types and component dependencies. Cross-client acceptance runs on Node 24 to include the actual OpenClaw host; existing browser, CLI, terminal and relay journeys remain required.
- Added the opt-in Python `qntm.charter` library for the experimental v0.2 registry: self-certification, parent and threshold governance, canonical signing, offline authority replay, pinned HTTP access and complete proof/snapshot verification. Shared fixtures and real Python/TypeScript/Go journeys cover invalid authority, threshold changes, historical evidence and abrupt server restart. Independent witnesses remain unfinished; applications still own checkpoint persistence and freshness policy.

- Added a hostname-scoped Cloudflare configuration rule so Browser Integrity Check accepts normal Python relay/gateway clients. Restored messaging after the separate Durable Object runtime-quota outage by activating Workers Paid; independent authenticated delivery/replay and telemetry verified recovery. Documented the gateway's idle connection costs and the need for account usage monitoring. These are account configuration changes, not package fixes.

- Terminal acceptance tests now wait for rendered composer state before pressing Return, and the PTY bridge drains complete JSON frames without buffered-input stalls. A regression pauses the real terminal process to catch command/Return coalescing under load.
- CI now disables the runner's unused Chrome APT source before installing Ubuntu test dependencies, so a broken Chrome package index cannot block terminal/browser tests. Package signature and checksum verification remains enabled; browser tests still use Playwright's pinned Chromium.
- OpenClaw now saves authenticated conversation state, current keys, pending delivery and relay progress together. A private local queue retries failed host admission and recovers after a process crash; rekeys and removal survive restart, and delayed replies use current keys. Identity/configuration parsing rejects malformed keys and epochs without echoing private input. Documented exact local plaintext fields, bounds, retention and the handoff's at-least-once limits.
- OpenClaw now targets the public 2026.9.3 SDK, with a self-contained plugin archive, generated configuration metadata, and a real-host CI smoke test for encrypted direct/group replies and restart replay. Removed the local SDK shims that could hide host API drift. This adapter revision requires a compatible Node 24 or 26 host.
- Normalize wrapped fragment-style invite links before URL parsing so pasted spaces do not corrupt the invite token.
- Remove historical operator identities, conversation state and the Beads credential key from tracked files; ignore local runtime state and refresh Beads hook scaffolding. Existing Git history still contains the old material; rotation assessment is tracked separately.

- Terminal gateway actions now use complete paged reviews before sending requests, approvals, vote withdrawals, sealed credentials, and governance changes. Signed chat admission establishes gateway authority; confirmation rejects expired or changed state. Terminal input no longer switches conversations while typing numeric IDs, and gateway summaries fit the viewport.
- Terminal gateway send receipts identify the submitted message. Commands entered during a pending action show visible feedback, and cross-client tests wait for that action's acknowledgement before continuing.
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
