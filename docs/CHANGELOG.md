# Changelog

## Unreleased

- Relay receipts are bounded advisory telemetry and cannot delete messages. `required_acks` remains signed for compatibility; `deleted` is always false. Public stats no longer enumerate conversation IDs.
- Python CLI/MCP state uses private POSIX permissions and atomic JSON replacement. Existing permissions are repaired on access; unsafe links and shared root configuration paths are rejected.
- CLI and MCP now share membership/rekey processing and preserve non-text bodies. Received rekeys apply within the batch, and history/state are stored before advancing the cursor.
- Restored gateway bootstrap authentication, trusted governance quorum, conversation binding, and restart maintenance from the prior security stack. Deployment now requires `GATEWAY_PROMOTION_TOKEN`; AIM accepts a masked, non-persisted operator token.
- AIM uses React Router 7.18.3; the TUI lockfile uses ws 8.21.3. CI checks both runtime dependency trees for high/critical advisories.

- Added local guidance pins for legal, moral/ethical, and law-enforcement contacts in the browser and CLI.
- Added MCP guidance discovery, preparation, and explicit send tools. Requests use existing encrypted conversations and do not attach history automatically.
- Added exact recipient, known audience, and message review, with checks for changed local destination state.
- Fixed MCP conversation create/join key handling, participant storage, and invite serialization.
- Fixed MCP configuration paths containing `~`, constrained its SDK dependency to the supported 1.x API, and enabled MCP tests in CI.
- MCP receive/history now return message text as `unsafe_body` instead of `body`. MCP key IDs and public keys now use hex to match the CLI. Integrations must account for these output changes.
- Corrected quick-start commands, public demo privacy claims, relay metadata claims, and guidance trust boundaries.


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
