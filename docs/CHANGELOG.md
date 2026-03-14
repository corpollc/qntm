# Changelog

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
