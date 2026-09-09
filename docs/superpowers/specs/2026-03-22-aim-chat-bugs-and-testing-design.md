# AIM Chat: Conversation Management Bugs + Two-Tier Testing

**Date:** 2026-03-22
**Scope:** Three bug fixes in aim-chat UI + comprehensive test infrastructure

## Problem Statement

Three conversation management bugs in AIM UI:

1. **No rename facility** — ConversationList shows names but has no edit UI. `store.updateConversation()` exists but is unreachable from the UI.
2. **Invite name doesn't stick** — InvitePanel `handleJoin()` sets `inviteName` via React state then calls `onAcceptInvite()` in a `setTimeout`. The App reads `inviteName` from state, which hasn't updated yet. Race condition.
3. **No real delete** — Only hide/unhide. No way to permanently remove a conversation and its data.

Additionally: no browser-level tests exist. Only vitest unit tests.

## Bug Fixes

### Fix 1: Inline Conversation Rename

**Component:** `ConversationList.tsx`

Add inline rename to each conversation row:
- A pencil/edit button appears on hover (alongside existing hide button)
- Clicking enters edit mode: name becomes an `<input>`, pre-filled with current name
- Enter or blur → save via new `onRenameConversation(convId, newName)` callback
- Escape → cancel, restore original name
- Empty name → reject (keep original)

**New API method:** `api.renameConversation(profileId, conversationId, newName)` — wraps `store.updateConversation()`. All store interactions in App.tsx go through the `api` layer; this maintains that pattern.

**Wiring in App.tsx:**
- New handler `handleRenameConversation(convId: string, newName: string)`
- Calls `api.renameConversation(profileId, convId, newName)`
- Updates local `conversations` state

**Styling:** New CSS classes in `components.css`:
- `.conversation-edit` — edit button, same hover-reveal pattern as `.conversation-hide`
- `.conversation-rename-input` — inline input replacing the name span in edit mode, fits within `.conversation-select` flex layout without reflow
- `.conversation-delete` — delete button, hover-reveal, uses danger color token

**Files changed:** `ConversationList.tsx`, `App.tsx`, `api.ts`, `components.css`

### Fix 2: Invite Name Race Condition

**Root cause:** `InvitePanel.handleJoin()` does:
```typescript
setInviteName(joinName)      // React state update — async
setTimeout(() => onAcceptInvite(), 0)  // Reads inviteName — stale
```

**Note:** The `JoinModal` component already does this correctly — it passes the name directly via `onJoin(name)`, and `onJoinFromModal` in App.tsx receives it as a parameter. The race condition only affects the `InvitePanel` sidebar flow.

**Fix:** Change `onAcceptInvite` signature to accept the name directly:
```typescript
onAcceptInvite: (name: string) => void
```

InvitePanel calls `onAcceptInvite(joinName)` directly. App.tsx `onAcceptInvite(name: string)` uses the argument instead of reading `inviteName` state.

Same fix for `handleCreate` → `onCreateInvite(name: string)`.

**Files changed:** `InvitePanel.tsx`, `App.tsx`

### Fix 3: Delete Conversation with Confirmation

**New store function:** `deleteConversation(profileId, conversationId)`
- Removes conversation from `conversations[profileId]` array
- Removes `history[profileId][conversationId]`
- Removes `cursors[profileId][conversationId]`

**New API method:** `api.deleteConversation(profileId, conversationId)`

**UI in ConversationList:**
- Delete button (trash icon or "Delete") appears alongside hide button
- Clicking opens the existing `ConfirmDialog` with:
  - Title: "Delete Conversation"
  - Message: "You won't be able to rejoin without a new invitation."
  - Confirm label: "Delete" (danger style)
- On confirm: calls `onDeleteConversation(convId)` callback
- Conversation disappears from list

**Wiring in App.tsx:**
- New handler `handleDeleteConversation(convId: string)`
- Calls `api.deleteConversation(profileId, convId)`
- Removes from `hiddenConversations` if present
- Clears `selectedConversationId` if it was the deleted one
- Closes relay subscription via `subscriptionsRef.current.get(convId)?.close()` and removes from the Map
- Refreshes conversation list

**Files changed:** `store.ts`, `api.ts`, `ConversationList.tsx`, `App.tsx`

## Testing Architecture

### Tier 1: Component Tests (vitest + happy-dom + @testing-library/react)

**New devDependencies:**
- `@testing-library/react`
- `@testing-library/user-event`
- `happy-dom` (vitest environment)

**Vitest config addition** (in `vite.config.ts` or new `vitest.config.ts`):
```typescript
test: {
  environment: 'happy-dom',
}
```

Note: existing unit tests (qntm.test.ts, api.test.ts, etc.) stub their own globals and don't depend on a DOM environment, so switching the default to happy-dom won't break them.

**Test files:**

#### `src/components/ConversationList.test.tsx`
- Renders conversation list with names
- Click edit → input appears with current name
- Type new name + Enter → `onRenameConversation` called with new name
- Escape during edit → reverts, no callback
- Empty name → rejected
- Click delete → ConfirmDialog appears
- Confirm delete → `onDeleteConversation` called
- Cancel delete → dialog dismissed, no callback

#### `src/components/InvitePanel.test.tsx`
- Join with custom name → `onAcceptInvite` called with that name
- Join with empty name → `onAcceptInvite` called with empty string (App provides fallback)
- Create with custom name → `onCreateInvite` called with that name

#### `src/components/JoinModal.test.tsx`
- Submit with name → `onJoin` called with name
- Submit without name → `onJoin` called with empty string

#### `src/components/ConfirmDialog.test.tsx`
- Renders title, message, confirm label
- Confirm click → `onConfirm` called
- Cancel click → `onCancel` called
- Escape key → `onCancel` called
- Backdrop click → `onCancel` called

#### `src/store.test.ts`
- `deleteConversation` removes conversation record
- `deleteConversation` removes history
- `deleteConversation` removes cursors
- `deleteConversation` for non-existent conversation is a no-op
- `updateConversation` with name change persists

### Tier 2: Playwright Integration Tests (Bob/Alice Pattern)

**New devDependencies:**
- `@playwright/test`

**Architecture:**

```
tests/
  e2e/
    fixtures/
      relay-stub.ts       # Local HTTP+WS relay server
      bob.ts              # Programmatic qntm client (Bob)
      alice.ts            # Playwright page helpers (Alice)
    rename.spec.ts
    invite-name.spec.ts
    delete.spec.ts
```

#### Local Relay Stub (`relay-stub.ts`)

A minimal Node.js HTTP + WebSocket server implementing the dropbox protocol:
- `POST /v1/send` — stores `{ conv_id, envelope_b64 }`, returns `{ seq }`
- `POST /v1/receipt` — records receipt, returns `{ recorded: true }`
- `GET /v1/subscribe` (WebSocket upgrade) — replays messages from `from_seq`, then streams new ones in real-time

Based on the existing `FakeDropboxRelay` pattern from unit tests, but running as a real server on a random port. Implements the same wire format the `DropboxClient` expects.

Exposed as a Playwright fixture that starts/stops the server per test.

#### Bob Fixture (`bob.ts`)

A Playwright test fixture wrapping `@corpollc/qntm` library calls:
- `bob.createProfile(name)` → creates profile + identity in a MemoryStorage
- `bob.createInvite(name)` → returns invite token
- `bob.sendMessage(conversationId, text)` → sends encrypted message via relay stub
- `bob.receiveMessages(conversationId)` → polls relay stub

Bob operates purely in Node.js — no browser. Uses the same `@corpollc/qntm` library the UI uses, pointed at the relay stub URL.

#### Alice Fixture (`alice.ts`)

Playwright page object helpers:
- `alice.createProfile(name)` → fills profile form in browser
- `alice.joinInvite(token, name)` → pastes invite, enters name, clicks Join
- `alice.renameConversation(convId, newName)` → clicks edit, types name, presses Enter
- `alice.deleteConversation(convId)` → clicks delete, confirms dialog
- `alice.getConversationNames()` → reads visible conversation names
- `alice.refresh()` → reloads page (verifies localStorage persistence)

Alice interacts with the actual Vite-served UI in a real browser, with the dropbox URL pointed at the relay stub.

#### Test Scenarios

**`rename.spec.ts`:**
1. Bob creates invite → Alice joins with name "Project Alpha"
2. Alice clicks edit on "Project Alpha", types "Project Beta", presses Enter
3. Assert conversation name is "Project Beta"
4. Alice refreshes page → assert name is still "Project Beta"

**`invite-name.spec.ts`:**
1. Bob creates invite → Alice joins via JoinModal with name "My Custom Chat"
2. Assert conversation appears as "My Custom Chat" in sidebar
3. Alice refreshes → assert name persists
4. Bob creates another invite → Alice joins via InvitePanel with name "Second Chat"
5. Assert "Second Chat" appears in sidebar

**`delete.spec.ts`:**
1. Bob creates invite → Alice joins
2. Alice clicks delete on conversation → ConfirmDialog appears
3. Alice clicks Cancel → conversation still exists
4. Alice clicks delete again → confirms → conversation gone
5. Alice refreshes → conversation still gone
6. Alice checks that messages and history are also purged

**Playwright config (`playwright.config.ts`):**
- Starts Vite dev server as `webServer`
- Single Chromium project (keep it simple)
- Sets `VITE_DROPBOX_URL` env var pointing to relay stub

**Dropbox URL injection via localStorage seeding:**
- The relay stub runs on a random port
- Before each test, seed Alice's browser localStorage with a valid `aim-store` JSON blob containing `dropboxUrl: 'http://localhost:<port>'`
- `getDropboxUrl()` in `store.ts` reads from the store on each call (not cached at startup), so seeding before page load is sufficient
- The full `aim-store` blob must be valid JSON (not just the `dropboxUrl` field) since `loadStore()` parses the entire object — missing fields get defaults via normalization

**Bob fixture Node.js compatibility:**
- Bob uses `@corpollc/qntm` in Node.js. The library accepts a URL at construction (`new DropboxClient(url)`)
- Bob needs its own isolated `MemoryStorage` (same pattern as unit tests) — not sharing state with Alice's browser localStorage
- Global stubs for `fetch` and `WebSocket` are needed in the Bob fixture, using Node.js built-in `fetch` and a WebSocket polyfill (or `ws` package)

## File Summary

**Modified files:**
- `src/components/ConversationList.tsx` — inline rename + delete button
- `src/components/InvitePanel.tsx` — pass name directly to callbacks
- `src/App.tsx` — new handlers for rename/delete, updated callback signatures
- `src/store.ts` — new `deleteConversation()` function
- `src/api.ts` — new `renameConversation()` and `deleteConversation()` methods
- `src/styles/components.css` — new classes for edit/delete buttons and inline rename input

**New files:**
- `src/components/ConversationList.test.tsx`
- `src/components/InvitePanel.test.tsx`
- `src/components/JoinModal.test.tsx`
- `src/components/ConfirmDialog.test.tsx`
- `src/store.test.ts`
- `tests/e2e/fixtures/relay-stub.ts`
- `tests/e2e/fixtures/bob.ts`
- `tests/e2e/fixtures/alice.ts`
- `tests/e2e/rename.spec.ts`
- `tests/e2e/invite-name.spec.ts`
- `tests/e2e/delete.spec.ts`
- `playwright.config.ts`

**New devDependencies:**
- `@testing-library/react`
- `@testing-library/user-event`
- `happy-dom`
- `@playwright/test`
