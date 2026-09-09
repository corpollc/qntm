# AIM Chat: URL-synced conversations, whitespace stripping, global paste listener

**Date:** 2026-03-22
**Scope:** Three UX improvements to AIM chat UI

## 1. URL-synced conversation selection

**Current behavior:** `selectedConversationId` is pure React state. Refreshing the page loses the selected conversation. URL only changes for `#/settings` and `#/help`.

**New behavior:** Selecting a conversation updates the URL to `#/c/<convId>`. Refreshing or navigating to that URL reopens the conversation.

**Implementation:**

- The current catch-all route (`path="*"`) renders the chat UI as inline JSX (Sidebar + ChatPane + GatePanel). The new `/c/:convId` route renders the same inline JSX — no new component needed. Use a shared fragment or render both routes with the same element.
- `selectConversation(convId)` calls `navigate(`/c/${convId}`)` in addition to setting state. Add `navigate` to the `useCallback` deps array (react-router v6 returns a stable reference, so no re-render risk).
- On mount/route change, read `convId` from route params via `useParams()`. If it matches an existing conversation, select it. If not, fall through to no-selection state.
- Settings (`#/settings`) and help (`#/help`) routes unchanged
- The default route (`#/`) shows the chat UI with no conversation selected (same as today)

**URL sync in other flows that set selectedConversationId:**
- `onSelectProfile` (lines 608-626) and the `activeProfileId` useEffect (lines 277-289) reset `selectedConversationId` to `''` — must also `navigate('/')` to avoid stale URL
- `refreshActiveProfileData` (lines 489-499) auto-selects the first visible conversation — must also navigate to `/c/<selectedId>` to keep URL in sync
- `onAcceptInvite`, `onJoinFromModal`, `onCreateInvite` all set `selectedConversationId` after creating/joining — must also navigate

**Edge cases:**
- Deep-linking to a conversation that doesn't exist (deleted, wrong profile) → select the first visible (non-hidden) conversation instead, or no selection if there are none
- Switching profiles → navigate to `#/` since the convId may not exist in the new profile

## 2. Strip all whitespace from pasted invite tokens

**Current behavior:** `extractToken()` in InvitePanel.tsx calls `.trim()` on input but does not strip internal whitespace. Tokens copied from emails/docs often have line breaks or spaces injected.

**New behavior:** Strip ALL whitespace (including internal) from the final token value.

**Implementation:**

Flow in `extractToken()`:
```
1. trimmed = input.trim()
2. try URL parse on trimmed → extract ?invite= param or hash fragment → rawToken
3. fall through: rawToken = trimmed
4. return rawToken.replace(/\s+/g, '')  // strip internal whitespace from final token
```

URL parsing happens on the trimmed (but not whitespace-stripped) input to preserve URL structure. Whitespace stripping happens only on the final extracted token string.

In the URL `?invite=` detection useEffect in App.tsx (lines 257-269), apply `.replace(/\s+/g, '')` to the extracted token before setting state (defense-in-depth).

## 3. Global paste listener for invite tokens

**Current behavior:** No global paste handling. Users must manually navigate to the Invites panel and paste into the input field.

**New behavior:** Pasting an invite token anywhere on the page (when not focused on a text input) either opens the conversation (if already joined) or shows the JoinModal (if not joined).

**Implementation:**

- Add a `paste` event listener on `document` in App.tsx (in a useEffect)
- On paste:
  1. Check if `document.activeElement` is an `<input>`, `<textarea>`, or `[contenteditable]` → if so, return (let native paste happen)
  2. Read clipboard text from `event.clipboardData.getData('text/plain')`
  3. Strip whitespace, run through `extractToken()`
  4. Try `inviteFromURL(token)` in a try/catch — if it throws, not a valid invite token → ignore silently
  5. Extract `conv_id` from the parsed invite, hex-encode it
  6. Look up the conv_id in current profile's conversations:
     - **Found** → select it (navigate to `#/c/<convId>`)
     - **Not found** → set `inviteToken` state and show `JoinModal`

**Shared utilities:**
- `extractToken()` is currently a module-private function in InvitePanel.tsx. Extract it to a shared utility file (`src/utils.ts` or new `src/invite-utils.ts`) so both InvitePanel and App.tsx can use it.
- Add a new helper `parseInviteConvId(token: string): string | null` in `src/qntm.ts` that wraps `inviteFromURL(token)` in a try/catch, extracts `conv_id`, hex-encodes it, and returns the hex string (or null if parsing fails). This keeps the `@corpollc/qntm` import contained in qntm.ts.

**Edge cases:**
- Pasting non-token text with no focus → silently ignored (inviteFromURL throws)
- Pasting a valid token while typing in the composer → native paste, no interception
- Pasting a token for a conversation in a different profile → shows JoinModal (conv_id won't match)

## Files changed

- `src/App.tsx` — route addition, selectConversation URL sync, global paste listener, invite URL whitespace fix, navigate on profile switch / auto-select
- `src/components/InvitePanel.tsx` — use shared `extractToken()` from utils
- `src/utils.ts` — extract `extractToken()` here for reuse
- `src/qntm.ts` — new `parseInviteConvId(token): string | null` helper

## Testing

**Component tests (vitest + happy-dom):**
- `extractToken()` strips internal whitespace from bare tokens
- `extractToken()` strips whitespace from tokens extracted from URLs
- `parseInviteConvId()` returns hex conv_id for valid tokens, null for garbage

**Playwright e2e:**
- Navigate to `#/c/<convId>` → correct conversation loaded after refresh
- Navigate to `#/c/nonexistent` → graceful fallback, no crash
- Select conversation → URL updates to `#/c/<convId>`
- Global paste of invite token (no focus) → JoinModal or conversation selection
