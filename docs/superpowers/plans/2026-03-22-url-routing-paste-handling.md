# URL Routing, Whitespace Stripping, Global Paste — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync selected conversation to URL hash (`#/c/<convId>`), strip whitespace from invite tokens, and add a global paste listener that auto-detects invite tokens.

**Architecture:** Three independent features sharing the same files. `extractToken()` moves from InvitePanel.tsx to utils.ts for reuse. A new `parseInviteConvId()` helper in qntm.ts wraps `inviteFromURL` + `bytesToHex`. App.tsx gets route-aware conversation selection, a paste event listener, and URL sync in all places that set `selectedConversationId`.

**Tech Stack:** React 18, React Router v7 (HashRouter), TypeScript, vitest, @corpollc/qntm

**Spec:** `docs/superpowers/specs/2026-03-22-url-routing-paste-handling-design.md`

---

## Task 1: Move `extractToken()` to utils.ts and add whitespace stripping

**Files:**
- Modify: `ui/aim-chat/src/utils.ts`
- Modify: `ui/aim-chat/src/components/InvitePanel.tsx`

- [ ] **Step 1: Write tests for extractToken with whitespace stripping**

Create `ui/aim-chat/src/utils.test.ts` (or append if it exists — it does not currently exist):

```typescript
import { describe, it, expect } from 'vitest'
import { extractToken } from './utils'

describe('extractToken', () => {
  it('returns bare token as-is', () => {
    expect(extractToken('abc123')).toBe('abc123')
  })

  it('trims leading/trailing whitespace', () => {
    expect(extractToken('  abc123  ')).toBe('abc123')
  })

  it('strips internal whitespace (line breaks, spaces)', () => {
    expect(extractToken('abc 123\n456\t789')).toBe('abc123456789')
  })

  it('extracts token from ?invite= URL param', () => {
    expect(extractToken('https://chat.corpo.llc/?invite=TOKEN123')).toBe('TOKEN123')
  })

  it('extracts token from URL and strips whitespace', () => {
    expect(extractToken('https://chat.corpo.llc/?invite=TOK EN\n123')).toBe('TOKEN123')
  })

  it('extracts token from hash fragment', () => {
    expect(extractToken('https://chat.corpo.llc/#TOKEN123')).toBe('TOKEN123')
  })

  it('returns empty string for empty input', () => {
    expect(extractToken('')).toBe('')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/utils.test.ts
```

Expected: FAIL — `extractToken` is not exported from `./utils`

- [ ] **Step 3: Add extractToken to utils.ts**

Add at the end of `ui/aim-chat/src/utils.ts`:

```typescript
/** Extract a raw token from a pasted invite link or bare token, stripping all whitespace */
export function extractToken(input: string): string {
  const trimmed = input.trim()
  try {
    const url = new URL(trimmed)
    const invite = url.searchParams.get('invite')
    if (invite) return invite.replace(/\s+/g, '')
    if (url.hash) return url.hash.replace(/^#/, '').replace(/\s+/g, '')
  } catch {
    // Not a URL — treat as bare token
  }
  return trimmed.replace(/\s+/g, '')
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/utils.test.ts
```

Expected: all PASS

- [ ] **Step 5: Update InvitePanel.tsx to import from utils**

In `ui/aim-chat/src/components/InvitePanel.tsx`:

1. Delete the local `extractToken` function (lines 17-30)
2. Add import at top: `import { extractToken } from '../utils'`

- [ ] **Step 6: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all pass

- [ ] **Step 7: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/utils.ts src/utils.test.ts src/components/InvitePanel.tsx && git commit -m "refactor: move extractToken to utils with whitespace stripping"
```

---

## Task 2: Add `parseInviteConvId()` helper to qntm.ts

**Files:**
- Modify: `ui/aim-chat/src/qntm.ts`
- Modify: `ui/aim-chat/src/utils.test.ts`

- [ ] **Step 1: Write test for parseInviteConvId**

Append to `ui/aim-chat/src/utils.test.ts`:

```typescript
import { parseInviteConvId } from './qntm'

describe('parseInviteConvId', () => {
  it('returns null for garbage input', () => {
    expect(parseInviteConvId('not-a-token')).toBeNull()
  })

  it('returns null for empty string', () => {
    expect(parseInviteConvId('')).toBeNull()
  })
})
```

Note: We can't easily test the positive case without generating a real invite token (requires crypto). The positive path is covered by e2e tests. Unit tests verify the error path.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/utils.test.ts
```

Expected: FAIL — `parseInviteConvId` not exported from `./qntm`

- [ ] **Step 3: Implement parseInviteConvId**

Add to `ui/aim-chat/src/qntm.ts`, after the `bytesToHex` function (around line 193):

```typescript
/**
 * Try to parse an invite token and return the conversation ID as a hex string.
 * Returns null if the token is invalid.
 * Pure function — no network calls, no state changes.
 */
export function parseInviteConvId(token: string): string | null {
  if (!token) return null
  try {
    const invite = inviteFromURL(token)
    return bytesToHex(invite.conv_id).toLowerCase()
  } catch {
    return null
  }
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/utils.test.ts
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/qntm.ts src/utils.test.ts && git commit -m "feat: add parseInviteConvId helper for invite token parsing"
```

---

## Task 3: URL-synced conversation selection

**Files:**
- Modify: `ui/aim-chat/src/App.tsx`

This is the largest task. It touches `selectConversation`, the route definitions, `onSelectProfile`, `refreshActiveProfileData`, `onCreateInvite`, `onJoinFromModal`, `onAcceptInvite`, and `confirmDeleteConversation`.

- [ ] **Step 1: Update selectConversation to navigate**

In `ui/aim-chat/src/App.tsx`, change `selectConversation` (lines 155-163):

```typescript
const navigate = useNavigate()
```
(This already exists in the file — verify. If not, add it.)

```typescript
const selectConversation = useCallback((convId: string) => {
  setSelectedConversationId(convId)
  setUnreadCounts((prev) => {
    if (!prev[convId]) return prev
    const next = { ...prev }
    delete next[convId]
    return next
  })
  if (convId) {
    navigate(`/c/${convId}`)
  }
}, [navigate])
```

- [ ] **Step 2: Add route param reading**

Add a `useEffect` that reads the route param on mount/navigation. Add this after the existing `useKeyboardShortcuts` call (around line 256):

```typescript
// Sync selected conversation from URL on mount/navigation
const location = useLocation()
```
(This already exists — verify. Look for `const location = useLocation()` or `const { pathname } = useLocation()`.)

Add a new useEffect. **Important:** This effect must NOT call `selectConversation` (which navigates) — the URL is already correct. Instead, directly set state to avoid an infinite navigate→effect→navigate loop:

```typescript
useEffect(() => {
  const match = location.pathname.match(/^\/c\/(.+)$/)
  if (match) {
    const convId = match[1]
    const exists = conversations.some(c => c.id === convId)
    if (exists) {
      if (convId !== selectedConversationIdRef.current) {
        setSelectedConversationId(convId)
        setUnreadCounts((prev) => {
          if (!prev[convId]) return prev
          const next = { ...prev }
          delete next[convId]
          return next
        })
      }
    } else if (conversations.length > 0) {
      // Conv doesn't exist — fall back to first visible
      const firstVisible = conversations.find(c => !hiddenConversations.has(c.id))
      const target = firstVisible?.id || conversations[0]?.id || ''
      if (target) {
        selectConversation(target) // This navigates to the correct URL
      } else {
        navigate('/', { replace: true })
      }
    }
  }
}, [location.pathname, conversations, hiddenConversations, navigate, selectConversation])
```

- [ ] **Step 3: Add /c/:convId route**

In the Routes block (around line 1133), change the catch-all route to also match `/c/:convId`. The simplest approach: the existing `path="*"` already catches `/c/anything`. The useEffect in Step 2 handles the param reading. No route change needed — the `*` route already covers it.

Verify this by checking that navigating to `#/c/test` renders the chat UI (not settings or help).

- [ ] **Step 4: Navigate on profile switch**

In `onSelectProfile` (line 608), after `setActiveProfileId(profileId)` (line 615), add:

```typescript
navigate('/')
```

- [ ] **Step 5: Navigate on auto-select in refreshActiveProfileData**

The `setSelectedConversationId` call at lines 489-499 uses a state setter callback to read the current value. We can't call `navigate` inside a state setter callback. Use `selectedConversationIdRef.current` (already exists at line 92) to read the current value without stale closure issues, then call `selectConversation` which navigates:

Replace lines 489-499:
```typescript
const previousId = selectedConversationIdRef.current
const stillExists = conversationsResponse.conversations.some(c => c.id === previousId)
if (stillExists) {
  // Keep current selection, but ensure URL is in sync
  if (previousId) navigate(`/c/${previousId}`, { replace: true })
} else {
  const firstVisible = conversationsResponse.conversations.find((c) => !hiddenConversations.has(c.id))
  const target = firstVisible?.id || conversationsResponse.conversations[0]?.id || ''
  if (target) {
    selectConversation(target)
  } else {
    navigate('/', { replace: true })
  }
}
```

- [ ] **Step 6: Navigate on createInvite / acceptInvite / joinFromModal**

In `onCreateInvite` (line 708-710), replace `setSelectedConversationId(response.conversationId)` with:
```typescript
selectConversation(response.conversationId)
```

In `onJoinFromModal` (line 736-738), replace `setSelectedConversationId(response.conversationId)` with:
```typescript
selectConversation(response.conversationId)
```

In `onAcceptInvite` (lines 770-772 — find the `if (response.conversationId) { setSelectedConversationId(response.conversationId) }` block), replace `setSelectedConversationId(response.conversationId)` with:
```typescript
selectConversation(response.conversationId)
```

- [ ] **Step 7: Navigate on delete**

In `confirmDeleteConversation` (line 689-691), after clearing the selected conversation, navigate home:

Replace:
```typescript
if (selectedConversationId === convId) {
  setSelectedConversationId('')
}
```
With:
```typescript
if (selectedConversationId === convId) {
  setSelectedConversationId('')
  navigate('/')
}
```

- [ ] **Step 8: Strip whitespace from invite URL param**

In the invite URL detection useEffect (lines 257-269), add whitespace stripping:

Change:
```typescript
setInviteToken(token)
```
To:
```typescript
setInviteToken(token.replace(/\s+/g, ''))
```

- [ ] **Step 9: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all pass

- [ ] **Step 10: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/App.tsx && git commit -m "feat: sync selected conversation to URL hash (#/c/<convId>)"
```

---

## Task 4: Global paste listener for invite tokens

**Files:**
- Modify: `ui/aim-chat/src/App.tsx`

- [ ] **Step 1: Add paste listener useEffect**

In `ui/aim-chat/src/App.tsx`, add a new useEffect after the invite URL detection useEffect (around line 270). Import `extractToken` from utils and `parseInviteConvId` from qntm at the top of the file:

Add imports:
```typescript
import { shortId, APP_VERSION, extractToken } from './utils'
import { parseInviteConvId } from './qntm'
```
(Modify the existing `shortId, APP_VERSION` import line to add `extractToken`, and add a new import for `parseInviteConvId`.)

Add the useEffect:

```typescript
// Global paste listener: detect invite tokens pasted outside text inputs
useEffect(() => {
  function handlePaste(e: ClipboardEvent) {
    const active = document.activeElement
    if (
      active instanceof HTMLInputElement ||
      active instanceof HTMLTextAreaElement ||
      (active instanceof HTMLElement && active.isContentEditable)
    ) {
      return // Let native paste happen
    }

    const text = e.clipboardData?.getData('text/plain')
    if (!text) return

    const token = extractToken(text)
    if (!token) return

    const convId = parseInviteConvId(token)
    if (!convId) return // Not a valid invite token

    // Check if we already have this conversation
    const existing = conversations.find(c => c.id === convId)
    if (existing) {
      selectConversation(convId)
    } else {
      setInviteToken(token)
      setShowJoinModal(true)
    }
  }

  document.addEventListener('paste', handlePaste)
  return () => document.removeEventListener('paste', handlePaste)
}, [conversations, selectConversation])
```

- [ ] **Step 2: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all pass

- [ ] **Step 3: Verify build**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm run build
```

Expected: clean build

- [ ] **Step 4: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/App.tsx && git commit -m "feat: add global paste listener for invite token detection"
```

---

## Task 5: Playwright e2e tests for URL routing

**Files:**
- Create: `ui/aim-chat/tests/e2e/url-routing.spec.ts`

- [ ] **Step 1: Write e2e tests**

Create `ui/aim-chat/tests/e2e/url-routing.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import { RelayStub } from './fixtures/relay-stub'
import { Bob } from './fixtures/bob'
import { Alice } from './fixtures/alice'

let relay: RelayStub

test.beforeEach(async () => {
  relay = new RelayStub()
  await relay.start()
})

test.afterEach(async () => {
  await relay.stop()
})

test('selecting a conversation updates the URL', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('URL Test')
    await alice.joinInviteViaSidebar(token, 'URL Test')

    // Click the conversation
    await page.locator('.conversation-name', { hasText: 'URL Test' }).click()

    // URL should contain /c/
    await expect(page).toHaveURL(/#\/c\//)
  } finally {
    bob.uninstall()
  }
})

test('refreshing on #/c/<convId> reloads the correct conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Persist Test')
    await alice.joinInviteViaSidebar(token, 'Persist Test')

    await page.locator('.conversation-name', { hasText: 'Persist Test' }).click()

    // Get the current URL
    const url = page.url()
    expect(url).toMatch(/#\/c\//)

    // Refresh
    await alice.refresh()

    // The conversation should still be selected (name visible in chat pane or sidebar highlight)
    const names = await alice.getConversationNames()
    expect(names).toContain('Persist Test')
    // URL should still have the conv ID
    await expect(page).toHaveURL(/#\/c\//)
  } finally {
    bob.uninstall()
  }
})

test('navigating to #/c/nonexistent falls back to first conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Fallback Test')
    await alice.joinInviteViaSidebar(token, 'Fallback Test')

    // Navigate to a non-existent conversation
    await page.goto('/#/c/nonexistent')
    await page.waitForTimeout(1000)

    // Should fall back — conversation list should still show our conversation
    const names = await alice.getConversationNames()
    expect(names).toContain('Fallback Test')
  } finally {
    bob.uninstall()
  }
})
```

- [ ] **Step 2: Run e2e tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test tests/e2e/url-routing.spec.ts --reporter=list
```

Expected: all PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/url-routing.spec.ts && git commit -m "test: add Playwright e2e tests for URL-synced conversation routing"
```

---

## Task 6: Final verification and version bump

- [ ] **Step 1: Run all vitest tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

- [ ] **Step 2: Run all Playwright tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test --reporter=list
```

- [ ] **Step 3: Verify build**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm run build
```

- [ ] **Step 4: Bump version to 0.5.1**

In `ui/aim-chat/package.json`, change `"version": "0.4.13"` to `"version": "0.5.1"`.

(Note: check current version first — it may have been bumped already.)

- [ ] **Step 5: Commit and push**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add package.json && git commit -m "chore: bump version to 0.5.1"
git push
git tag v0.5.1 && git push origin v0.5.1
```
