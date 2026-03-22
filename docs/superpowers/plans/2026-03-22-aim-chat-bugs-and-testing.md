# AIM Chat Conversation Management Bugs + Testing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three conversation management bugs (rename, invite name, delete) and build two-tier test infrastructure (vitest+happy-dom component tests, Playwright integration tests with Bob/Alice pattern).

**Architecture:** Bug fixes touch the prop chain App.tsx → Sidebar.tsx → ConversationList.tsx/InvitePanel.tsx, plus store.ts and api.ts. New `deleteConversation` in store, `renameConversation` and `deleteConversation` in api. InvitePanel race condition fixed by passing names as arguments instead of React state. Tests use vitest+happy-dom for component tests and Playwright with a local relay stub for e2e.

**Tech Stack:** React 18, TypeScript, vitest, happy-dom, @testing-library/react, Playwright, @corpollc/qntm

**Spec:** `docs/superpowers/specs/2026-03-22-aim-chat-bugs-and-testing-design.md`

---

## Task 1: Install test dependencies and configure vitest for happy-dom

**Files:**
- Modify: `ui/aim-chat/package.json`
- Modify: `ui/aim-chat/vite.config.ts`

- [ ] **Step 1: Install happy-dom and testing-library**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm install --save-dev @testing-library/react @testing-library/user-event happy-dom
```

- [ ] **Step 2: Add test environment to vite.config.ts**

In `ui/aim-chat/vite.config.ts`, add `test` block inside `defineConfig`:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: process.env.VITE_BASE_PATH || '/',
  server: {
    port: 5173,
  },
  define: {
    'globalThis.Buffer': 'globalThis.Buffer',
  },
  test: {
    environment: 'happy-dom',
  },
})
```

- [ ] **Step 3: Verify existing tests still pass**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all existing tests pass (qntm.test.ts, api.test.ts, group-apply.test.ts, relayStatus.test.ts, SystemEvents.test.tsx).

- [ ] **Step 4: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add package.json package-lock.json vite.config.ts && git commit -m "chore: add happy-dom and testing-library for component tests"
```

---

## Task 2: Add `store.deleteConversation()` with tests

**Files:**
- Modify: `ui/aim-chat/src/store.ts`
- Create: `ui/aim-chat/src/store.test.ts`

- [ ] **Step 1: Write failing tests for deleteConversation**

Create `ui/aim-chat/src/store.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as store from './store'

class MemoryStorage implements Storage {
  private data = new Map<string, string>()
  get length(): number { return this.data.size }
  clear(): void { this.data.clear() }
  getItem(key: string): string | null { return this.data.has(key) ? this.data.get(key)! : null }
  key(index: number): string | null { return Array.from(this.data.keys())[index] ?? null }
  removeItem(key: string): void { this.data.delete(key) }
  setItem(key: string, value: string): void { this.data.set(key, value) }
}

function makeConversation(id: string, name: string): store.StoredConversation {
  return {
    id,
    name,
    type: 'direct',
    keys: { root: 'aa', aeadKey: 'bb', nonceKey: 'cc' },
    participants: [],
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
  }
}

describe('store.deleteConversation', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('removes the conversation record', () => {
    const profileId = 'test-profile'
    store.addConversation(profileId, makeConversation('conv-1', 'Alpha'))
    store.addConversation(profileId, makeConversation('conv-2', 'Beta'))

    store.deleteConversation(profileId, 'conv-1')

    const remaining = store.listConversations(profileId)
    expect(remaining).toHaveLength(1)
    expect(remaining[0].id).toBe('conv-2')
  })

  it('removes message history for the conversation', () => {
    const profileId = 'test-profile'
    store.addConversation(profileId, makeConversation('conv-1', 'Alpha'))
    store.addHistoryMessage(profileId, 'conv-1', {
      id: 'msg-1', conversationId: 'conv-1', direction: 'outgoing',
      sender: 'me', senderKey: 'key1', bodyType: 'text',
      text: 'hello', createdAt: new Date().toISOString(),
    })

    store.deleteConversation(profileId, 'conv-1')

    expect(store.getHistory(profileId, 'conv-1')).toEqual([])
  })

  it('removes cursor for the conversation', () => {
    const profileId = 'test-profile'
    store.addConversation(profileId, makeConversation('conv-1', 'Alpha'))
    store.saveCursor(profileId, 'conv-1', 42)

    store.deleteConversation(profileId, 'conv-1')

    expect(store.loadCursor(profileId, 'conv-1')).toBe(0)
  })

  it('is a no-op for non-existent conversation', () => {
    const profileId = 'test-profile'
    store.addConversation(profileId, makeConversation('conv-1', 'Alpha'))

    store.deleteConversation(profileId, 'no-such-conv')

    expect(store.listConversations(profileId)).toHaveLength(1)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/store.test.ts
```

Expected: FAIL — `store.deleteConversation is not a function`

- [ ] **Step 3: Implement deleteConversation in store.ts**

Add at the end of `ui/aim-chat/src/store.ts`, before the final `export { DEFAULT_DROPBOX_URL }` line (after the `saveCursor` function around line 340):

```typescript
export function deleteConversation(profileId: string, conversationId: string): void {
  const store = loadStore()
  if (store.conversations[profileId]) {
    store.conversations[profileId] = store.conversations[profileId].filter(c => c.id !== conversationId)
  }
  if (store.history[profileId]) {
    delete store.history[profileId][conversationId]
  }
  if (store.cursors[profileId]) {
    delete store.cursors[profileId][conversationId]
  }
  saveStore(store)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/store.test.ts
```

Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/store.ts src/store.test.ts && git commit -m "feat: add store.deleteConversation with tests"
```

---

## Task 3: Add `api.renameConversation()` and `api.deleteConversation()`

**Files:**
- Modify: `ui/aim-chat/src/api.ts`
- Modify: `ui/aim-chat/src/api.test.ts`

- [ ] **Step 1: Write failing tests**

Add to `ui/aim-chat/src/api.test.ts` (after existing test blocks):

```typescript
describe('api.renameConversation', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('updates the conversation name', async () => {
    // Setup: create a profile with identity and conversation via createInvite
    const { profile, identity } = api.createProfile('Alice')
    const invite = api.createInvite(profile.id, 'Original Name')
    const convId = invite.conversationId

    const result = api.renameConversation(profile.id, convId, 'New Name')

    expect(result.conversations.find(c => c.id === convId)?.name).toBe('New Name')
  })
})

describe('api.deleteConversation', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('removes the conversation', () => {
    const { profile } = api.createProfile('Alice')
    const invite = api.createInvite(profile.id, 'To Delete')
    const convId = invite.conversationId

    const result = api.deleteConversation(profile.id, convId)

    expect(result.conversations.find(c => c.id === convId)).toBeUndefined()
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/api.test.ts
```

Expected: FAIL — `api.renameConversation is not a function`

- [ ] **Step 3: Implement in api.ts**

Add two methods to the `api` object in `ui/aim-chat/src/api.ts` (after `listConversations`):

```typescript
  renameConversation(profileId: string, conversationId: string, newName: string): { conversations: Conversation[] } {
    store.updateConversation(profileId, conversationId, (conv) => ({ ...conv, name: newName.trim() || conv.name }))
    return { conversations: store.listConversations(profileId).map(formatConversation) }
  },

  deleteConversation(profileId: string, conversationId: string): { conversations: Conversation[] } {
    store.deleteConversation(profileId, conversationId)
    return { conversations: store.listConversations(profileId).map(formatConversation) }
  },
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/api.test.ts
```

Expected: all tests PASS (existing + new)

- [ ] **Step 5: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/api.ts src/api.test.ts && git commit -m "feat: add api.renameConversation and api.deleteConversation"
```

---

## Task 4: Fix InvitePanel race condition — pass name as argument

**Files:**
- Modify: `ui/aim-chat/src/components/InvitePanel.tsx`
- Create: `ui/aim-chat/src/components/InvitePanel.test.tsx`
- Modify: `ui/aim-chat/src/components/Sidebar.tsx`
- Modify: `ui/aim-chat/src/App.tsx`

Note: we modify the component interface FIRST, then write the test. The test validates the new signature, so it needs the interface change to compile. This is the rare case where TDD ordering gives way to type-system constraints.

- [ ] **Step 1: Update InvitePanel to pass name directly**

In `ui/aim-chat/src/components/InvitePanel.tsx`:

**Change the props interface** (lines 32-43). Remove `inviteName`, `setInviteName`. Change callback signatures:

```typescript
export interface InvitePanelProps {
  inviteToken: string
  setInviteToken: (value: string) => void
  createdInviteToken: string
  identity: IdentityInfo
  isWorking: boolean
  onCreateInvite: (name: string) => void
  onAcceptInvite: (name: string) => void
  newConversationInputRef?: Ref<HTMLInputElement>
}
```

**Update destructured props** (line 45-56) — remove `inviteName` and `setInviteName` from the destructuring.

**Fix the `createName` state initializer** (line 57) — the old code was `useState(inviteName)` which referenced the now-removed prop. Change to:

```typescript
const [createName, setCreateName] = useState('')
```

**Fix handleCreate** (lines 75-79):

```typescript
function handleCreate() {
  onCreateInvite(createName)
}
```

**Fix handleJoin** (lines 81-84):

```typescript
function handleJoin() {
  onAcceptInvite(joinName)
}
```

- [ ] **Step 2: Write component tests for InvitePanel**

Create `ui/aim-chat/src/components/InvitePanel.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { InvitePanel } from './InvitePanel'
import type { InvitePanelProps } from './InvitePanel'

function makeProps(overrides?: Partial<InvitePanelProps>): InvitePanelProps {
  return {
    inviteToken: '',
    setInviteToken: vi.fn(),
    createdInviteToken: '',
    identity: { exists: true, publicKey: 'pk', keyId: 'kid' },
    isWorking: false,
    onCreateInvite: vi.fn(),
    onAcceptInvite: vi.fn(),
    ...overrides,
  }
}

describe('InvitePanel', () => {
  it('passes the typed name to onCreateInvite', async () => {
    const onCreateInvite = vi.fn()
    render(<InvitePanel {...makeProps({ onCreateInvite })} />)

    const nameInput = screen.getByPlaceholderText('Name your conversation')
    await userEvent.clear(nameInput)
    await userEvent.type(nameInput, 'My Group')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))

    expect(onCreateInvite).toHaveBeenCalledWith('My Group')
  })

  it('passes the typed label to onAcceptInvite', async () => {
    const onAcceptInvite = vi.fn()
    render(<InvitePanel {...makeProps({
      onAcceptInvite,
      inviteToken: 'some-token',
    })} />)

    const labelInput = screen.getByPlaceholderText('Label for this conversation (optional)')
    await userEvent.clear(labelInput)
    await userEvent.type(labelInput, 'Work Chat')
    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onAcceptInvite).toHaveBeenCalledWith('Work Chat')
  })

  it('passes empty string when no label is provided for join', async () => {
    const onAcceptInvite = vi.fn()
    render(<InvitePanel {...makeProps({
      onAcceptInvite,
      inviteToken: 'some-token',
    })} />)

    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onAcceptInvite).toHaveBeenCalledWith('')
  })
})
```

- [ ] **Step 3: Run tests to verify they pass**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/components/InvitePanel.test.tsx
```

Expected: all 3 tests PASS (the component already has the fix from Step 1).

- [ ] **Step 4: Update Sidebar.tsx prop types and forwarding**

In `ui/aim-chat/src/components/Sidebar.tsx`:

**Remove from SidebarProps** (lines 15-16): remove `inviteName` and `setInviteName`.

**Change callback types** (lines 37-38):
```typescript
onCreateInvite: (name: string) => void
onAcceptInvite: (name: string) => void
```

**Remove from destructured props** (line 59): remove `inviteName` and `setInviteName`.

**Update InvitePanel JSX** (lines 153-164) — remove the `inviteName` and `setInviteName` props:

```tsx
<InvitePanel
  inviteToken={inviteToken}
  setInviteToken={setInviteToken}
  createdInviteToken={createdInviteToken}
  identity={identity}
  isWorking={isWorking}
  onCreateInvite={onCreateInvite}
  onAcceptInvite={onAcceptInvite}
  newConversationInputRef={newConversationInputRef}
/>
```

- [ ] **Step 5: Update App.tsx handlers and Sidebar props**

In `ui/aim-chat/src/App.tsx`:

**Update `onCreateInvite`** (line 654) to accept name parameter:

```typescript
async function onCreateInvite(name: string) {
  if (!activeProfileId) {
    return
  }

  setIsWorking(true)
  try {
    const convName = name.trim() || `${activeProfile?.name || 'Conversation'} Room`
    const response = await api.createInvite(activeProfileId, convName)
    // ... rest unchanged ...
```

**Update `onAcceptInvite`** (line 713) to accept name parameter:

```typescript
async function onAcceptInvite(name: string) {
  if (!activeProfileId) {
    return
  }

  const token = inviteToken.trim()
  if (!token) {
    return
  }

  setIsWorking(true)
  try {
    const convName = name.trim() || `${activeProfile?.name || 'Conversation'} Link`
    const response = await api.acceptInvite(activeProfileId, token, convName)
    // ... rest unchanged ...
```

**Remove `inviteName` and `setInviteName` from Sidebar props** (lines 1100-1101): delete these two lines from the Sidebar JSX.

- [ ] **Step 6: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all tests pass including new InvitePanel.test.tsx.

- [ ] **Step 7: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/components/InvitePanel.tsx src/components/InvitePanel.test.tsx src/components/Sidebar.tsx src/App.tsx && git commit -m "fix: pass name directly to invite callbacks, eliminating React state race condition"
```

---

## Task 5: Add inline rename to ConversationList

**Files:**
- Modify: `ui/aim-chat/src/components/ConversationList.tsx`
- Create: `ui/aim-chat/src/components/ConversationList.test.tsx`
- Modify: `ui/aim-chat/src/styles/components.css`

- [ ] **Step 1: Write component tests for rename**

Create `ui/aim-chat/src/components/ConversationList.test.tsx`:

```tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConversationList } from './ConversationList'
import type { ConversationListProps } from './ConversationList'
import type { Conversation } from '../types'

function makeConversation(id: string, name: string): Conversation {
  return { id, name, type: 'direct', participants: [], createdAt: new Date().toISOString() }
}

function makeProps(overrides?: Partial<ConversationListProps>): ConversationListProps {
  return {
    visibleConversations: [
      makeConversation('conv-1', 'Alpha'),
      makeConversation('conv-2', 'Beta'),
    ],
    selectedConversationId: '',
    setSelectedConversationId: vi.fn(),
    hiddenConversations: new Set(),
    unreadCounts: {},
    hiddenCount: 0,
    showHidden: false,
    setShowHidden: vi.fn(),
    toggleHideConversation: vi.fn(),
    conversationFilter: '',
    setConversationFilter: vi.fn(),
    onRenameConversation: vi.fn(),
    onDeleteConversation: vi.fn(),
    ...overrides,
  }
}

describe('ConversationList rename', () => {
  it('renders conversation names', () => {
    render(<ConversationList {...makeProps()} />)
    expect(screen.getByText('Alpha')).toBeTruthy()
    expect(screen.getByText('Beta')).toBeTruthy()
  })

  it('enters edit mode on edit button click', async () => {
    render(<ConversationList {...makeProps()} />)
    const editButtons = screen.getAllByLabelText('Rename conversation')
    await userEvent.click(editButtons[0])
    expect(screen.getByDisplayValue('Alpha')).toBeTruthy()
  })

  it('saves new name on Enter', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)

    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, 'Renamed{Enter}')

    expect(onRenameConversation).toHaveBeenCalledWith('conv-1', 'Renamed')
  })

  it('cancels edit on Escape', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)

    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, 'Changed{Escape}')

    expect(onRenameConversation).not.toHaveBeenCalled()
    expect(screen.getByText('Alpha')).toBeTruthy()
  })

  it('rejects empty name', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)

    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, '{Enter}')

    expect(onRenameConversation).not.toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/components/ConversationList.test.tsx
```

Expected: FAIL — no `onRenameConversation` prop, no edit button.

- [ ] **Step 3: Implement inline rename in ConversationList.tsx**

Replace the full content of `ui/aim-chat/src/components/ConversationList.tsx`:

```tsx
import { useState, useRef, useEffect } from 'react'
import type { Ref } from 'react'
import type { Conversation } from '../types'
import { shortId } from '../utils'

export interface ConversationListProps {
  visibleConversations: Conversation[]
  selectedConversationId: string
  setSelectedConversationId: (id: string) => void
  hiddenConversations: Set<string>
  unreadCounts: Record<string, number>
  hiddenCount: number
  showHidden: boolean
  setShowHidden: (fn: (prev: boolean) => boolean) => void
  toggleHideConversation: (convId: string) => void
  conversationFilter: string
  setConversationFilter: (value: string) => void
  filterInputRef?: Ref<HTMLInputElement>
  onRenameConversation: (convId: string, newName: string) => void
  onDeleteConversation: (convId: string) => void
}

export function ConversationList({
  visibleConversations,
  selectedConversationId,
  setSelectedConversationId,
  hiddenConversations,
  unreadCounts,
  toggleHideConversation,
  conversationFilter,
  setConversationFilter,
  filterInputRef,
  onRenameConversation,
  onDeleteConversation,
}: ConversationListProps) {
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editValue, setEditValue] = useState('')
  const editInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (editingId) {
      editInputRef.current?.focus()
      editInputRef.current?.select()
    }
  }, [editingId])

  function startEditing(conv: Conversation) {
    setEditingId(conv.id)
    setEditValue(conv.name)
  }

  function commitEdit() {
    if (editingId && editValue.trim()) {
      onRenameConversation(editingId, editValue.trim())
    }
    setEditingId(null)
  }

  function cancelEdit() {
    setEditingId(null)
  }

  return (
    <>
      <input
        ref={filterInputRef}
        className="input conversation-filter"
        placeholder="Filter conversations..."
        aria-label="Filter conversations"
        value={conversationFilter}
        onChange={(e) => setConversationFilter(e.target.value)}
      />
      <ul className="conversation-list" role="listbox" aria-label="Conversations">
        {visibleConversations.length === 0 && <li className="empty" role="presentation">No conversations yet. Create one above or join with an invite token.</li>}
        {visibleConversations.map((conversation) => {
          const unread = unreadCounts[conversation.id] || 0
          const isSelected = conversation.id === selectedConversationId
          const isEditing = editingId === conversation.id
          return (
          <li key={conversation.id} role="option" aria-selected={isSelected}>
            <div className={`conversation ${isSelected ? 'selected' : ''}`}>
              {isEditing ? (
                <input
                  ref={editInputRef}
                  className="input conversation-rename-input"
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitEdit()
                    if (e.key === 'Escape') cancelEdit()
                  }}
                  onBlur={commitEdit}
                  aria-label="Rename conversation"
                />
              ) : (
                <button
                  className="conversation-select"
                  type="button"
                  onClick={() => setSelectedConversationId(conversation.id)}
                  aria-current={isSelected ? 'true' : undefined}
                >
                  <span className={`conversation-name${unread > 0 ? ' has-unread' : ''}`}>{conversation.name}</span>
                  <span className="conversation-id">{shortId(conversation.id)}</span>
                </button>
              )}
              {unread > 0 && <span className="unread-badge">{unread}</span>}
              {!isEditing && (
                <button
                  className="conversation-edit"
                  type="button"
                  onClick={(e) => { e.stopPropagation(); startEditing(conversation) }}
                  aria-label="Rename conversation"
                  title="Rename"
                >
                  &#x270E;
                </button>
              )}
              <button
                className="conversation-hide"
                type="button"
                onClick={(e) => { e.stopPropagation(); toggleHideConversation(conversation.id) }}
                aria-label={hiddenConversations.has(conversation.id) ? 'Show conversation' : 'Hide conversation'}
                title={hiddenConversations.has(conversation.id) ? 'Unhide' : 'Hide'}
              >
                {hiddenConversations.has(conversation.id) ? 'Show' : '\u00d7'}
              </button>
              <button
                className="conversation-delete"
                type="button"
                onClick={(e) => { e.stopPropagation(); onDeleteConversation(conversation.id) }}
                aria-label="Delete conversation"
                title="Delete"
              >
                &#x1F5D1;
              </button>
            </div>
          </li>
          )
        })}
      </ul>
    </>
  )
}
```

- [ ] **Step 4: Add CSS styles for new buttons**

In `ui/aim-chat/src/styles/components.css`, after the existing `.conversation-hide:hover` block (around line 240), add:

```css
.conversation-edit {
  padding: 0 6px;
  cursor: pointer;
  background: none;
  border: none;
  border-left: 1px solid var(--tint-separator);
  font-size: 13px;
  color: var(--text-secondary);
  opacity: 0;
  transition: opacity 0.15s;
}

.conversation:hover .conversation-edit {
  opacity: 1;
}

.conversation-edit:hover {
  background: rgba(59, 130, 246, 0.08);
  color: var(--brand-primary);
}

.conversation-delete {
  padding: 0 6px;
  cursor: pointer;
  background: none;
  border: none;
  border-left: 1px solid var(--tint-separator);
  font-size: 13px;
  color: var(--text-secondary);
  opacity: 0;
  transition: opacity 0.15s;
}

.conversation:hover .conversation-delete {
  opacity: 1;
}

.conversation-delete:hover {
  background: rgba(220, 38, 38, 0.08);
  color: var(--danger);
}

.conversation-rename-input {
  flex: 1;
  min-width: 0;
  margin: 4px;
  padding: 4px 8px;
  font: inherit;
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/components/ConversationList.test.tsx
```

Expected: all rename tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/components/ConversationList.tsx src/components/ConversationList.test.tsx src/styles/components.css && git commit -m "feat: add inline conversation rename with edit button"
```

---

## Task 6: Add delete with confirmation to ConversationList

**Files:**
- Modify: `ui/aim-chat/src/components/ConversationList.test.tsx`

- [ ] **Step 1: Add delete tests to ConversationList.test.tsx**

Append to `ui/aim-chat/src/components/ConversationList.test.tsx`:

```tsx
describe('ConversationList delete', () => {
  it('calls onDeleteConversation when delete button clicked', async () => {
    const onDeleteConversation = vi.fn()
    render(<ConversationList {...makeProps({ onDeleteConversation })} />)

    const deleteButtons = screen.getAllByLabelText('Delete conversation')
    await userEvent.click(deleteButtons[0])

    expect(onDeleteConversation).toHaveBeenCalledWith('conv-1')
  })

  it('does not call onDeleteConversation for a different conversation', async () => {
    const onDeleteConversation = vi.fn()
    render(<ConversationList {...makeProps({ onDeleteConversation })} />)

    const deleteButtons = screen.getAllByLabelText('Delete conversation')
    await userEvent.click(deleteButtons[1])

    expect(onDeleteConversation).toHaveBeenCalledWith('conv-2')
  })
})
```

- [ ] **Step 2: Run tests to verify they pass**

The delete button already emits `onDeleteConversation(conversation.id)` from Task 5. These tests should pass immediately.

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx vitest run src/components/ConversationList.test.tsx
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/components/ConversationList.test.tsx && git commit -m "test: add delete button tests for ConversationList"
```

---

## Task 7: Wire rename and delete into App.tsx and Sidebar.tsx

**Files:**
- Modify: `ui/aim-chat/src/components/Sidebar.tsx`
- Modify: `ui/aim-chat/src/App.tsx`

- [ ] **Step 1: Add rename and delete props to Sidebar**

In `ui/aim-chat/src/components/Sidebar.tsx`:

**Add to SidebarProps** (after line 28 `toggleHideConversation`):

```typescript
onRenameConversation: (convId: string, newName: string) => void
onDeleteConversation: (convId: string) => void
```

**Add to destructured props** and **pass to ConversationList JSX** (in the ConversationList element, add):

```tsx
onRenameConversation={onRenameConversation}
onDeleteConversation={onDeleteConversation}
```

- [ ] **Step 2: Add handlers to App.tsx**

In `ui/aim-chat/src/App.tsx`, add two new handler functions (near the other conversation handlers, around line 650):

```typescript
function handleRenameConversation(convId: string, newName: string) {
  if (!activeProfileId) return
  const result = api.renameConversation(activeProfileId, convId, newName)
  setConversations(result.conversations)
}

function handleDeleteConversation(convId: string) {
  if (!activeProfileId) return
  // Close relay subscription
  const sub = subscriptionsRef.current.get(convId)
  if (sub) {
    sub.close()
    subscriptionsRef.current.delete(convId)
  }
  // Remove from store
  const result = api.deleteConversation(activeProfileId, convId)
  setConversations(result.conversations)
  // Clean up related state
  setHiddenConversations(prev => {
    if (!prev.has(convId)) return prev
    const next = new Set(prev)
    next.delete(convId)
    window.localStorage.setItem('aim-hidden-conversations', JSON.stringify([...next]))
    return next
  })
  if (selectedConversationId === convId) {
    setSelectedConversationId('')
  }
}
```

**Pass as props to Sidebar** (in the Sidebar JSX around line 1113, after `toggleHideConversation`):

```tsx
onRenameConversation={handleRenameConversation}
onDeleteConversation={handleDeleteConversation}
```

- [ ] **Step 3: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/components/Sidebar.tsx src/App.tsx && git commit -m "feat: wire rename and delete handlers through Sidebar to ConversationList"
```

---

## Task 8: Add ConfirmDialog for delete in App.tsx

**Files:**
- Modify: `ui/aim-chat/src/App.tsx`

The current Task 7 implementation calls `onDeleteConversation` directly. We need to intercept this with a confirmation dialog using the existing `ConfirmDialog` component.

- [ ] **Step 1: Add delete confirmation state and dialog to App.tsx**

In `ui/aim-chat/src/App.tsx`:

**Add state** (near the other modal state declarations around line 84):

```typescript
const [deleteConfirmConvId, setDeleteConfirmConvId] = useState<string | null>(null)
```

**Replace the direct delete prop with a confirmation trigger.** Change `handleDeleteConversation` to a two-step flow:

```typescript
function requestDeleteConversation(convId: string) {
  setDeleteConfirmConvId(convId)
}

function confirmDeleteConversation() {
  const convId = deleteConfirmConvId
  if (!convId || !activeProfileId) {
    setDeleteConfirmConvId(null)
    return
  }
  // Close relay subscription
  const sub = subscriptionsRef.current.get(convId)
  if (sub) {
    sub.close()
    subscriptionsRef.current.delete(convId)
  }
  // Remove from store
  const result = api.deleteConversation(activeProfileId, convId)
  setConversations(result.conversations)
  // Clean up related state
  setHiddenConversations(prev => {
    if (!prev.has(convId)) return prev
    const next = new Set(prev)
    next.delete(convId)
    window.localStorage.setItem('aim-hidden-conversations', JSON.stringify([...next]))
    return next
  })
  if (selectedConversationId === convId) {
    setSelectedConversationId('')
  }
  setDeleteConfirmConvId(null)
}
```

**Update the Sidebar prop** to use `requestDeleteConversation` instead of `handleDeleteConversation`:

```tsx
onDeleteConversation={requestDeleteConversation}
```

**Add ConfirmDialog JSX** (in the return, near the existing JoinModal around line 1191):

```tsx
<ConfirmDialog
  open={deleteConfirmConvId !== null}
  title="Delete Conversation"
  message="You won't be able to rejoin without a new invitation."
  confirmLabel="Delete"
  danger
  onConfirm={confirmDeleteConversation}
  onCancel={() => setDeleteConfirmConvId(null)}
/>
```

**Add the ConfirmDialog import** at the top of App.tsx (it is NOT currently imported — verify with grep first):

```typescript
import { ConfirmDialog } from './components/ConfirmDialog'
```

- [ ] **Step 2: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/App.tsx && git commit -m "feat: add confirmation dialog before deleting conversations"
```

---

## Task 9: Add component tests for ConfirmDialog and JoinModal

**Files:**
- Create: `ui/aim-chat/src/components/ConfirmDialog.test.tsx`
- Create: `ui/aim-chat/src/components/JoinModal.test.tsx`

- [ ] **Step 1: Write ConfirmDialog tests**

Create `ui/aim-chat/src/components/ConfirmDialog.test.tsx`:

```tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfirmDialog } from './ConfirmDialog'

describe('ConfirmDialog', () => {
  it('renders nothing when not open', () => {
    const { container } = render(
      <ConfirmDialog open={false} title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={vi.fn()} />
    )
    expect(container.innerHTML).toBe('')
  })

  it('renders title, message, and confirm label', () => {
    render(
      <ConfirmDialog open title="Delete?" message="Are you sure?" confirmLabel="Yes, delete" onConfirm={vi.fn()} onCancel={vi.fn()} />
    )
    expect(screen.getByText('Delete?')).toBeTruthy()
    expect(screen.getByText('Are you sure?')).toBeTruthy()
    expect(screen.getByText('Yes, delete')).toBeTruthy()
  })

  it('calls onConfirm when confirm clicked', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={onConfirm} onCancel={vi.fn()} />
    )
    await userEvent.click(screen.getByText('OK'))
    expect(onConfirm).toHaveBeenCalledOnce()
  })

  it('calls onCancel when cancel clicked', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    await userEvent.click(screen.getByText('Cancel'))
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('calls onCancel on Escape key', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    await userEvent.keyboard('{Escape}')
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('calls onCancel on backdrop click', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    // The overlay div has role="dialog" — click the backdrop behind the card
    const overlay = screen.getByRole('dialog')
    await userEvent.click(overlay)
    expect(onCancel).toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Write JoinModal tests**

Create `ui/aim-chat/src/components/JoinModal.test.tsx`:

```tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { JoinModal } from './JoinModal'

describe('JoinModal', () => {
  it('calls onJoin with typed name on submit', async () => {
    const onJoin = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={onJoin} onCancel={vi.fn()} />)

    await userEvent.type(screen.getByPlaceholderText('e.g. Team Chat, Project Alpha'), 'My Chat')
    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onJoin).toHaveBeenCalledWith('My Chat')
  })

  it('calls onJoin with empty string when no name provided', async () => {
    const onJoin = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={onJoin} onCancel={vi.fn()} />)

    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onJoin).toHaveBeenCalledWith('')
  })

  it('calls onCancel on backdrop click', async () => {
    const onCancel = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={vi.fn()} onCancel={onCancel} />)

    // Click the backdrop
    const backdrop = document.querySelector('.join-modal-backdrop')!
    await userEvent.click(backdrop)

    expect(onCancel).toHaveBeenCalled()
  })
})
```

- [ ] **Step 3: Run all tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add src/components/ConfirmDialog.test.tsx src/components/JoinModal.test.tsx && git commit -m "test: add component tests for ConfirmDialog and JoinModal"
```

---

## Task 10: Install Playwright and create config

**Files:**
- Modify: `ui/aim-chat/package.json`
- Create: `ui/aim-chat/playwright.config.ts`

- [ ] **Step 1: Install Playwright**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm install --save-dev @playwright/test && npx playwright install chromium
```

- [ ] **Step 2: Create Playwright config**

Create `ui/aim-chat/playwright.config.ts`:

```typescript
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:5173',
    headless: true,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
  webServer: {
    command: 'npm run dev',
    port: 5173,
    reuseExistingServer: true,
  },
})
```

- [ ] **Step 3: Add e2e script to package.json**

Add to `scripts` in `ui/aim-chat/package.json`:

```json
"test:e2e": "playwright test"
```

- [ ] **Step 4: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add package.json package-lock.json playwright.config.ts && git commit -m "chore: install Playwright and add config for e2e tests"
```

---

## Task 11: Create local relay stub

**Files:**
- Create: `ui/aim-chat/tests/e2e/fixtures/relay-stub.ts`

- [ ] **Step 1: Create the relay stub**

Create `ui/aim-chat/tests/e2e/fixtures/relay-stub.ts`:

```typescript
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { WebSocketServer, WebSocket } from 'ws'

interface StoredMessage {
  seq: number
  envelope_b64: string
  conv_id: string
}

/**
 * Minimal dropbox relay stub for e2e tests.
 * Implements the same wire protocol as the real dropbox relay:
 * - POST /v1/send — store envelope, return { seq }
 * - POST /v1/receipt — record receipt, return { recorded: true }
 * - WebSocket /v1/subscribe?conv_id=HEX&from_seq=N — replay + stream
 */
export class RelayStub {
  private messages: StoredMessage[] = []
  private nextSeq = 1
  private server: ReturnType<typeof createServer> | null = null
  private wss: WebSocketServer | null = null
  private subscribers: Map<string, Set<WebSocket>> = new Map()
  port = 0

  get url(): string {
    return `http://localhost:${this.port}`
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleHttp(req, res))
      this.wss = new WebSocketServer({ server: this.server })
      this.wss.on('connection', (ws, req) => this.handleWs(ws, req))
      this.server.listen(0, () => {
        const addr = this.server!.address()
        if (addr && typeof addr === 'object') {
          this.port = addr.port
        }
        resolve()
      })
    })
  }

  async stop(): Promise<void> {
    for (const subs of this.subscribers.values()) {
      for (const ws of subs) ws.close()
    }
    this.wss?.close()
    return new Promise((resolve) => {
      if (this.server) this.server.close(() => resolve())
      else resolve()
    })
  }

  reset(): void {
    this.messages = []
    this.nextSeq = 1
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    // CORS headers for browser requests
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    if (req.method === 'POST' && req.url === '/v1/send') {
      this.handleSend(req, res)
      return
    }

    if (req.method === 'POST' && req.url === '/v1/receipt') {
      this.handleReceipt(req, res)
      return
    }

    res.writeHead(404)
    res.end(JSON.stringify({ error: 'not found' }))
  }

  private handleSend(req: IncomingMessage, res: ServerResponse): void {
    let body = ''
    req.on('data', (chunk: string) => { body += chunk })
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body)
        const seq = this.nextSeq++
        const msg: StoredMessage = {
          seq,
          envelope_b64: parsed.envelope_b64,
          conv_id: parsed.conv_id,
        }
        this.messages.push(msg)

        // Notify WebSocket subscribers for this conversation
        const subs = this.subscribers.get(parsed.conv_id)
        if (subs) {
          const frame = JSON.stringify({ type: 'message', seq: msg.seq, envelope_b64: msg.envelope_b64 })
          for (const ws of subs) {
            if (ws.readyState === WebSocket.OPEN) ws.send(frame)
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ seq }))
      } catch {
        res.writeHead(400)
        res.end(JSON.stringify({ error: 'bad request' }))
      }
    })
  }

  private handleReceipt(_req: IncomingMessage, res: ServerResponse): void {
    // Consume body
    let body = ''
    _req.on('data', (chunk: string) => { body += chunk })
    _req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ recorded: true, deleted: false, receipts: 1, required_acks: 1 }))
    })
  }

  private handleWs(ws: WebSocket, req: IncomingMessage): void {
    const url = new URL(req.url || '', `http://localhost:${this.port}`)
    const convId = url.searchParams.get('conv_id') || ''
    const fromSeq = parseInt(url.searchParams.get('from_seq') || '0', 10)

    // Register subscriber
    if (!this.subscribers.has(convId)) {
      this.subscribers.set(convId, new Set())
    }
    this.subscribers.get(convId)!.add(ws)

    ws.on('close', () => {
      this.subscribers.get(convId)?.delete(ws)
    })

    // Replay messages after fromSeq for this conversation
    const replay = this.messages.filter(m => m.conv_id === convId && m.seq > fromSeq)
    for (const msg of replay) {
      ws.send(JSON.stringify({ type: 'message', seq: msg.seq, envelope_b64: msg.envelope_b64 }))
    }

    // Send ready frame
    const headSeq = this.messages.filter(m => m.conv_id === convId).at(-1)?.seq ?? fromSeq
    ws.send(JSON.stringify({ type: 'ready', head_seq: headSeq }))
  }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx tsc --noEmit tests/e2e/fixtures/relay-stub.ts --esModuleInterop --module nodenext --moduleResolution nodenext --target es2020 2>&1 || echo "Will verify at runtime via Playwright"
```

Note: TypeScript compilation of test fixtures happens at Playwright runtime. The `ws` package is needed:

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm install --save-dev ws @types/ws
```

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/fixtures/relay-stub.ts package.json package-lock.json && git commit -m "feat: add local relay stub for e2e tests"
```

---

## Task 12: Create Bob fixture (programmatic qntm client)

**Files:**
- Create: `ui/aim-chat/tests/e2e/fixtures/bob.ts`

- [ ] **Step 1: Create Bob fixture**

Create `ui/aim-chat/tests/e2e/fixtures/bob.ts`:

```typescript
/**
 * Bob — a programmatic qntm client for e2e tests.
 * Operates purely in Node.js, uses @corpollc/qntm library directly.
 * Shares the same relay stub as Alice's browser.
 *
 * Node.js compatibility: stubs localStorage (not native in Node) and
 * ensures WebSocket is available (via the `ws` package, which is also
 * used by the relay stub). Node 18+ provides native fetch and crypto.
 */
import { WebSocket } from 'ws'
import * as store from '../../../src/store'
import * as qntm from '../../../src/qntm'

class MemoryStorage implements Storage {
  private data = new Map<string, string>()
  get length(): number { return this.data.size }
  clear(): void { this.data.clear() }
  getItem(key: string): string | null { return this.data.has(key) ? this.data.get(key)! : null }
  key(index: number): string | null { return Array.from(this.data.keys())[index] ?? null }
  removeItem(key: string): void { this.data.delete(key) }
  setItem(key: string, value: string): void { this.data.set(key, value) }
}

export class Bob {
  private profileId = ''
  private profileName = ''
  private storage: MemoryStorage
  private relayUrl: string
  private originalLocalStorage: Storage | undefined
  private originalWebSocket: typeof globalThis.WebSocket | undefined

  constructor(relayUrl: string) {
    this.relayUrl = relayUrl
    this.storage = new MemoryStorage()
  }

  /**
   * Install global stubs so qntm/store functions use Bob's isolated storage and relay.
   * Stubs: localStorage (MemoryStorage), WebSocket (ws package).
   * Node 18+ provides native fetch and crypto.getRandomValues — no stubs needed.
   */
  install(): void {
    this.originalLocalStorage = globalThis.localStorage
    this.originalWebSocket = globalThis.WebSocket
    Object.defineProperty(globalThis, 'localStorage', { value: this.storage, configurable: true })
    // The @corpollc/qntm DropboxClient uses globalThis.WebSocket for subscriptions
    Object.defineProperty(globalThis, 'WebSocket', { value: WebSocket, configurable: true })
    // Set dropbox URL in Bob's store
    store.setDropboxUrl(this.relayUrl)
  }

  /** Restore original globals */
  uninstall(): void {
    if (this.originalLocalStorage !== undefined) {
      Object.defineProperty(globalThis, 'localStorage', { value: this.originalLocalStorage, configurable: true })
    }
    if (this.originalWebSocket !== undefined) {
      Object.defineProperty(globalThis, 'WebSocket', { value: this.originalWebSocket, configurable: true })
    }
  }

  createProfile(name: string): void {
    const profile = store.createProfile(name)
    this.profileId = profile.id
    this.profileName = profile.name
    store.selectProfile(profile.id)
    qntm.generateIdentityForProfile(profile.id)
  }

  createInvite(name: string): string {
    const result = qntm.createInviteForProfile(this.profileId, name)
    return result.inviteToken
  }

  async sendMessage(conversationId: string, text: string): Promise<void> {
    await qntm.sendMessageToConversation(this.profileId, this.profileName, conversationId, text)
  }

  async receiveMessages(conversationId: string): Promise<void> {
    await qntm.receiveMessages(this.profileId, this.profileName, conversationId)
  }

  getConversationId(token: string): string {
    // Accept the invite to get conversation ID, but Bob already has it from createInvite
    const convs = store.listConversations(this.profileId)
    return convs[convs.length - 1]?.id || ''
  }
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/fixtures/bob.ts && git commit -m "feat: add Bob fixture for programmatic e2e test client"
```

---

## Task 13: Create Alice fixture (Playwright page helpers)

**Files:**
- Create: `ui/aim-chat/tests/e2e/fixtures/alice.ts`

- [ ] **Step 1: Create Alice fixture**

Create `ui/aim-chat/tests/e2e/fixtures/alice.ts`:

```typescript
/**
 * Alice — Playwright page object for interacting with AIM UI in a real browser.
 */
import type { Page } from '@playwright/test'

export class Alice {
  constructor(private page: Page) {}

  /** Seed localStorage with the relay URL before navigating */
  async setup(relayUrl: string): Promise<void> {
    // Navigate to the app first to set the origin for localStorage
    await this.page.goto('/')
    // Seed the store with the relay URL
    await this.page.evaluate((url) => {
      const existing = localStorage.getItem('aim-store')
      const data = existing ? JSON.parse(existing) : {}
      data.dropboxUrl = url
      localStorage.setItem('aim-store', JSON.stringify(data))
    }, relayUrl)
    // Reload to pick up the seeded URL
    await this.page.reload()
  }

  /** Create a new profile */
  async createProfile(name: string): Promise<void> {
    // Click the Profile panel to expand it
    await this.page.getByText('Profile').click()
    await this.page.getByPlaceholderText('New profile name').fill(name)
    await this.page.getByRole('button', { name: 'Create' }).first().click()
    // Wait for identity generation
    await this.page.waitForSelector('text=Public Key')
  }

  /** Join a conversation using the sidebar InvitePanel */
  async joinInviteViaSidebar(token: string, name: string): Promise<void> {
    // Expand Invites panel
    await this.page.getByText('Invites').click()
    // Paste the invite token
    await this.page.getByPlaceholderText('Paste an invite link or token').fill(token)
    // Enter a label
    if (name) {
      await this.page.getByPlaceholderText('Label for this conversation (optional)').fill(name)
    }
    await this.page.getByRole('button', { name: 'Join' }).click()
    // Wait for the conversation to appear
    await this.page.waitForTimeout(500)
  }

  /** Join a conversation via the JoinModal (URL-based invite) */
  async joinInviteViaModal(name: string): Promise<void> {
    // The JoinModal should already be showing from URL params
    if (name) {
      await this.page.getByPlaceholderText('e.g. Team Chat, Project Alpha').fill(name)
    }
    await this.page.getByRole('button', { name: 'Join' }).click()
    await this.page.waitForTimeout(500)
  }

  /** Rename a conversation by clicking edit, typing new name, pressing Enter */
  async renameConversation(currentName: string, newName: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: currentName })
    await row.hover()
    await row.getByLabel('Rename conversation').click()
    const input = this.page.locator('.conversation-rename-input')
    await input.fill(newName)
    await input.press('Enter')
  }

  /** Delete a conversation — clicks delete then confirms dialog */
  async deleteConversation(name: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: name })
    await row.hover()
    await row.getByLabel('Delete conversation').click()
    // Confirm the dialog
    await this.page.getByRole('button', { name: 'Delete' }).click()
  }

  /** Cancel a delete confirmation */
  async cancelDeleteConversation(name: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: name })
    await row.hover()
    await row.getByLabel('Delete conversation').click()
    await this.page.getByRole('button', { name: 'Cancel' }).click()
  }

  /** Get all visible conversation names */
  async getConversationNames(): Promise<string[]> {
    const names = await this.page.locator('.conversation-name').allTextContents()
    return names
  }

  /** Refresh the page */
  async refresh(): Promise<void> {
    await this.page.reload()
    await this.page.waitForTimeout(500)
  }
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/fixtures/alice.ts && git commit -m "feat: add Alice page object fixture for e2e tests"
```

---

## Task 14: Write Playwright e2e test — rename

**Files:**
- Create: `ui/aim-chat/tests/e2e/rename.spec.ts`

- [ ] **Step 1: Write rename e2e test**

Create `ui/aim-chat/tests/e2e/rename.spec.ts`:

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

test('rename a conversation and verify persistence', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  // Bob creates an invite
  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Project Alpha')

    // Alice joins with the invite
    await alice.joinInviteViaSidebar(token, 'Project Alpha')

    // Verify conversation appears
    let names = await alice.getConversationNames()
    expect(names).toContain('Project Alpha')

    // Rename it
    await alice.renameConversation('Project Alpha', 'Project Beta')

    // Verify new name
    names = await alice.getConversationNames()
    expect(names).toContain('Project Beta')
    expect(names).not.toContain('Project Alpha')

    // Refresh and verify persistence
    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).toContain('Project Beta')
  } finally {
    bob.uninstall()
  }
})
```

- [ ] **Step 2: Run the test**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test tests/e2e/rename.spec.ts
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/rename.spec.ts && git commit -m "test: add Playwright e2e test for conversation rename"
```

---

## Task 15: Write Playwright e2e test — invite name persistence

**Files:**
- Create: `ui/aim-chat/tests/e2e/invite-name.spec.ts`

- [ ] **Step 1: Write invite name e2e test**

Create `ui/aim-chat/tests/e2e/invite-name.spec.ts`:

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

test('joining via sidebar preserves the custom name', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Bobs Chat')

    // Alice joins with her own custom name
    await alice.joinInviteViaSidebar(token, 'My Custom Chat')

    let names = await alice.getConversationNames()
    expect(names).toContain('My Custom Chat')

    // Refresh to verify persistence
    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).toContain('My Custom Chat')
  } finally {
    bob.uninstall()
  }
})

test('joining a second invite also preserves its name', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')

    const token1 = bob.createInvite('First')
    await alice.joinInviteViaSidebar(token1, 'Chat One')

    const token2 = bob.createInvite('Second')
    await alice.joinInviteViaSidebar(token2, 'Chat Two')

    const names = await alice.getConversationNames()
    expect(names).toContain('Chat One')
    expect(names).toContain('Chat Two')
  } finally {
    bob.uninstall()
  }
})
```

- [ ] **Step 2: Run the test**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test tests/e2e/invite-name.spec.ts
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/invite-name.spec.ts && git commit -m "test: add Playwright e2e test for invite name persistence"
```

---

## Task 16: Write Playwright e2e test — delete with confirmation

**Files:**
- Create: `ui/aim-chat/tests/e2e/delete.spec.ts`

- [ ] **Step 1: Write delete e2e test**

Create `ui/aim-chat/tests/e2e/delete.spec.ts`:

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

test('cancel delete keeps conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('To Delete')
    await alice.joinInviteViaSidebar(token, 'To Delete')

    // Click delete then cancel
    await alice.cancelDeleteConversation('To Delete')

    // Conversation still exists
    const names = await alice.getConversationNames()
    expect(names).toContain('To Delete')
  } finally {
    bob.uninstall()
  }
})

test('confirm delete removes conversation permanently', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Doomed')
    await alice.joinInviteViaSidebar(token, 'Doomed')

    // Verify it exists
    let names = await alice.getConversationNames()
    expect(names).toContain('Doomed')

    // Delete and confirm
    await alice.deleteConversation('Doomed')

    // Gone
    names = await alice.getConversationNames()
    expect(names).not.toContain('Doomed')

    // Still gone after refresh
    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).not.toContain('Doomed')
  } finally {
    bob.uninstall()
  }
})

test('deleting selected conversation clears the chat pane', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Active Chat')
    await alice.joinInviteViaSidebar(token, 'Active Chat')

    // Select the conversation
    await page.getByText('Active Chat').click()

    // Delete it
    await alice.deleteConversation('Active Chat')

    // The conversation should no longer be in the list
    const names = await alice.getConversationNames()
    expect(names).not.toContain('Active Chat')
  } finally {
    bob.uninstall()
  }
})
```

- [ ] **Step 2: Run the test**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test tests/e2e/delete.spec.ts
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && git add tests/e2e/delete.spec.ts && git commit -m "test: add Playwright e2e test for conversation deletion with confirmation"
```

---

## Task 17: Run full test suite and verify

- [ ] **Step 1: Run all vitest tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm test
```

Expected: all tests pass (existing + new component tests + new store tests).

- [ ] **Step 2: Run all Playwright tests**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npx playwright test
```

Expected: all e2e tests pass (rename, invite-name, delete).

- [ ] **Step 3: Verify the app builds**

```bash
cd /Users/pv/src/qntm/ui/aim-chat && npm run build
```

Expected: clean build with no TypeScript errors.

- [ ] **Step 4: Final commit if any fixes needed, then push**

```bash
git push
```
