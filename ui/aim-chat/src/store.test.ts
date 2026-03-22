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
