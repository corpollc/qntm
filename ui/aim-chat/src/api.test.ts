import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import * as qntm from './qntm'

class MemoryStorage implements Storage {
  private data = new Map<string, string>()

  get length(): number {
    return this.data.size
  }

  clear(): void {
    this.data.clear()
  }

  getItem(key: string): string | null {
    return this.data.has(key) ? this.data.get(key)! : null
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null
  }

  removeItem(key: string): void {
    this.data.delete(key)
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value)
  }
}

describe('api', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('round-trips backups through local storage', () => {
    const profile = api.createProfile('Agent 1').profile
    api.generateIdentity(profile.id)
    api.createInvite(profile.id, 'Backup Test')

    const backup = api.exportBackup()
    localStorage.clear()
    api.importBackup(backup)

    const profiles = api.listProfiles()
    expect(profiles.profiles).toHaveLength(1)
    expect(profiles.profiles[0]).toMatchObject({ id: profile.id, name: profile.name })
    expect(api.listConversations(profile.id).conversations).toHaveLength(1)
  })

  it('loads starter gate recipes', () => {
    const recipes = api.gateRecipes()
    expect(recipes.recipes.length).toBeGreaterThan(0)
    expect(recipes.recipes.some((recipe) => recipe.name === 'jokes.dad')).toBe(true)
  })

  it('bootstraps the gateway before sending gate.promote', async () => {
    const bootstrapSpy = vi.spyOn(qntm, 'bootstrapGatewayForConversation').mockResolvedValue({
      gatewayPublicKey: 'gateway-public-key',
      gatewayKid: 'gateway-kid',
    })
    const promoteSpy = vi.spyOn(qntm, 'gatePromoteRequest').mockResolvedValue({
      id: 'm1',
      conversationId: 'conv-1',
      direction: 'outgoing',
      sender: 'Alice',
      senderKey: '',
      bodyType: 'gate.promote',
      text: '{"type":"gate.promote"}',
      createdAt: new Date().toISOString(),
    })

    const response = await api.gatePromote('profile-1', 'Alice', 'conv-1', 'http://gateway.test', 2)

    expect(bootstrapSpy).toHaveBeenCalledWith('profile-1', 'conv-1', 'http://gateway.test')
    expect(promoteSpy).toHaveBeenCalledWith('profile-1', 'Alice', 'conv-1', 'gateway-kid', 2)
    expect(response.message.bodyType).toBe('gate.promote')
  })
})

describe('api.renameConversation', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('updates the conversation name', async () => {
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
