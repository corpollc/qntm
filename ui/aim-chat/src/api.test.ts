import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

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
})
