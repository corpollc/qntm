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
    Object.defineProperty(globalThis, 'WebSocket', { value: WebSocket, configurable: true })
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
    const convs = store.listConversations(this.profileId)
    return convs[convs.length - 1]?.id || ''
  }
}
