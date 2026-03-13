/**
 * localStorage-backed store for AIM UI.
 * Replaces the Express server's filesystem storage.
 * All state lives in the browser — no server needed.
 */

const STORE_KEY = 'aim-store'
const DEFAULT_DROPBOX_URL = 'https://inbox.qntm.corpo.llc'

export interface StoredProfile {
  id: string
  name: string
}

export interface StoredIdentity {
  privateKey: string // hex
  publicKey: string  // hex
  keyId: string      // hex
}

export interface StoredConversationKeys {
  root: string     // hex
  aeadKey: string  // hex
  nonceKey: string // hex
}

export interface StoredConversation {
  id: string
  name: string
  type: string
  keys: StoredConversationKeys
  participants: string[] // hex key IDs
  participantPublicKeys?: string[] // hex public keys
  createdAt: string
  currentEpoch: number
}

export interface StoredMessage {
  id: string
  conversationId: string
  direction: 'incoming' | 'outgoing'
  sender: string
  senderKey: string
  bodyType: string
  text: string
  createdAt: string
}

interface StoreData {
  activeProfileId: string
  profiles: StoredProfile[]
  identities: Record<string, StoredIdentity>       // profileId -> identity
  conversations: Record<string, StoredConversation[]> // profileId -> conversations
  history: Record<string, Record<string, StoredMessage[]>> // profileId -> convId -> messages
  contacts: Record<string, Record<string, string>>  // profileId -> key -> name
  cursors: Record<string, Record<string, number>>    // profileId -> convId -> seq
  dropboxUrl: string
}

function normalizeConversation(raw: Partial<StoredConversation> | null | undefined): StoredConversation {
  return {
    id: typeof raw?.id === 'string' ? raw.id : '',
    name: typeof raw?.name === 'string' ? raw.name : '',
    type: typeof raw?.type === 'string' ? raw.type : 'direct',
    keys: {
      root: typeof raw?.keys?.root === 'string' ? raw.keys.root : '',
      aeadKey: typeof raw?.keys?.aeadKey === 'string' ? raw.keys.aeadKey : '',
      nonceKey: typeof raw?.keys?.nonceKey === 'string' ? raw.keys.nonceKey : '',
    },
    participants: Array.isArray(raw?.participants) ? raw.participants : [],
    participantPublicKeys: Array.isArray(raw?.participantPublicKeys) ? raw.participantPublicKeys : [],
    createdAt: typeof raw?.createdAt === 'string' ? raw.createdAt : new Date(0).toISOString(),
    currentEpoch: typeof raw?.currentEpoch === 'number' ? raw.currentEpoch : 0,
  }
}

function normalizeConversations(
  raw: Record<string, StoredConversation[]> | null | undefined,
): Record<string, StoredConversation[]> {
  if (!raw || typeof raw !== 'object') {
    return {}
  }

  return Object.fromEntries(
    Object.entries(raw).map(([profileId, conversations]) => [
      profileId,
      Array.isArray(conversations) ? conversations.map((conv) => normalizeConversation(conv)) : [],
    ]),
  )
}

function loadStore(): StoreData {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      return {
        activeProfileId: parsed.activeProfileId || '',
        profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
        identities: parsed.identities || {},
        conversations: normalizeConversations(parsed.conversations),
        history: parsed.history || {},
        contacts: parsed.contacts || {},
        cursors: parsed.cursors || {},
        dropboxUrl: parsed.dropboxUrl || DEFAULT_DROPBOX_URL,
      }
    }
  } catch { /* ignore */ }
  return {
    activeProfileId: '',
    profiles: [],
    identities: {},
    conversations: {},
    history: {},
    contacts: {},
    cursors: {},
    dropboxUrl: DEFAULT_DROPBOX_URL,
  }
}

function saveStore(store: StoreData): void {
  localStorage.setItem(STORE_KEY, JSON.stringify(store))
}

// Generates a short random hex suffix
function randomSuffix(): string {
  const arr = new Uint8Array(2)
  crypto.getRandomValues(arr)
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32)
}

// ---- Public API ----

export function listProfiles(): { activeProfileId: string; profiles: StoredProfile[] } {
  const store = loadStore()
  return { activeProfileId: store.activeProfileId, profiles: store.profiles }
}

export function createProfile(name: string): StoredProfile {
  const store = loadStore()
  const displayName = name.trim() || `Agent ${store.profiles.length + 1}`
  const slug = slugify(displayName) || `agent-${store.profiles.length + 1}`
  const id = `${slug}-${randomSuffix()}`
  const profile: StoredProfile = { id, name: displayName }
  store.profiles.push(profile)
  if (!store.activeProfileId) store.activeProfileId = id
  saveStore(store)
  return profile
}

export function selectProfile(profileId: string): void {
  const store = loadStore()
  if (!store.profiles.find(p => p.id === profileId)) throw new Error(`profile ${profileId} not found`)
  store.activeProfileId = profileId
  saveStore(store)
}

export function getIdentity(profileId: string): StoredIdentity | null {
  const store = loadStore()
  return store.identities[profileId] || null
}

export function saveIdentity(profileId: string, identity: StoredIdentity): void {
  const store = loadStore()
  store.identities[profileId] = identity
  // Auto-add self as contact in all profiles
  for (const p of store.profiles) {
    if (!store.contacts[p.id]) store.contacts[p.id] = {}
    const key = identity.keyId.toLowerCase()
    if (!store.contacts[p.id][key]) {
      const thisProfile = store.profiles.find(pp => pp.id === profileId)
      store.contacts[p.id][key] = thisProfile?.name || profileId
    }
  }
  saveStore(store)
}

export function listConversations(profileId: string): StoredConversation[] {
  const store = loadStore()
  return store.conversations[profileId] || []
}

export function addConversation(profileId: string, conv: StoredConversation): void {
  const store = loadStore()
  if (!store.conversations[profileId]) store.conversations[profileId] = []
  const existing = store.conversations[profileId].find(c => c.id === conv.id)
  if (!existing) {
    store.conversations[profileId].push(normalizeConversation(conv))
    saveStore(store)
  }
}

export function updateConversation(
  profileId: string,
  conversationId: string,
  updater: (conv: StoredConversation) => StoredConversation,
): StoredConversation | null {
  const store = loadStore()
  const convs = store.conversations[profileId] || []
  const index = convs.findIndex((conv) => conv.id === conversationId)
  if (index < 0) {
    return null
  }

  const updated = normalizeConversation(updater(convs[index]))
  convs[index] = updated
  saveStore(store)
  return updated
}

export function findConversation(profileId: string, conversationId: string): StoredConversation | null {
  const store = loadStore()
  const convs = store.conversations[profileId] || []
  return convs.find(c => c.id === conversationId) || null
}

export function listContacts(profileId: string): Array<{ key: string; name: string }> {
  const store = loadStore()
  const bucket = store.contacts[profileId] || {}
  return Object.entries(bucket)
    .filter(([k, v]) => k && typeof v === 'string' && v.trim())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, name]) => ({ key, name }))
}

export function setContact(profileId: string, key: string, name: string): void {
  const store = loadStore()
  if (!store.contacts[profileId]) store.contacts[profileId] = {}
  const normalizedKey = key.trim().toLowerCase()
  if (name.trim()) {
    store.contacts[profileId][normalizedKey] = name.trim()
  } else {
    delete store.contacts[profileId][normalizedKey]
  }
  saveStore(store)
}

export function resolveContactAlias(profileId: string, senderKey: string): string {
  const store = loadStore()
  const bucket = store.contacts[profileId] || {}
  const normalized = senderKey.trim().toLowerCase()
  const alias = bucket[normalized]
  return typeof alias === 'string' ? alias.trim() : ''
}

export function getHistory(profileId: string, conversationId: string): StoredMessage[] {
  const store = loadStore()
  return store.history?.[profileId]?.[conversationId] || []
}

export function addHistoryMessage(profileId: string, conversationId: string, message: StoredMessage): void {
  const store = loadStore()
  if (!store.history[profileId]) store.history[profileId] = {}
  if (!store.history[profileId][conversationId]) store.history[profileId][conversationId] = []
  const bucket = store.history[profileId][conversationId]

  // Dedup within 1.5s window
  const dedupeWindowMs = 1500
  const hasDuplicate = bucket.some(existing => {
    if (existing.direction !== message.direction) return false
    if (existing.sender !== message.sender) return false
    if (existing.bodyType !== message.bodyType) return false
    if (existing.text !== message.text) return false
    const existingTs = Date.parse(existing.createdAt)
    const incomingTs = Date.parse(message.createdAt)
    if (Number.isNaN(existingTs) || Number.isNaN(incomingTs)) return false
    return Math.abs(existingTs - incomingTs) <= dedupeWindowMs
  })
  if (hasDuplicate) return

  bucket.push(message)
  if (bucket.length > 1000) bucket.splice(0, bucket.length - 1000)
  saveStore(store)
}

export function hasRecentOutgoingMatch(profileId: string, conversationId: string, message: StoredMessage, windowMs: number): boolean {
  const bucket = getHistory(profileId, conversationId)
  const incomingTs = Date.parse(message.createdAt)
  if (Number.isNaN(incomingTs)) return false
  return bucket.some(existing => {
    if (existing.direction !== 'outgoing') return false
    if (existing.bodyType !== message.bodyType || existing.text !== message.text) return false
    const existingTs = Date.parse(existing.createdAt)
    if (Number.isNaN(existingTs)) return false
    return Math.abs(existingTs - incomingTs) <= windowMs
  })
}

export function loadCursor(profileId: string, conversationId: string): number {
  const store = loadStore()
  return store.cursors?.[profileId]?.[conversationId] || 0
}

export function saveCursor(profileId: string, conversationId: string, seq: number): void {
  const store = loadStore()
  if (!store.cursors[profileId]) store.cursors[profileId] = {}
  store.cursors[profileId][conversationId] = seq
  saveStore(store)
}

export function getDropboxUrl(): string {
  const store = loadStore()
  return store.dropboxUrl || DEFAULT_DROPBOX_URL
}

export function setDropboxUrl(url: string): void {
  const store = loadStore()
  store.dropboxUrl = url.trim().replace(/\/+$/, '') || DEFAULT_DROPBOX_URL
  saveStore(store)
}

export { DEFAULT_DROPBOX_URL }
