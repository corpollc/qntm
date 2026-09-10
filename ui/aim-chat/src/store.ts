/**
 * localStorage-backed store for AIM UI.
 * Replaces the Express server's filesystem storage.
 * All state lives in the browser — no server needed.
 */

import type { GroupAdmission, GroupSessionState, GatewayInvitation, GatewayBootstrapRequest } from '@corpollc/qntm'
import type { GuidanceContact } from './guidance'

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

export interface StoredGatewayIdentity {
  status?: 'pending' | 'active'
  invitationId?: string
  floor?: number
  pending?: { invitation: GatewayInvitation; request: GatewayBootstrapRequest; url: string; messageId: string; text: string }

  publicKey: string // base64url
  keyId: string     // base64url
}

export interface StoredGroupAdditionOrigin {
  kind: 'addition'
  controls: string[]
  welcomes: string[]
  delivered: number
  recipient: string
  admission: Pick<GroupAdmission, 'addId' | 'addDigest'>
  recoveryChallenge: string | null
  delivery: 'unknown'
}
export interface StoredGroupOperationEvidence {
  kind: 'addition_rekey' | 'renewal' | 'refresh' | 'removal_rekey' | 'rekey'
  controls: string[]
  welcomes: string[]
  delivered: number
  delivery: 'unknown'
}
/** The exact member incarnation a saved removal targets: full key, canonical
 * roster record and admission provenance at intent time. A later readmission of
 * the same identity never matches it. */
export interface StoredGroupRemovalTarget {
  keyId: string
  publicKey: string
  record: string
  admission: GroupAdmission | null
}
export interface StoredGroupRemovalOrigin {
  kind: 'remove'
  controls: string[]
  welcomes: string[]
  delivered: number
  target?: StoredGroupRemovalTarget
  delivery: 'unknown'
}
export type StoredGroupOperation = {
  controls: string[]
  welcomes: string[]
  delivered: number
  expected: GroupSessionState
} & ({ kind: 'create'; recipient?: never; admission?: never; recoveryChallenge?: never; origin?: never; superseded?: never; target?: never }
  | { kind: 'remove'; target?: StoredGroupRemovalTarget; recipient?: never; admission?: never; recoveryChallenge?: never; origin?: never; superseded?: never }
  | { kind: 'rekey'; superseded?: StoredGroupOperationEvidence[]; recipient?: never; admission?: never; recoveryChallenge?: never; origin?: never; target?: never }
  | { kind: 'removal_rekey'; origin: StoredGroupRemovalOrigin; superseded?: StoredGroupOperationEvidence[]; recipient?: never; admission?: never; recoveryChallenge?: never; target?: never }
  | { kind: 'refresh'; recipient?: string; recoveryChallenge?: string | null; admission?: never; origin?: never; superseded?: StoredGroupOperationEvidence[]; target?: never }
  | { kind: 'addition'; recipient?: string; recoveryChallenge?: string | null; admission?: never; origin?: never; superseded?: never; target?: never }
  | { kind: 'addition_rekey'; recipient: string; origin: StoredGroupAdditionOrigin; superseded?: StoredGroupOperationEvidence[]; admission?: never; recoveryChallenge?: never; target?: never }
  | { kind: 'renewal'; recipient: string; admission: GroupAdmission; origin?: StoredGroupAdditionOrigin; superseded?: StoredGroupOperationEvidence[]; recoveryChallenge?: never; target?: never })

export const GROUP_RELEASE_REASONS = ['expired', 'superseded', 'wrong_branch', 'target_absent', 'inapplicable', 'incarnation_changed', 'legacy_same_epoch_admission'] as const
export type StoredGroupReleaseReason = typeof GROUP_RELEASE_REASONS[number]
/** A removal journal whose local retry was explicitly given up. Its uncertain
 * ciphertext stays as evidence; nothing here records a remote outcome. */
export interface StoredGroupReleasedOperation {
  kind: 'remove' | 'removal_rekey'
  controls: string[]
  welcomes: string[]
  delivered: number
  target?: StoredGroupRemovalTarget
  origin?: StoredGroupRemovalOrigin
  superseded?: StoredGroupOperationEvidence[]
  delivery: 'unknown'
  releasedReason: StoredGroupReleaseReason
  releasedAt: number
}
export type StoredGroupControlBody = 'group_genesis' | 'group_add' | 'group_remove' | 'group_rekey'
export const MAX_GROUP_CONTROL_RECEIPTS = 64
/** Private exact pending-control receive proof. Missing entries stay unknown. */
export interface StoredGroupControlReceipt {
  id: string
  digest: string
  epoch: number
  sequence: number
  valid: boolean
  bodyType: StoredGroupControlBody
}
export interface StoredGroup {
  session: GroupSessionState
  cursor: number
  bootstrapSequence: number
  removedSequence?: number
  pending: Array<{ seq: number; wire: string }>
  receipts: number[]
  controlReceipts?: StoredGroupControlReceipt[]
  releasedOperations?: StoredGroupReleasedOperation[]
  operation: StoredGroupOperation | null
  relayUrl: string
  inviterPublicKey: string
  revision: number
}

export interface StoredConversation {
  id: string
  name: string
  type: string
  keys: StoredConversationKeys
  participants: string[] // hex key IDs
  participantPublicKeys?: string[] // hex public keys
  gateway?: StoredGatewayIdentity | null
  createdAt: string
  currentEpoch: number
  inviteToken?: string
  group?: StoredGroup
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
  /** Exact authenticated ordinary-group envelope. Invalid branch history is
   * retained privately but cannot be displayed or dispatched as current. */
  groupBinding?: { digest: string; epoch: number; valid: boolean }
}

export interface StoreData {
  activeProfileId: string
  profiles: StoredProfile[]
  identities: Record<string, StoredIdentity>       // profileId -> identity
  conversations: Record<string, StoredConversation[]> // profileId -> conversations
  history: Record<string, Record<string, StoredMessage[]>> // profileId -> convId -> messages
  contactPins?: Record<string, Record<string, string>> // profile -> key ID -> full public key
  contacts: Record<string, Record<string, string>>  // profileId -> key -> name
  guidanceContacts: Record<string, GuidanceContact[]>
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
    gateway: raw?.gateway && typeof raw.gateway === 'object'
      ? {
          status: raw.gateway.status,
          invitationId: raw.gateway.invitationId,
          floor: raw.gateway.floor,
          pending: raw.gateway.pending,
          publicKey: typeof raw.gateway.publicKey === 'string' ? raw.gateway.publicKey : '',
          keyId: typeof raw.gateway.keyId === 'string' ? raw.gateway.keyId : '',
        }
      : null,
    createdAt: typeof raw?.createdAt === 'string' ? raw.createdAt : new Date(0).toISOString(),
    currentEpoch: typeof raw?.currentEpoch === 'number' ? raw.currentEpoch : 0,
    inviteToken: typeof raw?.inviteToken === 'string' ? raw.inviteToken : undefined,
    group: raw?.group,
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
        contactPins: parsed.contactPins || {},
        guidanceContacts: parsed.guidanceContacts || {},
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
    contactPins: {},
    guidanceContacts: {},
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

export function renameProfile(profileId: string, newName: string): StoredProfile {
  const store = loadStore()
  const profile = store.profiles.find(p => p.id === profileId)
  if (!profile) throw new Error(`profile ${profileId} not found`)
  profile.name = newName.trim() || profile.name
  saveStore(store)
  return profile
}

export function deleteProfile(profileId: string): void {
  const store = loadStore()
  store.profiles = store.profiles.filter(p => p.id !== profileId)
  delete store.identities[profileId]
  delete store.conversations[profileId]
  delete store.history[profileId]
  delete store.contacts[profileId]
  if (store.contactPins) delete store.contactPins[profileId]
  delete store.guidanceContacts[profileId]
  delete store.cursors[profileId]
  if (store.activeProfileId === profileId) {
    store.activeProfileId = store.profiles[0]?.id || ''
  }
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

  const revision = convs[index].group?.revision
  const updated = normalizeConversation(updater(convs[index]))
  if (updated.group && revision !== undefined) updated.group.revision = revision + 1
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

export function listGuidanceContacts(profileId: string): GuidanceContact[] {
  const contacts = loadStore().guidanceContacts[profileId]
  return Array.isArray(contacts) ? contacts : []
}

export function saveGuidanceContact(profileId: string, contact: GuidanceContact): void {
  const store = loadStore()
  const contacts = store.guidanceContacts[profileId] || []
  store.guidanceContacts[profileId] = [...contacts.filter(c => c.id !== contact.id), contact]
  saveStore(store)
}

export function removeGuidanceContact(profileId: string, contactId: string): void {
  const store = loadStore()
  store.guidanceContacts[profileId] = (store.guidanceContacts[profileId] || []).filter(c => c.id !== contactId)
  saveStore(store)
}

export function setContact(profileId: string, key: string, name: string): void {
  const store = loadStore()
  if (!store.contacts[profileId]) store.contacts[profileId] = {}
  const normalizedKey = key.trim().toLowerCase()
  if (name.trim()) {
    store.contacts[profileId][normalizedKey] = name.trim()
  } else {
    delete store.contacts[profileId]
  if (store.contactPins) delete store.contactPins[profileId][normalizedKey]
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

export function getVisibleHistory(profileId: string, conversationId: string): StoredMessage[] {
  const data = loadStore(), rows = data.history?.[profileId]?.[conversationId] || []
  return data.conversations[profileId]?.find(conv => conv.id === conversationId)?.group
    ? rows.filter(row => row.groupBinding?.valid === true)
    : rows
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

export { DEFAULT_DROPBOX_URL }

/** One localStorage write commits keys, membership, ciphertext, history and cursor.
 * Group hosts hold a Web Lock across network/receive operations and re-read other
 * profiles here, so unrelated synchronous edits are not overwritten. */
export function commitGroup(profileId: string, conv: StoredConversation, history: StoredMessage[], expectedRevision?: number): void {
  const data = loadStore()
  const conversations = data.conversations[profileId] ?? []
  const index = conversations.findIndex(c => c.id === conv.id)
  const current = conversations[index]
  if (expectedRevision !== undefined && current?.group?.revision !== expectedRevision) throw new Error('Group changed in another tab; retry')
  if (!data.identities[profileId] || data.identities[profileId].keyId !== conv.group?.session.identityKid) throw new Error('Group identity changed; reopen this profile')
  if (index < 0) conversations.push(normalizeConversation(conv))
  else conversations[index] = normalizeConversation(conv)
  data.conversations[profileId] = conversations
  data.history[profileId] ??= {}
  data.history[profileId][conv.id] = history.slice(-1000)
  data.cursors[profileId] ??= {}
  data.cursors[profileId][conv.id] = conv.group!.cursor
  saveStore(data)
}

export function listContactPins(profileId: string): Array<{ key: string; publicKey: string; name: string }> {
  const data = loadStore()
  return Object.entries(data.contactPins?.[profileId] ?? {}).map(([key, publicKey]) => ({ key, publicKey, name: data.contacts[profileId]?.[key] || key }))
}

export function saveContactPin(profileId: string, key: string, publicKey: string, name: string): void {
  const data = loadStore()
  data.contactPins ??= {}
  data.contactPins[profileId] ??= {}
  data.contacts[profileId] ??= {}
  const existing = Object.entries(data.contactPins[profileId]).find(([kid]) => data.contacts[profileId]?.[kid]?.toLowerCase() === name.toLowerCase())
  if (existing && existing[1] !== publicKey) throw new Error('That contact name already pins another identity; remove the old pin first')
  if (data.contactPins[profileId][key] && data.contactPins[profileId][key] !== publicKey) throw new Error('Contact public key does not match its existing pin')
  data.contactPins[profileId][key] = publicKey
  data.contacts[profileId][key] = name
  saveStore(data)
}

export function removeContactPin(profileId: string, key: string): void {
  const data = loadStore()
  if (data.contactPins?.[profileId]) delete data.contactPins[profileId][key]
  saveStore(data)
}
