import cors from 'cors'
import express from 'express'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'

// Import @qntm/client library (replaces Go binary invocations)
import {
  generateIdentity as clientGenerateIdentity,
  keyIDToString,
  publicKeyToString,
  serializeIdentity,
  deserializeIdentity,
  validateIdentity,
  keyIDFromPublicKey,
  createInvite,
  inviteToToken,
  inviteFromURL,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  createMessage,
  decryptMessage,
  serializeEnvelope,
  deserializeEnvelope,
  defaultTTL,
  marshalCanonical,
  unmarshalCanonical,
  base64UrlEncode,
} from '@qntm/client'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const APP_ROOT = path.resolve(__dirname, '..')

const DATA_ROOT = path.join(APP_ROOT, '.qntm-ui')
const PROFILES_ROOT = path.join(DATA_ROOT, 'profiles')
const SHARED_DROPBOX_DIR = path.join(DATA_ROOT, 'dropbox')
const STORE_PATH = path.join(DATA_ROOT, 'store.json')
const SELF_ECHO_WINDOW_MS = Number(process.env.QNTM_UI_SELF_ECHO_WINDOW_MS || 60000)

const PORT = Number(process.env.QNTM_UI_API_PORT || 8787)

const app = express()
app.use(cors())
app.use(express.json({ limit: '1mb' }))

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
}

function fileExists(targetPath) {
  try {
    fs.accessSync(targetPath, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

function ensureDataRoot() {
  fs.mkdirSync(DATA_ROOT, { recursive: true })
  fs.mkdirSync(PROFILES_ROOT, { recursive: true })
  fs.mkdirSync(SHARED_DROPBOX_DIR, { recursive: true })
}

function loadStore() {
  ensureDataRoot()

  if (!fileExists(STORE_PATH)) {
    return {
      activeProfileId: '',
      profiles: [],
      history: {},
      contacts: {},
    }
  }

  const raw = fs.readFileSync(STORE_PATH, 'utf8')
  const parsed = JSON.parse(raw)
  return {
    activeProfileId: parsed.activeProfileId || '',
    profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
    history: parsed.history && typeof parsed.history === 'object' ? parsed.history : {},
    contacts: parsed.contacts && typeof parsed.contacts === 'object' ? parsed.contacts : {},
  }
}

function saveStore(store) {
  ensureDataRoot()
  fs.writeFileSync(STORE_PATH, `${JSON.stringify(store, null, 2)}\n`, 'utf8')
}

function getProfileOrThrow(store, id) {
  const profile = store.profiles.find((entry) => entry.id === id)
  if (!profile) {
    const error = new Error(`profile ${id} not found`)
    error.statusCode = 404
    throw error
  }
  return profile
}

function ensureProfileFilesystem(profile) {
  fs.mkdirSync(profile.configDir, { recursive: true })
}

// --- Identity helpers ---

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex')
}

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'))
}

function loadIdentity(profile) {
  const identityPath = path.join(profile.configDir, 'identity.json')
  if (!fileExists(identityPath)) {
    return null
  }

  const raw = JSON.parse(fs.readFileSync(identityPath, 'utf8'))
  return {
    privateKey: hexToBytes(raw.private_key),
    publicKey: hexToBytes(raw.public_key),
    keyID: hexToBytes(raw.key_id),
  }
}

function saveIdentity(profile, identity) {
  const identityPath = path.join(profile.configDir, 'identity.json')
  const data = {
    private_key: bytesToHex(identity.privateKey),
    public_key: bytesToHex(identity.publicKey),
    key_id: bytesToHex(identity.keyID),
  }
  fs.writeFileSync(identityPath, JSON.stringify(data, null, 2) + '\n', 'utf8')
}

// --- Conversation helpers ---

function loadConversations(profile) {
  const conversationsPath = path.join(profile.configDir, 'conversations.json')
  if (!fileExists(conversationsPath)) {
    return []
  }

  const raw = JSON.parse(fs.readFileSync(conversationsPath, 'utf8'))
  if (!Array.isArray(raw)) {
    return []
  }

  return raw
}

function saveConversations(profile, conversations) {
  const conversationsPath = path.join(profile.configDir, 'conversations.json')
  fs.writeFileSync(conversationsPath, JSON.stringify(conversations, null, 2) + '\n', 'utf8')
}

function formatConversationsForClient(conversations) {
  return conversations.map((conv) => {
    const id = conv.id
    const participants = Array.isArray(conv.participants) ? conv.participants : []
    const fallbackName = `${conv.type || 'chat'}-${id.slice(0, 8)}`
    return {
      id,
      name: conv.name || fallbackName,
      type: conv.type || 'direct',
      participants,
      createdAt: conv.createdAt || null,
    }
  })
}

function findConversation(profile, conversationId) {
  const conversations = loadConversations(profile)
  return conversations.find((c) => c.id === conversationId) || null
}

function getConversationCryptoState(profile, conversationId) {
  const conv = findConversation(profile, conversationId)
  if (!conv) {
    return null
  }
  // Reconstruct the conversation object with crypto keys
  return {
    id: hexToBytes(conv.id),
    type: conv.type,
    keys: {
      root: hexToBytes(conv.keys.root),
      aeadKey: hexToBytes(conv.keys.aeadKey),
      nonceKey: hexToBytes(conv.keys.nonceKey),
    },
    participants: (conv.participants || []).map((p) => hexToBytes(p)),
    createdAt: new Date(conv.createdAt || Date.now()),
    currentEpoch: conv.currentEpoch || 0,
  }
}

// --- Message storage (local filesystem dropbox) ---

function getDropboxDir(conversationId) {
  const dir = path.join(SHARED_DROPBOX_DIR, conversationId)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function storeEnvelope(conversationId, envelope) {
  const dir = getDropboxDir(conversationId)
  const msgIdHex = bytesToHex(envelope.msg_id)
  const filePath = path.join(dir, `${msgIdHex}.cbor`)
  const data = serializeEnvelope(envelope)
  fs.writeFileSync(filePath, Buffer.from(data))
}

function loadEnvelopes(conversationId) {
  const dir = getDropboxDir(conversationId)
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.cbor')).sort()

  const envelopes = []
  for (const file of files) {
    try {
      const data = new Uint8Array(fs.readFileSync(path.join(dir, file)))
      const envelope = deserializeEnvelope(data)
      envelopes.push(envelope)
    } catch {
      // Skip corrupt files
    }
  }
  return envelopes
}

function loadCursor(profile, conversationId) {
  const cursorsPath = path.join(profile.configDir, 'cursors.json')
  if (!fileExists(cursorsPath)) {
    return new Set()
  }
  const raw = JSON.parse(fs.readFileSync(cursorsPath, 'utf8'))
  const seen = raw[conversationId] || []
  return new Set(seen)
}

function saveCursor(profile, conversationId, seenSet) {
  const cursorsPath = path.join(profile.configDir, 'cursors.json')
  let raw = {}
  if (fileExists(cursorsPath)) {
    raw = JSON.parse(fs.readFileSync(cursorsPath, 'utf8'))
  }
  raw[conversationId] = Array.from(seenSet)
  fs.writeFileSync(cursorsPath, JSON.stringify(raw, null, 2) + '\n', 'utf8')
}

// --- Contact helpers ---

function extractSenderKey(sender) {
  if (typeof sender !== 'string') return ''
  const trimmed = sender.trim()
  if (!trimmed) return ''
  const wrappedMatch = trimmed.match(/\(([^()]+)\)\s*$/)
  if (wrappedMatch) return wrappedMatch[1].trim()
  return trimmed
}

function normalizeSenderKey(sender) {
  return extractSenderKey(sender).toLowerCase()
}

function senderLookupKeys(...labels) {
  const result = new Set()
  for (const value of labels) {
    if (typeof value !== 'string') continue
    const raw = value.trim()
    if (!raw) continue
    result.add(raw.toLowerCase())
    const extracted = normalizeSenderKey(raw)
    if (extracted) result.add(extracted)
  }
  return result
}

function ensureContactsBucket(store, profileId) {
  if (!store.contacts || typeof store.contacts !== 'object') store.contacts = {}
  if (!store.contacts[profileId] || typeof store.contacts[profileId] !== 'object') store.contacts[profileId] = {}
  return store.contacts[profileId]
}

function listContacts(store, profileId) {
  const bucket = ensureContactsBucket(store, profileId)
  return Object.entries(bucket)
    .filter(([key, value]) => key && typeof value === 'string' && value.trim())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, name]) => ({ key, name }))
}

function resolveContactAlias(store, profileId, sender) {
  const normalizedKey = normalizeSenderKey(sender)
  if (!normalizedKey) return ''
  const bucket = ensureContactsBucket(store, profileId)
  const alias = bucket[normalizedKey]
  return typeof alias === 'string' ? alias.trim() : ''
}

function formatMessageForClient(store, profileId, message) {
  const senderKey = message.senderKey || extractSenderKey(message.sender)
  const alias = message.direction === 'incoming'
    ? resolveContactAlias(store, profileId, senderKey)
    : ''
  return { ...message, senderKey, sender: alias || message.sender }
}

function ensureHistoryBucket(store, profileId, conversationId) {
  if (!store.history[profileId]) store.history[profileId] = {}
  if (!store.history[profileId][conversationId]) store.history[profileId][conversationId] = []
  return store.history[profileId][conversationId]
}

function addHistoryMessage(store, profileId, conversationId, message) {
  const bucket = ensureHistoryBucket(store, profileId, conversationId)
  const dedupeWindowMs = 1500
  const hasRecentDuplicate = bucket.some((existing) => {
    const sameCore =
      existing.direction === message.direction &&
      existing.sender === message.sender &&
      existing.bodyType === message.bodyType &&
      existing.text === message.text
    if (!sameCore) return false
    const existingTs = Date.parse(existing.createdAt)
    const incomingTs = Date.parse(message.createdAt)
    if (Number.isNaN(existingTs) || Number.isNaN(incomingTs)) return false
    return Math.abs(existingTs - incomingTs) <= dedupeWindowMs
  })
  if (hasRecentDuplicate) return
  bucket.push(message)
  if (bucket.length > 1000) bucket.splice(0, bucket.length - 1000)
}

function hasRecentOutgoingMatch(bucket, message, windowMs) {
  const incomingTs = Date.parse(message.createdAt)
  if (Number.isNaN(incomingTs)) return false
  return bucket.some((existing) => {
    if (existing.direction !== 'outgoing') return false
    if (existing.bodyType !== message.bodyType || existing.text !== message.text) return false
    const existingTs = Date.parse(existing.createdAt)
    if (Number.isNaN(existingTs)) return false
    return Math.abs(existingTs - incomingTs) <= windowMs
  })
}

function route(handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res)
    } catch (error) {
      next(error)
    }
  }
}

// =========== ROUTES ===========

app.get('/api/health', (_req, res) => {
  res.json({ ok: true })
})

app.get('/api/profiles', route(async (_req, res) => {
  const store = loadStore()
  res.json({
    activeProfileId: store.activeProfileId,
    profiles: store.profiles,
  })
}))

app.post('/api/profiles', route(async (req, res) => {
  const store = loadStore()

  const rawName = typeof req.body.name === 'string' ? req.body.name.trim() : ''
  const name = rawName || `Agent ${store.profiles.length + 1}`
  const slug = slugify(name) || `agent-${store.profiles.length + 1}`
  const id = `${slug}-${crypto.randomBytes(2).toString('hex')}`

  const configDir = path.resolve(path.join(PROFILES_ROOT, id, 'config'))

  const profile = {
    id,
    name,
    configDir,
    storage: '',
    dropboxUrl: '',
    qntmBin: '',
  }

  ensureProfileFilesystem(profile)

  store.profiles.push(profile)
  if (!store.activeProfileId) {
    store.activeProfileId = id
  }

  saveStore(store)
  res.status(201).json({ profile })
}))

app.post('/api/profiles/:profileId/select', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  store.activeProfileId = profile.id
  saveStore(store)

  res.json({ activeProfileId: store.activeProfileId })
}))

app.get('/api/profiles/:profileId/identity', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)
  const identity = loadIdentity(profile)

  if (!identity) {
    res.json({ exists: false, keyId: '', publicKey: '' })
    return
  }

  res.json({
    exists: true,
    keyId: bytesToHex(identity.keyID),
    publicKey: bytesToHex(identity.publicKey),
  })
}))

app.post('/api/profiles/:profileId/identity/generate', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  // Generate identity using @qntm/client
  const identity = clientGenerateIdentity()

  // Save to disk
  ensureProfileFilesystem(profile)
  saveIdentity(profile, identity)

  const keyIdHex = bytesToHex(identity.keyID)

  // Auto-add self as contact in all profiles
  for (const p of store.profiles) {
    const bucket = ensureContactsBucket(store, p.id)
    if (!bucket[keyIdHex.toLowerCase()]) {
      bucket[keyIdHex.toLowerCase()] = profile.name
    }
  }
  saveStore(store)

  res.json({
    output: 'Identity generated using @qntm/client',
    identity: {
      exists: true,
      keyId: keyIdHex,
      publicKey: bytesToHex(identity.publicKey),
    },
  })
}))

app.get('/api/profiles/:profileId/conversations', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)
  const conversations = loadConversations(profile)

  res.json({ conversations: formatConversationsForClient(conversations) })
}))

app.get('/api/profiles/:profileId/contacts', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  res.json({
    contacts: listContacts(store, profile.id),
  })
}))

app.post('/api/profiles/:profileId/contacts', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const keyInput = typeof req.body.key === 'string' ? req.body.key : ''
  const senderInput = typeof req.body.sender === 'string' ? req.body.sender : ''
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : ''
  const normalizedKey = normalizeSenderKey(keyInput || senderInput)

  if (!normalizedKey) {
    const error = new Error('contact key is required')
    error.statusCode = 400
    throw error
  }

  const bucket = ensureContactsBucket(store, profile.id)
  if (name) {
    bucket[normalizedKey] = name
  } else {
    delete bucket[normalizedKey]
  }

  saveStore(store)

  res.json({
    contacts: listContacts(store, profile.id),
  })
}))

app.post('/api/profiles/:profileId/invite/create', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const identity = loadIdentity(profile)
  if (!identity) {
    const error = new Error('no identity found for this profile; generate one first')
    error.statusCode = 400
    throw error
  }

  const rawName = typeof req.body.name === 'string' ? req.body.name.trim() : ''
  const selfJoin = req.body.selfJoin !== false

  // Create invite using @qntm/client
  const invite = createInvite(identity, 'direct')
  const token = inviteToToken(invite)
  const convIdHex = bytesToHex(invite.conv_id)

  // Derive keys and create conversation
  const keys = deriveConversationKeys(invite)
  const conv = createConversation(invite, keys)

  // If self-join, add own identity as participant
  if (selfJoin) {
    addParticipant(conv, identity.publicKey)
  }

  // Save conversation to disk
  const conversations = loadConversations(profile)
  const convRecord = {
    id: convIdHex,
    name: rawName || `Chat ${convIdHex.slice(0, 8)}`,
    type: 'direct',
    keys: {
      root: bytesToHex(keys.root),
      aeadKey: bytesToHex(keys.aeadKey),
      nonceKey: bytesToHex(keys.nonceKey),
    },
    participants: conv.participants.map((p) => bytesToHex(p)),
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
  }
  conversations.push(convRecord)
  saveConversations(profile, conversations)

  res.json({
    inviteToken: token,
    conversationId: convIdHex.toLowerCase(),
    output: 'Invite created using @qntm/client',
    conversations: formatConversationsForClient(conversations),
  })
}))

app.post('/api/profiles/:profileId/invite/accept', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const identity = loadIdentity(profile)
  if (!identity) {
    const error = new Error('no identity found for this profile; generate one first')
    error.statusCode = 400
    throw error
  }

  const token = typeof req.body.token === 'string' ? req.body.token.trim() : ''
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : ''

  if (!token) {
    const error = new Error('invite token is required')
    error.statusCode = 400
    throw error
  }

  // Parse invite and derive keys using @qntm/client
  const invite = inviteFromURL(token)
  const keys = deriveConversationKeys(invite)
  const conv = createConversation(invite, keys)

  // Add self as participant
  addParticipant(conv, identity.publicKey)

  const convIdHex = bytesToHex(invite.conv_id)

  // Check if conversation already exists
  const conversations = loadConversations(profile)
  const existing = conversations.find((c) => c.id === convIdHex)
  if (existing) {
    res.json({
      conversationId: convIdHex.toLowerCase(),
      output: 'Conversation already exists',
      conversations: formatConversationsForClient(conversations),
    })
    return
  }

  // Save conversation
  const convRecord = {
    id: convIdHex,
    name: name || `Chat ${convIdHex.slice(0, 8)}`,
    type: invite.type || 'direct',
    keys: {
      root: bytesToHex(keys.root),
      aeadKey: bytesToHex(keys.aeadKey),
      nonceKey: bytesToHex(keys.nonceKey),
    },
    participants: conv.participants.map((p) => bytesToHex(p)),
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
  }
  conversations.push(convRecord)
  saveConversations(profile, conversations)

  res.json({
    conversationId: convIdHex.toLowerCase(),
    output: 'Invite accepted using @qntm/client',
    conversations: formatConversationsForClient(conversations),
  })
}))

app.get('/api/profiles/:profileId/history', route(async (req, res) => {
  const store = loadStore()
  getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.query.conversationId === 'string'
    ? req.query.conversationId.trim().toLowerCase()
    : ''

  if (!conversationId) {
    const error = new Error('conversationId query parameter is required')
    error.statusCode = 400
    throw error
  }

  const bucket = store.history?.[req.params.profileId]?.[conversationId] || []
  res.json({
    messages: bucket.map((message) => formatMessageForClient(store, req.params.profileId, message)),
  })
}))

app.post('/api/profiles/:profileId/messages/send', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''
  const text = typeof req.body.text === 'string' ? req.body.text : ''

  if (!conversationId) {
    const error = new Error('conversationId is required')
    error.statusCode = 400
    throw error
  }

  if (!text.trim()) {
    const error = new Error('message text is required')
    error.statusCode = 400
    throw error
  }

  const identity = loadIdentity(profile)
  if (!identity) {
    const error = new Error('no identity found for this profile')
    error.statusCode = 400
    throw error
  }

  const convCrypto = getConversationCryptoState(profile, conversationId)
  if (!convCrypto) {
    const error = new Error(`conversation ${conversationId} not found`)
    error.statusCode = 404
    throw error
  }

  // Create and encrypt message using @qntm/client
  const bodyBytes = new TextEncoder().encode(text)
  const envelope = createMessage(identity, convCrypto, 'text', bodyBytes, undefined, defaultTTL())

  // Store encrypted envelope to shared dropbox
  storeEnvelope(conversationId, envelope)

  const message = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'text',
    text,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  res.json({
    output: 'Message sent using @qntm/client',
    warning: '',
    message: formatMessageForClient(store, profile.id, message),
  })
}))

app.post('/api/profiles/:profileId/messages/receive', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''

  if (!conversationId) {
    const error = new Error('conversationId is required')
    error.statusCode = 400
    throw error
  }

  const identity = loadIdentity(profile)
  if (!identity) {
    const error = new Error('no identity found for this profile')
    error.statusCode = 400
    throw error
  }

  const convCrypto = getConversationCryptoState(profile, conversationId)
  if (!convCrypto) {
    res.json({ messages: [], suppressedSelfEchoes: 0, output: '', warning: '' })
    return
  }

  // Load all envelopes from dropbox and check for new ones
  const seenSet = loadCursor(profile, conversationId)
  const allEnvelopes = loadEnvelopes(conversationId)

  const selfKeyIdHex = bytesToHex(identity.keyID).toLowerCase()
  const selfLookupKeys = senderLookupKeys(selfKeyIdHex)
  const historyBucket = ensureHistoryBucket(store, profile.id, conversationId)

  const acceptedMessages = []
  let suppressedSelfEchoes = 0
  let newMessages = false

  for (const envelope of allEnvelopes) {
    const msgIdHex = bytesToHex(envelope.msg_id)
    if (seenSet.has(msgIdHex)) continue

    seenSet.add(msgIdHex)
    newMessages = true

    // Decrypt the message
    let decrypted
    try {
      decrypted = decryptMessage(envelope, convCrypto)
    } catch (err) {
      // Skip messages we can't decrypt
      continue
    }

    const senderKidHex = bytesToHex(new Uint8Array(decrypted.inner.sender_kid)).toLowerCase()
    const bodyText = new TextDecoder().decode(new Uint8Array(decrypted.inner.body))
    const bodyType = decrypted.inner.body_type || 'text'
    const createdAt = new Date(envelope.created_ts * 1000).toISOString()

    const message = {
      id: msgIdHex,
      conversationId,
      direction: 'incoming',
      sender: senderKidHex,
      senderKey: senderKidHex,
      bodyType,
      text: bodyText,
      createdAt,
    }

    // Check if this is a self-echo
    const senderKeys = senderLookupKeys(senderKidHex)
    let isSelfSender = false
    for (const key of senderKeys) {
      if (selfLookupKeys.has(key)) {
        isSelfSender = true
        break
      }
    }

    if (isSelfSender) {
      if (hasRecentOutgoingMatch(historyBucket, message, SELF_ECHO_WINDOW_MS)) {
        suppressedSelfEchoes++
        continue
      }

      const normalizedSelfMessage = {
        ...message,
        direction: 'outgoing',
        sender: profile.name,
        senderKey: '',
      }
      addHistoryMessage(store, profile.id, conversationId, normalizedSelfMessage)
      acceptedMessages.push(normalizedSelfMessage)
      continue
    }

    addHistoryMessage(store, profile.id, conversationId, message)
    acceptedMessages.push(message)
  }

  if (newMessages) {
    saveCursor(profile, conversationId, seenSet)
    saveStore(store)
  }

  res.json({
    messages: acceptedMessages.map((msg) => formatMessageForClient(store, profile.id, msg)),
    suppressedSelfEchoes,
    output: '',
    warning: '',
  })
}))

app.use((error, _req, res, _next) => {
  const status = Number.isInteger(error.statusCode) ? error.statusCode : 500
  res.status(status).json({
    error: error.message || 'unexpected error',
  })
})

app.listen(PORT, () => {
  ensureDataRoot()
  console.log(`qntm AIM API listening on http://localhost:${PORT}`)
  console.log(`data root: ${DATA_ROOT}`)
  console.log('Using @qntm/client library (no Go binary required)')
})
