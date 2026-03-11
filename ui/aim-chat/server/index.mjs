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
  signRequest,
  signApproval,
  hashRequest,
  computePayloadHash,
  sealSecret,
} from '@qntm/client'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const APP_ROOT = path.resolve(__dirname, '..')

const DATA_ROOT = path.join(APP_ROOT, '.qntm-ui')
const PROFILES_ROOT = path.join(DATA_ROOT, 'profiles')
const STORE_PATH = path.join(DATA_ROOT, 'store.json')
const SELF_ECHO_WINDOW_MS = Number(process.env.QNTM_UI_SELF_ECHO_WINDOW_MS || 60000)

const DEFAULT_DROPBOX_URL = 'https://inbox.qntm.corpo.llc'

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
    dropboxUrl: parsed.dropboxUrl || DEFAULT_DROPBOX_URL,
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

// --- Message storage (remote HTTP dropbox) ---

function getDropboxUrl(store) {
  return store.dropboxUrl || DEFAULT_DROPBOX_URL
}

async function sendEnvelopeToDropbox(store, conversationId, envelope) {
  const dropboxUrl = getDropboxUrl(store)
  const data = serializeEnvelope(envelope)
  const envelopeB64 = Buffer.from(data).toString('base64')

  const response = await fetch(`${dropboxUrl}/v1/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      conv_id: conversationId,
      envelope_b64: envelopeB64,
    }),
  })

  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(`dropbox send failed: ${response.status} ${body}`)
  }

  return response.json()
}

async function pollEnvelopesFromDropbox(store, conversationId, fromSeq) {
  const dropboxUrl = getDropboxUrl(store)

  const response = await fetch(`${dropboxUrl}/v1/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      conversations: [{ conv_id: conversationId, from_seq: fromSeq }],
      max_messages: 200,
    }),
  })

  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(`dropbox poll failed: ${response.status} ${body}`)
  }

  const result = await response.json()
  const convResult = result.conversations?.[0]
  if (!convResult) {
    return { upToSeq: fromSeq, envelopes: [] }
  }

  const envelopes = []
  for (const msg of convResult.messages || []) {
    try {
      const raw = Buffer.from(msg.envelope_b64, 'base64')
      const envelope = deserializeEnvelope(new Uint8Array(raw))
      envelopes.push({ seq: msg.seq, envelope })
    } catch {
      // Skip corrupt envelopes
    }
  }

  return { upToSeq: convResult.up_to_seq, envelopes }
}

function loadCursor(profile, conversationId) {
  const cursorsPath = path.join(profile.configDir, 'cursors.json')
  if (!fileExists(cursorsPath)) {
    return 0
  }
  const raw = JSON.parse(fs.readFileSync(cursorsPath, 'utf8'))
  return raw[conversationId] || 0
}

function saveCursor(profile, conversationId, seq) {
  const cursorsPath = path.join(profile.configDir, 'cursors.json')
  let raw = {}
  if (fileExists(cursorsPath)) {
    raw = JSON.parse(fs.readFileSync(cursorsPath, 'utf8'))
  }
  raw[conversationId] = seq
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

  // Send encrypted envelope to remote dropbox
  await sendEnvelopeToDropbox(store, conversationId, envelope)

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

  // Poll remote dropbox for new envelopes
  const fromSeq = loadCursor(profile, conversationId)
  const { upToSeq, envelopes } = await pollEnvelopesFromDropbox(store, conversationId, fromSeq)

  const selfKeyIdHex = bytesToHex(identity.keyID).toLowerCase()
  const selfLookupKeys = senderLookupKeys(selfKeyIdHex)
  const historyBucket = ensureHistoryBucket(store, profile.id, conversationId)

  const acceptedMessages = []
  let suppressedSelfEchoes = 0

  for (const { envelope } of envelopes) {
    const msgIdHex = bytesToHex(envelope.msg_id)

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

  if (upToSeq > fromSeq) {
    saveCursor(profile, conversationId, upToSeq)
    saveStore(store)
  }

  res.json({
    messages: acceptedMessages.map((msg) => formatMessageForClient(store, profile.id, msg)),
    suppressedSelfEchoes,
    output: '',
    warning: '',
  })
}))

// =========== GATE ===========

// Embedded starter recipes (loaded from the Go-compiled JSON)
const starterCatalogPath = path.resolve(__dirname, '..', '..', '..', 'gate', 'recipes', 'starter.json')
let starterCatalog = { profiles: {}, recipes: {} }
try {
  starterCatalog = JSON.parse(fs.readFileSync(starterCatalogPath, 'utf8'))
} catch {
  console.warn('Could not load starter catalog from', starterCatalogPath)
}

app.get('/api/gate/recipes', route(async (_req, res) => {
  const recipes = Object.values(starterCatalog.recipes || {})
  res.json({ recipes })
}))

app.post('/api/profiles/:profileId/gate/run', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''
  const recipeName = typeof req.body.recipeName === 'string' ? req.body.recipeName.trim() : ''
  const orgId = typeof req.body.orgId === 'string' ? req.body.orgId.trim() : ''
  const gateUrl = typeof req.body.gateUrl === 'string' ? req.body.gateUrl.trim() : ''
  const args = (req.body.arguments && typeof req.body.arguments === 'object') ? req.body.arguments : {}

  if (!conversationId || !recipeName || !orgId) {
    const error = new Error('conversationId, recipeName, and orgId are required')
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

  // Look up recipe
  const recipe = starterCatalog.recipes?.[recipeName]
  if (!recipe) {
    const error = new Error(`recipe "${recipeName}" not found`)
    error.statusCode = 404
    throw error
  }

  // Resolve template params in endpoint and target_url
  function resolveTemplate(template, params) {
    return template.replace(/\{(\w+)\}/g, (match, key) => {
      return params[key] !== undefined ? params[key] : match
    })
  }

  const resolvedEndpoint = resolveTemplate(recipe.endpoint, args)
  const resolvedTargetUrl = resolveTemplate(recipe.target_url, args)

  // Build request body from body_schema or body_example if applicable
  let requestBody = null
  if (recipe.body_schema && recipe.body_schema.properties) {
    requestBody = {}
    for (const [key, _schemaProp] of Object.entries(recipe.body_schema.properties)) {
      if (args[key] !== undefined) {
        requestBody[key] = args[key]
      }
    }
    if (Object.keys(requestBody).length === 0) requestBody = null
  } else if (args._body) {
    try { requestBody = JSON.parse(args._body) } catch { requestBody = args._body }
  }

  // Generate request ID and expiry
  const requestId = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + 3600000).toISOString()
  const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600

  // Sign the request
  const kidHex = bytesToHex(identity.keyID)
  const payloadHash = computePayloadHash(requestBody ? JSON.stringify(requestBody) : null)

  const signable = {
    org_id: orgId,
    request_id: requestId,
    verb: recipe.verb,
    target_endpoint: resolvedEndpoint,
    target_service: recipe.service,
    target_url: resolvedTargetUrl,
    expires_at_unix: expiresAtUnix,
    payload_hash: payloadHash,
  }

  const sig = signRequest(identity.privateKey, signable)
  const sigB64 = base64UrlEncode(sig)

  // Build gate.request message body
  const gateMsg = {
    type: 'gate.request',
    recipe_name: recipeName,
    org_id: orgId,
    request_id: requestId,
    verb: recipe.verb,
    target_endpoint: resolvedEndpoint,
    target_service: recipe.service,
    target_url: resolvedTargetUrl,
    expires_at: expiresAt,
    signer_kid: kidHex,
    signature: sigB64,
    arguments: Object.keys(args).length > 0 ? args : undefined,
    request_body: requestBody || undefined,
  }
  const bodyText = JSON.stringify(gateMsg)
  const bodyBytes = new TextEncoder().encode(bodyText)

  // Send as encrypted qntm message
  const envelope = createMessage(identity, convCrypto, 'gate.request', bodyBytes, undefined, defaultTTL())
  await sendEnvelopeToDropbox(store, conversationId, envelope)

  // Also POST to gate server if provided
  if (gateUrl) {
    try {
      await fetch(`${gateUrl}/v1/orgs/${orgId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: bodyText,
      })
    } catch {
      // Gate server may not be running — not fatal
    }
  }

  const message = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'gate.request',
    text: bodyText,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  res.json({
    output: `Gate request ${requestId} submitted`,
    warning: '',
    message: formatMessageForClient(store, profile.id, message),
  })
}))

app.post('/api/profiles/:profileId/gate/approve', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''
  const requestId = typeof req.body.requestId === 'string'
    ? req.body.requestId.trim()
    : ''

  if (!conversationId || !requestId) {
    const error = new Error('conversationId and requestId are required')
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

  // Find the gate.request in history
  const bucket = ensureHistoryBucket(store, profile.id, conversationId)
  let reqMsg = null
  for (const msg of bucket) {
    if (msg.bodyType !== 'gate.request') continue
    try {
      const parsed = JSON.parse(msg.text)
      if (parsed.request_id === requestId) {
        reqMsg = parsed
        break
      }
    } catch {
      continue
    }
  }

  if (!reqMsg) {
    const error = new Error(`gate request ${requestId} not found in conversation history`)
    error.statusCode = 404
    throw error
  }

  // Build gate signable and sign approval
  const kidHex = bytesToHex(identity.keyID)
  const payloadHash = computePayloadHash(reqMsg.payload || null)

  const signable = {
    org_id: reqMsg.org_id,
    request_id: requestId,
    verb: reqMsg.verb,
    target_endpoint: reqMsg.target_endpoint,
    target_service: reqMsg.target_service,
    target_url: reqMsg.target_url,
    expires_at_unix: Math.floor(new Date(reqMsg.expires_at).getTime() / 1000),
    payload_hash: payloadHash,
  }

  const reqHash = hashRequest(signable)
  const approvalSignable = {
    org_id: reqMsg.org_id,
    request_id: requestId,
    request_hash: reqHash,
  }

  const sig = signApproval(identity.privateKey, approvalSignable)
  const sigB64 = base64UrlEncode(sig)

  // Build approval message body
  const approvalBody = {
    type: 'gate.approval',
    org_id: reqMsg.org_id,
    request_id: requestId,
    signer_kid: kidHex,
    signature: sigB64,
  }
  const bodyText = JSON.stringify(approvalBody)
  const bodyBytes = new TextEncoder().encode(bodyText)

  // Create and send encrypted qntm message with body_type=gate.approval
  const envelope = createMessage(identity, convCrypto, 'gate.approval', bodyBytes, undefined, defaultTTL())
  await sendEnvelopeToDropbox(store, conversationId, envelope)

  const message = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'gate.approval',
    text: bodyText,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  res.json({
    output: 'Gate approval sent',
    warning: '',
    message: formatMessageForClient(store, profile.id, message),
  })
}))

app.post('/api/profiles/:profileId/gate/promote', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''
  const orgId = typeof req.body.orgId === 'string' ? req.body.orgId.trim() : ''
  const threshold = typeof req.body.threshold === 'number' ? req.body.threshold : 2
  const gatewayKid = typeof req.body.gatewayKid === 'string' ? req.body.gatewayKid.trim() : ''

  if (!conversationId || !orgId) {
    const error = new Error('conversationId and orgId are required')
    error.statusCode = 400
    throw error
  }

  if (threshold < 1) {
    const error = new Error('threshold must be at least 1')
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

  // Build signers from conversation participants
  const conv = findConversation(profile, conversationId)
  const signers = []
  const selfKidHex = bytesToHex(identity.keyID)
  const seen = new Set()

  // Add self
  signers.push({ kid: selfKidHex, public_key: bytesToHex(identity.publicKey) })
  seen.add(selfKidHex)

  // Add other participants
  if (conv && Array.isArray(conv.participants)) {
    for (const pHex of conv.participants) {
      const pBytes = hexToBytes(pHex)
      const pKid = bytesToHex(keyIDFromPublicKey(pBytes))
      if (!seen.has(pKid)) {
        signers.push({ kid: pKid, public_key: pHex })
        seen.add(pKid)
      }
    }
  }

  const n = signers.length

  // Build promote payload (matches Go PromotePayload)
  const promotePayload = {
    org_id: orgId,
    signers: signers,
    rules: [
      {
        service: '*',
        endpoint: '*',
        verb: '*',
        m: threshold,
        n: n,
      },
    ],
  }

  const bodyText = JSON.stringify(promotePayload)
  const bodyBytes = new TextEncoder().encode(bodyText)

  // Send as encrypted qntm message with body_type=gate.promote
  const envelope = createMessage(identity, convCrypto, 'gate.promote', bodyBytes, undefined, defaultTTL())
  await sendEnvelopeToDropbox(store, conversationId, envelope)

  const message = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'gate.promote',
    text: bodyText,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  res.json({
    output: `Gate promote sent: org=${orgId} threshold=${threshold}-of-${n}`,
    warning: '',
    message: formatMessageForClient(store, profile.id, message),
  })
}))

app.post('/api/profiles/:profileId/gate/secret', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const conversationId = typeof req.body.conversationId === 'string'
    ? req.body.conversationId.trim().toLowerCase()
    : ''
  const service = typeof req.body.service === 'string' ? req.body.service.trim() : ''
  const headerName = typeof req.body.headerName === 'string' ? req.body.headerName.trim() : 'Authorization'
  const headerTemplate = typeof req.body.headerTemplate === 'string' ? req.body.headerTemplate.trim() : 'Bearer {value}'
  const value = typeof req.body.value === 'string' ? req.body.value : ''
  const gatewayPublicKey = typeof req.body.gatewayPublicKey === 'string' ? req.body.gatewayPublicKey.trim() : ''

  if (!conversationId || !service || !value) {
    const error = new Error('conversationId, service, and value are required')
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

  // Find the gateway public key
  let gwPubKeyBytes
  const selfKidHex = bytesToHex(identity.keyID).toLowerCase()

  if (gatewayPublicKey) {
    gwPubKeyBytes = hexToBytes(gatewayPublicKey)
  } else {
    // Use first non-self participant
    const conv = findConversation(profile, conversationId)
    if (conv && Array.isArray(conv.participants)) {
      for (const pHex of conv.participants) {
        const pBytes = hexToBytes(pHex)
        const pKid = bytesToHex(keyIDFromPublicKey(pBytes)).toLowerCase()
        if (pKid !== selfKidHex) {
          gwPubKeyBytes = pBytes
          break
        }
      }
    }
    if (!gwPubKeyBytes) {
      const error = new Error('no gateway participant found (need a non-self participant, or provide gatewayPublicKey)')
      error.statusCode = 400
      throw error
    }
  }

  // Encrypt the secret to the gateway's public key
  const secretId = crypto.randomUUID()
  const plaintext = new TextEncoder().encode(value)
  const sealed = sealSecret(identity.privateKey, gwPubKeyBytes, plaintext)
  const encryptedBlob = Buffer.from(sealed).toString('base64url')

  // Build gate.secret payload
  const secretPayload = {
    secret_id: secretId,
    service,
    header_name: headerName,
    header_template: headerTemplate,
    encrypted_blob: encryptedBlob,
    sender_kid: bytesToHex(identity.keyID),
  }

  const bodyText = JSON.stringify(secretPayload)
  const bodyBytes = new TextEncoder().encode(bodyText)

  // Send as encrypted qntm message with body_type=gate.secret
  const envelope = createMessage(identity, convCrypto, 'gate.secret', bodyBytes, undefined, defaultTTL())
  await sendEnvelopeToDropbox(store, conversationId, envelope)

  const message = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'gate.secret',
    text: bodyText,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  const gwKid = bytesToHex(keyIDFromPublicKey(gwPubKeyBytes))

  res.json({
    output: `Secret provisioned for service ${service} (encrypted to gateway ${gwKid.slice(0, 8)}...)`,
    warning: '',
    message: formatMessageForClient(store, profile.id, message),
  })
}))

// =========== SETTINGS ===========

app.get('/api/settings', route(async (_req, res) => {
  const store = loadStore()
  res.json({
    dropboxUrl: store.dropboxUrl || DEFAULT_DROPBOX_URL,
    defaultDropboxUrl: DEFAULT_DROPBOX_URL,
  })
}))

app.post('/api/settings', route(async (req, res) => {
  const store = loadStore()

  if (typeof req.body.dropboxUrl === 'string') {
    const url = req.body.dropboxUrl.trim().replace(/\/+$/, '')
    store.dropboxUrl = url || DEFAULT_DROPBOX_URL
  }

  saveStore(store)
  res.json({
    dropboxUrl: store.dropboxUrl || DEFAULT_DROPBOX_URL,
    defaultDropboxUrl: DEFAULT_DROPBOX_URL,
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
