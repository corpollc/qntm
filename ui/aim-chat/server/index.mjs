import cors from 'cors'
import express from 'express'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { fileURLToPath } from 'url'
import crypto from 'crypto'
import { createQntmInvocationResolver } from './qntm-invocation.mjs'

const execFileAsync = promisify(execFile)

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const APP_ROOT = path.resolve(__dirname, '..')
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..')

const DATA_ROOT = path.join(APP_ROOT, '.qntm-ui')
const PROFILES_ROOT = path.join(DATA_ROOT, 'profiles')
const SHARED_DROPBOX_DIR = path.join(DATA_ROOT, 'dropbox')
const STORE_PATH = path.join(DATA_ROOT, 'store.json')
const DEFAULT_STORAGE = parseStorage(process.env.QNTM_UI_DEFAULT_STORAGE || '')
const DEFAULT_DROPBOX_URL = (process.env.QNTM_UI_DEFAULT_DROPBOX_URL || 'https://inbox.qntm.corpo.llc').trim()
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

function expandHome(inputPath) {
  if (!inputPath) {
    return inputPath
  }
  if (inputPath.startsWith('~/')) {
    return path.join(os.homedir(), inputPath.slice(2))
  }
  return inputPath
}

function parseStorage(inputStorage) {
  if (!inputStorage) {
    return ''
  }
  if (inputStorage.startsWith('local:')) {
    const dir = expandHome(inputStorage.slice('local:'.length))
    return `local:${path.resolve(dir)}`
  }
  return inputStorage
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

  if (profile.storage && profile.storage.startsWith('local:')) {
    const localDir = profile.storage.slice('local:'.length)
    fs.mkdirSync(localDir, { recursive: true })
  }
}

const resolveQntmInvocation = createQntmInvocationResolver({
  repoRoot: REPO_ROOT,
  dataRoot: DATA_ROOT,
  env: process.env,
  fileExists,
})

function parseJSONOutput(output) {
  if (!output) {
    return null
  }
  try {
    const parsed = JSON.parse(output)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

function qntmString(data, key) {
  if (!data || typeof data !== 'object') {
    return ''
  }

  const value = data[key]
  return typeof value === 'string' ? value : ''
}

async function runQntm(profile, args) {
  ensureProfileFilesystem(profile)

  const invocation = await resolveQntmInvocation(profile)
  const finalArgs = [...invocation.prefixArgs, '--config-dir', profile.configDir]

  if (profile.storage) {
    finalArgs.push('--storage', profile.storage)
  }

  if (profile.dropboxUrl) {
    finalArgs.push('--dropbox-url', profile.dropboxUrl)
  }

  finalArgs.push(...args)

  try {
    const { stdout, stderr } = await execFileAsync(invocation.command, finalArgs, {
      cwd: REPO_ROOT,
      maxBuffer: 8 * 1024 * 1024,
    })

    const stdoutTrimmed = stdout.trim()
    const stderrTrimmed = stderr.trim()
    const payload = parseJSONOutput(stdoutTrimmed)
    if (!payload) {
      const wrapped = new Error('qntm command returned invalid JSON')
      wrapped.statusCode = 502
      throw wrapped
    }
    if (payload.ok !== true) {
      const wrapped = new Error(qntmString(payload, 'error') || 'qntm command failed')
      wrapped.statusCode = 400
      throw wrapped
    }

    return {
      stdout: stdoutTrimmed,
      stderr: stderrTrimmed,
      payload,
      data: payload.data && typeof payload.data === 'object' ? payload.data : {},
    }
  } catch (error) {
    if (Number.isInteger(error?.statusCode) &&
      typeof error?.stdout !== 'string' &&
      typeof error?.stderr !== 'string') {
      throw error
    }

    const stdout = typeof error.stdout === 'string' ? error.stdout.trim() : ''
    const stderr = typeof error.stderr === 'string' ? error.stderr.trim() : ''
    const parsedError = parseJSONOutput(stdout)
    const parsedDetail = qntmString(parsedError, 'error')
    const detail = parsedDetail || stderr || stdout || error.message

    const wrapped = new Error(`qntm command failed: ${detail}`)
    wrapped.statusCode = 400
    throw wrapped
  }
}

function bytesToHex(value) {
  if (Array.isArray(value)) {
    return Buffer.from(value).toString('hex')
  }

  if (typeof value === 'string') {
    if (/^[0-9a-f]{32}$/i.test(value)) {
      return value.toLowerCase()
    }

    try {
      const decoded = Buffer.from(value, 'base64url')
      if (decoded.length === 16) {
        return decoded.toString('hex')
      }
    } catch {
      // Ignore decode errors and fall through.
    }

    try {
      const decoded = Buffer.from(value, 'base64')
      if (decoded.length === 16) {
        return decoded.toString('hex')
      }
    } catch {
      // Ignore decode errors and fall through.
    }

    return value
  }

  return ''
}

function loadConversations(profile) {
  const conversationsPath = path.join(profile.configDir, 'conversations.json')
  if (!fileExists(conversationsPath)) {
    return []
  }

  const raw = fs.readFileSync(conversationsPath, 'utf8')
  const parsed = JSON.parse(raw)

  if (!Array.isArray(parsed)) {
    return []
  }

  return parsed
    .map((entry) => {
      const id = bytesToHex(entry.id)
      if (!id) {
        return null
      }

      const participantsRaw = Array.isArray(entry.participants) ? entry.participants : []
      const participants = participantsRaw
        .map((participant) => bytesToHex(participant))
        .filter((participant) => participant)

      const fallbackName = `${entry.type || 'chat'}-${id.slice(0, 8)}`

      return {
        id,
        name: entry.name || fallbackName,
        type: entry.type || 'direct',
        participants,
        createdAt: entry.created_at || null,
      }
    })
    .filter((entry) => entry !== null)
}

function extractSenderKey(sender) {
  if (typeof sender !== 'string') {
    return ''
  }

  const trimmed = sender.trim()
  if (!trimmed) {
    return ''
  }

  const wrappedMatch = trimmed.match(/\(([^()]+)\)\s*$/)
  if (wrappedMatch) {
    return wrappedMatch[1].trim()
  }

  return trimmed
}

function normalizeSenderKey(sender) {
  return extractSenderKey(sender).toLowerCase()
}

function senderLookupKeys(...labels) {
  const result = new Set()

  for (const value of labels) {
    if (typeof value !== 'string') {
      continue
    }

    const raw = value.trim()
    if (!raw) {
      continue
    }

    const normalizedRaw = raw.toLowerCase()
    if (normalizedRaw) {
      result.add(normalizedRaw)
    }

    const extracted = normalizeSenderKey(raw)
    if (extracted) {
      result.add(extracted)
    }
  }

  return result
}

function ensureContactsBucket(store, profileId) {
  if (!store.contacts || typeof store.contacts !== 'object') {
    store.contacts = {}
  }

  if (!store.contacts[profileId] || typeof store.contacts[profileId] !== 'object') {
    store.contacts[profileId] = {}
  }

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
  if (!normalizedKey) {
    return ''
  }

  const bucket = ensureContactsBucket(store, profileId)
  const alias = bucket[normalizedKey]
  return typeof alias === 'string' ? alias.trim() : ''
}

function formatMessageForClient(store, profileId, message) {
  const senderKey = message.senderKey || extractSenderKey(message.sender)
  const alias = message.direction === 'incoming'
    ? resolveContactAlias(store, profileId, senderKey)
    : ''

  return {
    ...message,
    senderKey,
    sender: alias || message.sender,
  }
}

function ensureHistoryBucket(store, profileId, conversationId) {
  if (!store.history[profileId]) {
    store.history[profileId] = {}
  }

  if (!store.history[profileId][conversationId]) {
    store.history[profileId][conversationId] = []
  }

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

    if (!sameCore) {
      return false
    }

    const existingTs = Date.parse(existing.createdAt)
    const incomingTs = Date.parse(message.createdAt)
    if (Number.isNaN(existingTs) || Number.isNaN(incomingTs)) {
      return false
    }

    return Math.abs(existingTs - incomingTs) <= dedupeWindowMs
  })

  if (hasRecentDuplicate) {
    return
  }

  bucket.push(message)

  if (bucket.length > 1000) {
    bucket.splice(0, bucket.length - 1000)
  }
}

function hasRecentOutgoingMatch(bucket, message, windowMs) {
  const incomingTs = Date.parse(message.createdAt)
  if (Number.isNaN(incomingTs)) {
    return false
  }

  return bucket.some((existing) => {
    if (existing.direction !== 'outgoing') {
      return false
    }

    if (existing.bodyType !== message.bodyType || existing.text !== message.text) {
      return false
    }

    const existingTs = Date.parse(existing.createdAt)
    if (Number.isNaN(existingTs)) {
      return false
    }

    return Math.abs(existingTs - incomingTs) <= windowMs
  })
}

function decodeUnsafeBody(messageData) {
  const unsafeBody = qntmString(messageData, 'unsafe_body')
  if (unsafeBody) {
    return unsafeBody
  }

  const unsafeBodyB64 = qntmString(messageData, 'unsafe_body_b64')
  if (!unsafeBodyB64) {
    return ''
  }

  try {
    return Buffer.from(unsafeBodyB64, 'base64').toString('utf8')
  } catch {
    return ''
  }
}

function parseReceiveDataMessages(rawMessages, fallbackConversationId) {
  if (!Array.isArray(rawMessages)) {
    return []
  }

  return rawMessages
    .filter((entry) => entry && typeof entry === 'object')
    .map((entry) => {
      const conversationId = qntmString(entry, 'conversation_id') || fallbackConversationId
      const sender = qntmString(entry, 'sender')
      const senderKID = qntmString(entry, 'sender_kid').toLowerCase()
      const bodyType = qntmString(entry, 'body_type') || 'text'
      const rawText = decodeUnsafeBody(entry)
      const text = rawText || (bodyType === 'text' ? '' : `[${bodyType}]`)
      const createdTS = Number(entry.created_ts)

      return {
        id: qntmString(entry, 'message_id') || crypto.randomUUID(),
        conversationId,
        direction: 'incoming',
        sender: sender || 'unknown',
        senderKey: senderKID || extractSenderKey(sender),
        bodyType,
        text,
        createdAt: Number.isFinite(createdTS) ? new Date(createdTS * 1000).toISOString() : new Date().toISOString(),
      }
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

  const configDirInput = typeof req.body.configDir === 'string' ? req.body.configDir : ''
  const storageInput = typeof req.body.storage === 'string' ? req.body.storage : ''
  const dropboxUrlInput = typeof req.body.dropboxUrl === 'string' ? req.body.dropboxUrl.trim() : ''
  const qntmBin = typeof req.body.qntmBin === 'string' ? req.body.qntmBin.trim() : ''

  const configDir = path.resolve(expandHome(configDirInput || path.join(PROFILES_ROOT, id, 'config')))
  const storage = parseStorage(storageInput || DEFAULT_STORAGE)
  const dropboxUrl = dropboxUrlInput || (!storage ? DEFAULT_DROPBOX_URL : '')

  const profile = {
    id,
    name,
    configDir,
    storage,
    dropboxUrl,
    qntmBin,
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
  const identityPath = path.join(profile.configDir, 'identity.json')

  if (!fileExists(identityPath)) {
    res.json({ exists: false, keyId: '', publicKey: '' })
    return
  }

  const output = await runQntm(profile, ['identity', 'show'])

  res.json({
    exists: true,
    keyId: qntmString(output.data, 'key_id'),
    publicKey: qntmString(output.data, 'public_key'),
  })
}))

app.post('/api/profiles/:profileId/identity/generate', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const generateOutput = await runQntm(profile, ['identity', 'generate'])
  const showOutput = await runQntm(profile, ['identity', 'show'])
  const showKeyID = qntmString(showOutput.data, 'key_id')
  const showPublicKey = qntmString(showOutput.data, 'public_key')

  if (showKeyID) {
    for (const p of store.profiles) {
      const bucket = ensureContactsBucket(store, p.id)
      if (!bucket[showKeyID.toLowerCase()]) {
        bucket[showKeyID.toLowerCase()] = profile.name
      }
    }
    saveStore(store)
  }

  res.json({
    output: generateOutput.stdout,
    identity: {
      exists: true,
      keyId: showKeyID,
      publicKey: showPublicKey,
    },
  })
}))

app.get('/api/profiles/:profileId/conversations', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)
  const conversations = loadConversations(profile)

  res.json({ conversations })
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

  const rawName = typeof req.body.name === 'string' ? req.body.name.trim() : ''
  const isGroup = Boolean(req.body.group)
  const selfJoin = req.body.selfJoin !== false

  const createArgs = ['convo', 'create']
  if (isGroup) {
    createArgs.push('--group')
  }
  if (rawName) {
    createArgs.push('--name', rawName)
  }
  if (!selfJoin) {
    createArgs.push('--self-join=false')
  }

  const createOutput = await runQntm(profile, createArgs)
  const inviteToken = qntmString(createOutput.data, 'invite_token')
  const conversationID = qntmString(createOutput.data, 'conversation_id')

  if (!inviteToken) {
    const error = new Error('failed to parse invite token from qntm output')
    error.statusCode = 500
    throw error
  }

  res.json({
    inviteToken,
    conversationId: conversationID.toLowerCase(),
    output: createOutput.stdout,
    conversations: loadConversations(profile),
  })
}))

app.post('/api/profiles/:profileId/invite/accept', route(async (req, res) => {
  const store = loadStore()
  const profile = getProfileOrThrow(store, req.params.profileId)

  const token = typeof req.body.token === 'string' ? req.body.token.trim() : ''
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : ''

  if (!token) {
    const error = new Error('invite token is required')
    error.statusCode = 400
    throw error
  }

  const args = ['convo', 'join', token]
  if (name) {
    args.push('--name', name)
  }

  const output = await runQntm(profile, args)
  const conversationID = qntmString(output.data, 'conversation_id')

  res.json({
    conversationId: conversationID.toLowerCase(),
    output: output.stdout,
    conversations: loadConversations(profile),
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

  const output = await runQntm(profile, ['send', conversationId, text])

  const message = {
    id: crypto.randomUUID(),
    conversationId,
    direction: 'outgoing',
    sender: profile.name,
    senderKey: '',
    bodyType: 'text',
    text,
    createdAt: new Date().toISOString(),
  }

  addHistoryMessage(store, profile.id, conversationId, message)
  saveStore(store)

  res.json({
    output: output.stdout,
    warning: output.stderr,
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

  const historyBucket = ensureHistoryBucket(store, profile.id, conversationId)
  const identityOutput = await runQntm(profile, ['identity', 'show'])
  const selfLookupKeys = senderLookupKeys(qntmString(identityOutput.data, 'key_id'))

  const output = await runQntm(profile, ['recv', conversationId])
  const incomingMessages = parseReceiveDataMessages(output.data.messages, conversationId)
  const acceptedMessages = []
  let suppressedSelfEchoes = 0

  if (incomingMessages.length > 0) {
    for (const message of incomingMessages) {
      const senderKeys = senderLookupKeys(message.sender, message.senderKey)
      let isSelfSender = false
      for (const key of senderKeys) {
        if (selfLookupKeys.has(key)) {
          isSelfSender = true
          break
        }
      }

      if (isSelfSender) {
        if (hasRecentOutgoingMatch(historyBucket, message, SELF_ECHO_WINDOW_MS)) {
          suppressedSelfEchoes += 1
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
    saveStore(store)
  }

  res.json({
    messages: acceptedMessages.map((message) => formatMessageForClient(store, profile.id, message)),
    suppressedSelfEchoes,
    output: output.stdout,
    warning: output.stderr,
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
})
