/**
 * Browser-side crypto operations using @qntm/client directly.
 * Replaces all Express server crypto — keys never leave the browser.
 */

import {
  generateIdentity as clientGenerateIdentity,
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
  base64UrlEncode,
  signRequest,
  signApproval,
  hashRequest,
  computePayloadHash,
  sealSecret,
  DropboxClient,
} from '@qntm/client'

import * as store from './store'
import type { ChatMessage, Conversation, IdentityInfo } from './types'

// ---- Hex utilities ----

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function base64ToUint8(s: string): Uint8Array {
  const binary = atob(s)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

// ---- Identity ----

interface IdentityKeys {
  privateKey: Uint8Array
  publicKey: Uint8Array
  keyID: Uint8Array
}

function loadIdentityKeys(profileId: string): IdentityKeys | null {
  const stored = store.getIdentity(profileId)
  if (!stored) return null
  return {
    privateKey: hexToBytes(stored.privateKey),
    publicKey: hexToBytes(stored.publicKey),
    keyID: hexToBytes(stored.keyId),
  }
}

export function generateIdentityForProfile(profileId: string): IdentityInfo {
  const identity = clientGenerateIdentity()
  const keyIdHex = bytesToHex(identity.keyID)
  store.saveIdentity(profileId, {
    privateKey: bytesToHex(identity.privateKey),
    publicKey: bytesToHex(identity.publicKey),
    keyId: keyIdHex,
  })
  return { exists: true, keyId: keyIdHex, publicKey: bytesToHex(identity.publicKey) }
}

export function getIdentityInfo(profileId: string): IdentityInfo {
  const stored = store.getIdentity(profileId)
  if (!stored) return { exists: false, keyId: '', publicKey: '' }
  return { exists: true, keyId: stored.keyId, publicKey: stored.publicKey }
}

// ---- Conversation crypto state ----

function getConvCrypto(profileId: string, conversationId: string) {
  const conv = store.findConversation(profileId, conversationId)
  if (!conv) return null
  return {
    id: hexToBytes(conv.id),
    type: conv.type as 'direct' | 'group' | 'announce',
    keys: {
      root: hexToBytes(conv.keys.root),
      aeadKey: hexToBytes(conv.keys.aeadKey),
      nonceKey: hexToBytes(conv.keys.nonceKey),
    },
    participants: conv.participants.map(p => hexToBytes(p)),
    createdAt: new Date(conv.createdAt || Date.now()),
    currentEpoch: conv.currentEpoch || 0,
  }
}

// ---- Dropbox transport ----

function getDropbox(): DropboxClient {
  return new DropboxClient(store.getDropboxUrl())
}

async function sendEnvelope(conversationId: string, envelope: ReturnType<typeof createMessage>): Promise<void> {
  const dropbox = getDropbox()
  const data = serializeEnvelope(envelope)
  const convIdBytes = hexToBytes(conversationId)
  await dropbox.postMessage(convIdBytes, data)
}

// ---- Invite ----

function formatConversation(conv: store.StoredConversation): Conversation {
  return {
    id: conv.id,
    name: conv.name || `${conv.type || 'chat'}-${conv.id.slice(0, 8)}`,
    type: conv.type || 'direct',
    participants: conv.participants || [],
    createdAt: conv.createdAt || null,
  }
}

export function createInviteForProfile(
  profileId: string, name: string
): { inviteToken: string; conversationId: string; conversations: Conversation[] } {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found; generate one first')

  const invite = createInvite(identity, 'direct')
  const token = inviteToToken(invite)
  const convIdHex = bytesToHex(invite.conv_id)
  const keys = deriveConversationKeys(invite)
  const conv = createConversation(invite, keys)
  addParticipant(conv, identity.publicKey)

  const convRecord: store.StoredConversation = {
    id: convIdHex,
    name: name.trim() || `Chat ${convIdHex.slice(0, 8)}`,
    type: 'direct',
    keys: {
      root: bytesToHex(keys.root),
      aeadKey: bytesToHex(keys.aeadKey),
      nonceKey: bytesToHex(keys.nonceKey),
    },
    participants: conv.participants.map((p: Uint8Array) => bytesToHex(p)),
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
  }

  store.addConversation(profileId, convRecord)
  return {
    inviteToken: token,
    conversationId: convIdHex.toLowerCase(),
    conversations: store.listConversations(profileId).map(formatConversation),
  }
}

export function acceptInviteForProfile(
  profileId: string, token: string, name: string
): { conversationId: string; conversations: Conversation[] } {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found; generate one first')

  if (!token.trim()) throw new Error('Invite token is required')

  const invite = inviteFromURL(token.trim())
  const keys = deriveConversationKeys(invite)
  const conv = createConversation(invite, keys)
  addParticipant(conv, identity.publicKey)

  const convIdHex = bytesToHex(invite.conv_id)

  // Check if already exists
  const existing = store.findConversation(profileId, convIdHex)
  if (existing) {
    return {
      conversationId: convIdHex.toLowerCase(),
      conversations: store.listConversations(profileId).map(formatConversation),
    }
  }

  const convRecord: store.StoredConversation = {
    id: convIdHex,
    name: name.trim() || `Chat ${convIdHex.slice(0, 8)}`,
    type: (invite as { type?: string }).type || 'direct',
    keys: {
      root: bytesToHex(keys.root),
      aeadKey: bytesToHex(keys.aeadKey),
      nonceKey: bytesToHex(keys.nonceKey),
    },
    participants: conv.participants.map((p: Uint8Array) => bytesToHex(p)),
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
  }

  store.addConversation(profileId, convRecord)
  return {
    conversationId: convIdHex.toLowerCase(),
    conversations: store.listConversations(profileId).map(formatConversation),
  }
}

// ---- Messages ----

const SELF_ECHO_WINDOW_MS = 60000

function resolveMessageSender(profileId: string, message: store.StoredMessage): ChatMessage {
  const senderKey = message.senderKey || message.sender
  const alias = message.direction === 'incoming'
    ? store.resolveContactAlias(profileId, senderKey)
    : ''
  return { ...message, senderKey, sender: alias || message.sender }
}

export async function sendMessageToConversation(
  profileId: string, profileName: string, conversationId: string, text: string, bodyType = 'text'
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  const bodyBytes = new TextEncoder().encode(text)
  const envelope = createMessage(identity, convCrypto, bodyType, bodyBytes, undefined, defaultTTL())

  await sendEnvelope(conversationId, envelope)

  const message: store.StoredMessage = {
    id: bytesToHex(envelope.msg_id),
    conversationId,
    direction: 'outgoing',
    sender: profileName,
    senderKey: '',
    bodyType,
    text,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  }

  store.addHistoryMessage(profileId, conversationId, message)
  return resolveMessageSender(profileId, message)
}

export async function receiveMessages(
  profileId: string, profileName: string, conversationId: string
): Promise<{ messages: ChatMessage[] }> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) return { messages: [] }

  const dropbox = getDropbox()
  const fromSeq = store.loadCursor(profileId, conversationId)
  const convIdBytes = hexToBytes(conversationId)
  const result = await dropbox.receiveMessages(convIdBytes, fromSeq, 200)

  const selfKeyIdHex = bytesToHex(identity.keyID).toLowerCase()
  const acceptedMessages: ChatMessage[] = []

  for (const rawEnvelope of result.messages) {
    let envelope
    try {
      envelope = deserializeEnvelope(rawEnvelope)
    } catch {
      continue
    }

    let decrypted
    try {
      decrypted = decryptMessage(envelope, convCrypto)
    } catch {
      continue
    }

    const senderKidHex = bytesToHex(new Uint8Array(decrypted.inner.sender_kid)).toLowerCase()
    const bodyText = new TextDecoder().decode(new Uint8Array(decrypted.inner.body))
    const bodyType = decrypted.inner.body_type || 'text'
    const createdAt = new Date(envelope.created_ts * 1000).toISOString()

    const message: store.StoredMessage = {
      id: bytesToHex(envelope.msg_id),
      conversationId,
      direction: 'incoming',
      sender: senderKidHex,
      senderKey: senderKidHex,
      bodyType,
      text: bodyText,
      createdAt,
    }

    const isSelf = senderKidHex === selfKeyIdHex
    if (isSelf) {
      if (store.hasRecentOutgoingMatch(profileId, conversationId, message, SELF_ECHO_WINDOW_MS)) {
        continue // suppress self-echo
      }
      const selfMessage: store.StoredMessage = {
        ...message,
        direction: 'outgoing',
        sender: profileName,
        senderKey: '',
      }
      store.addHistoryMessage(profileId, conversationId, selfMessage)
      acceptedMessages.push(resolveMessageSender(profileId, selfMessage))
    } else {
      store.addHistoryMessage(profileId, conversationId, message)
      acceptedMessages.push(resolveMessageSender(profileId, message))
    }
  }

  if (result.sequence > fromSeq) {
    store.saveCursor(profileId, conversationId, result.sequence)
  }

  return { messages: acceptedMessages }
}

// ---- Gate operations ----

export async function gateRunRequest(
  profileId: string, profileName: string, conversationId: string,
  recipe: { verb: string; service: string; endpoint: string; target_url: string; body_schema?: Record<string, unknown> },
  recipeName: string, orgId: string, _gateUrl: string, args: Record<string, string>
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  function resolveTemplate(template: string, params: Record<string, string>): string {
    return template.replace(/\{(\w+)\}/g, (match, key) => params[key] !== undefined ? params[key] : match)
  }

  const resolvedEndpoint = resolveTemplate(recipe.endpoint, args)
  const resolvedTargetUrl = resolveTemplate(recipe.target_url, args)

  let requestBody: unknown = null
  if (recipe.body_schema && (recipe.body_schema as { properties?: unknown }).properties) {
    const body: Record<string, string> = {}
    for (const key of Object.keys((recipe.body_schema as { properties: Record<string, unknown> }).properties)) {
      if (args[key] !== undefined) body[key] = args[key]
    }
    if (Object.keys(body).length > 0) requestBody = body
  } else if (args._body) {
    try { requestBody = JSON.parse(args._body) } catch { requestBody = args._body }
  }

  const requestId = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + 3600000).toISOString()
  const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600
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
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.request')
}

export async function gateApproveRequest(
  profileId: string, profileName: string, conversationId: string, requestId: string
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  // Find the request in history
  const history = store.getHistory(profileId, conversationId)
  let reqMsg: Record<string, unknown> | null = null
  for (const msg of history) {
    if (msg.bodyType !== 'gate.request') continue
    try {
      const parsed = JSON.parse(msg.text)
      if (parsed.request_id === requestId) { reqMsg = parsed; break }
    } catch { continue }
  }

  if (!reqMsg) throw new Error(`Gate request ${requestId} not found in conversation history`)

  const kidHex = bytesToHex(identity.keyID)
  const payloadHash = computePayloadHash((reqMsg.payload as string) || null)

  const signable = {
    org_id: reqMsg.org_id as string,
    request_id: requestId,
    verb: reqMsg.verb as string,
    target_endpoint: reqMsg.target_endpoint as string,
    target_service: reqMsg.target_service as string,
    target_url: reqMsg.target_url as string,
    expires_at_unix: Math.floor(new Date(reqMsg.expires_at as string).getTime() / 1000),
    payload_hash: payloadHash,
  }

  const reqHash = hashRequest(signable)
  const approvalSignable = {
    org_id: reqMsg.org_id as string,
    request_id: requestId,
    request_hash: reqHash,
  }

  const sig = signApproval(identity.privateKey, approvalSignable)
  const sigB64 = base64UrlEncode(sig)

  const approvalBody = {
    type: 'gate.approval',
    org_id: reqMsg.org_id,
    request_id: requestId,
    signer_kid: kidHex,
    signature: sigB64,
  }

  const bodyText = JSON.stringify(approvalBody)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.approval')
}

export async function gatePromoteRequest(
  profileId: string, profileName: string, conversationId: string,
  orgId: string, threshold: number
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  const conv = store.findConversation(profileId, conversationId)
  const signers: Array<{ kid: string; public_key: string }> = []
  const seen = new Set<string>()

  // Add self
  const selfKidHex = bytesToHex(identity.keyID)
  signers.push({ kid: selfKidHex, public_key: bytesToHex(identity.publicKey) })
  seen.add(selfKidHex)

  // Add other participants
  if (conv?.participants) {
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
  const promotePayload = {
    org_id: orgId,
    signers,
    rules: [{ service: '*', endpoint: '*', verb: '*', m: threshold, n }],
  }

  const bodyText = JSON.stringify(promotePayload)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.promote')
}

export async function gateSecretRequest(
  profileId: string, profileName: string, conversationId: string,
  service: string, value: string, headerName: string, headerTemplate: string,
  gatewayPublicKey?: string
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  let gwPubKeyBytes: Uint8Array | undefined
  const selfKidHex = bytesToHex(identity.keyID).toLowerCase()

  if (gatewayPublicKey) {
    gwPubKeyBytes = hexToBytes(gatewayPublicKey)
  } else {
    const conv = store.findConversation(profileId, conversationId)
    if (conv?.participants) {
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
      throw new Error('No gateway participant found (need a non-self participant, or provide gatewayPublicKey)')
    }
  }

  const secretId = crypto.randomUUID()
  const plaintext = new TextEncoder().encode(value)
  const sealed = sealSecret(identity.privateKey, gwPubKeyBytes, plaintext)
  const encryptedBlob = uint8ToBase64(sealed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

  const secretPayload = {
    secret_id: secretId,
    service,
    header_name: headerName || 'Authorization',
    header_template: headerTemplate || 'Bearer {value}',
    encrypted_blob: encryptedBlob,
    sender_kid: bytesToHex(identity.keyID),
  }

  const bodyText = JSON.stringify(secretPayload)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.secret')
}

// ---- Backup / Restore ----

export function exportBackup(): string {
  const raw = localStorage.getItem('aim-store')
  return raw || '{}'
}

export function importBackup(json: string): void {
  // Validate it's parseable
  JSON.parse(json) // throws if invalid
  localStorage.setItem('aim-store', json)
}
