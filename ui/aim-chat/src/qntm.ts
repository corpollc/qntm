/**
 * Browser-side crypto operations using @corpollc/qntm directly.
 * Replaces all Express server crypto — keys never leave the browser.
 */

import {
  generateIdentity as clientGenerateIdentity,
  keyIDFromPublicKey,
  publicKeyToString,
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
  base64UrlDecode,
  base64UrlEncode,
  signRequest,
  signApproval,
  hashRequest,
  createProposalBody,
  signGovApproval,
  hashProposal,
  computePayloadHash,
  resolveRecipe,
  sealSecret,
  DropboxClient,
  buildSignedReceipt,
  parseGroupGenesisBody,
  parseGroupAddBody,
  parseGroupRemoveBody,
  parseGroupRekeyBody,
  QSP1Suite,
} from '@corpollc/qntm'

import * as store from './store'
import type { ChatMessage, Conversation, GateRecipe, IdentityInfo } from './types'

const _suite = new QSP1Suite()
const GROUP_BODY_TYPES = new Set(['group_genesis', 'group_add', 'group_remove', 'group_rekey'])
// Conversation creators only know themselves until another participant is learned locally.
const MIN_RECEIPT_ACKS = 2

// ---- Group event state application ----

/**
 * Apply group membership/epoch mutations from a received group event.
 * Mutates the stored conversation in localStorage.
 */
function applyGroupEvent(
  profileId: string,
  conversationId: string,
  bodyType: string,
  bodyBytes: Uint8Array,
  localIdentity: IdentityKeys | null,
): void {
  if (!GROUP_BODY_TYPES.has(bodyType)) return

  try {
    switch (bodyType) {
      case 'group_genesis': {
        const parsed = parseGroupGenesisBody(bodyBytes)
        const newKids: string[] = []
        const newPks: string[] = []
        for (const m of parsed.founding_members ?? []) {
          newKids.push(bytesToHex(new Uint8Array(m.key_id)).toLowerCase())
          newPks.push(bytesToHex(new Uint8Array(m.public_key)))
        }
        store.updateConversation(profileId, conversationId, (conv) => ({
          ...conv,
          participants: dedupeHex([...conv.participants, ...newKids]),
          participantPublicKeys: dedupeHex([...(conv.participantPublicKeys || []), ...newPks]),
        }))
        break
      }
      case 'group_add': {
        const parsed = parseGroupAddBody(bodyBytes)
        const newKids: string[] = []
        const newPks: string[] = []
        for (const m of parsed.new_members ?? []) {
          newKids.push(bytesToHex(new Uint8Array(m.key_id)).toLowerCase())
          newPks.push(bytesToHex(new Uint8Array(m.public_key)))
        }
        store.updateConversation(profileId, conversationId, (conv) => ({
          ...conv,
          participants: dedupeHex([...conv.participants, ...newKids]),
          participantPublicKeys: dedupeHex([...(conv.participantPublicKeys || []), ...newPks]),
        }))
        break
      }
      case 'group_remove': {
        const parsed = parseGroupRemoveBody(bodyBytes)
        const removedKids = new Set(
          (parsed.removed_members ?? []).map((kid: Uint8Array | ArrayBuffer) =>
            bytesToHex(kid instanceof Uint8Array ? kid : new Uint8Array(kid)).toLowerCase()
          ),
        )
        store.updateConversation(profileId, conversationId, (conv) => ({
          ...conv,
          participants: conv.participants.filter((p) => !removedKids.has(p.toLowerCase())),
          participantPublicKeys: (conv.participantPublicKeys || []).filter((pk) => {
            const kid = bytesToHex(keyIDFromPublicKey(hexToBytes(pk))).toLowerCase()
            return !removedKids.has(kid)
          }),
        }))
        break
      }
      case 'group_rekey': {
        if (!localIdentity) break
        const parsed = parseGroupRekeyBody(bodyBytes)
        const localKidB64 = base64UrlEncode(localIdentity.keyID)
        const wrappedBlob = parsed.wrapped_keys[localKidB64]
        if (!wrappedBlob) {
          // We're excluded from this rekey — don't update keys
          break
        }
        // Unwrap the new group key
        const conv = store.findConversation(profileId, conversationId)
        if (!conv) break
        const convIdBytes = hexToBytes(conv.id)
        const newGroupKey = _suite.unwrapKeyForRecipient(
          new Uint8Array(wrappedBlob),
          localIdentity.privateKey,
          localIdentity.keyID,
          convIdBytes,
        )
        const newEpoch = parsed.new_conv_epoch
        const { aeadKey, nonceKey } = _suite.deriveEpochKeys(newGroupKey, convIdBytes, newEpoch)
        store.updateConversation(profileId, conversationId, (c) => ({
          ...c,
          currentEpoch: newEpoch,
          keys: {
            root: bytesToHex(newGroupKey),
            aeadKey: bytesToHex(aeadKey),
            nonceKey: bytesToHex(nonceKey),
          },
        }))
        break
      }
    }
  } catch {
    // Silently ignore malformed group events — they'll still show as system messages
  }
}

// ---- Group event CBOR → JSON ----

/**
 * Convert a CBOR-encoded group event body to JSON text for UI display/storage.
 * Non-group body types return the raw UTF-8 decoded text unchanged.
 */
function groupBodyToJson(bodyType: string, bodyBytes: Uint8Array): string | null {
  if (!GROUP_BODY_TYPES.has(bodyType)) return null
  try {
    let parsed: unknown
    switch (bodyType) {
      case 'group_genesis':
        parsed = parseGroupGenesisBody(bodyBytes)
        break
      case 'group_add':
        parsed = parseGroupAddBody(bodyBytes)
        break
      case 'group_remove':
        parsed = parseGroupRemoveBody(bodyBytes)
        break
      case 'group_rekey':
        parsed = parseGroupRekeyBody(bodyBytes)
        break
    }
    return JSON.stringify(parsed, (_key, value) => {
      // Convert Uint8Array / ArrayBuffer to base64url strings for JSON serialization
      if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
        return base64UrlEncode(value instanceof Uint8Array ? value : new Uint8Array(value))
      }
      return value
    })
  } catch {
    return null
  }
}

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

function decodeGatewayPublicKey(value: string): Uint8Array {
  // Canonical gateway wire encoding is base64url. Keep 64-char hex as a
  // compatibility shim for older callers until those inputs are removed.
  const decoded = /^[0-9a-fA-F]{64}$/.test(value) ? hexToBytes(value) : base64UrlDecode(value)
  if (decoded.length !== 32) throw new Error(`gatewayPublicKey must decode to 32 bytes (got ${decoded.length})`)
  return decoded
}

function decodeIdentityPublicKey(value: string): Uint8Array {
  const trimmed = value.trim()
  const decoded = /^[0-9a-fA-F]{64}$/.test(trimmed) ? hexToBytes(trimmed) : base64UrlDecode(trimmed)
  if (decoded.length !== 32) throw new Error(`public key must decode to 32 bytes (got ${decoded.length})`)
  return decoded
}

function decodeIdentityKeyID(value: string): Uint8Array {
  const trimmed = value.trim()
  const decoded = /^[0-9a-fA-F]{32}$/.test(trimmed) ? hexToBytes(trimmed) : base64UrlDecode(trimmed)
  if (decoded.length !== 16) throw new Error(`key ID must decode to 16 bytes (got ${decoded.length})`)
  return decoded
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
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
  const participants = conv.participants.length > 0
    ? conv.participants
    : listParticipantKeyIDs(conv.participantPublicKeys || [])
  return {
    id: hexToBytes(conv.id),
    type: conv.type as 'direct' | 'group' | 'announce',
    keys: {
      root: hexToBytes(conv.keys.root),
      aeadKey: hexToBytes(conv.keys.aeadKey),
      nonceKey: hexToBytes(conv.keys.nonceKey),
    },
    participants: participants.map((p) => hexToBytes(p)),
    createdAt: new Date(conv.createdAt || Date.now()),
    currentEpoch: conv.currentEpoch || 0,
  }
}

// ---- Dropbox transport ----

function getDropbox(): DropboxClient {
  return new DropboxClient(store.getDropboxUrl())
}

interface GatewayBootstrap {
  gatewayPublicKey: string
  gatewayKid: string
}

function submitReceiptBestEffort(
  dropbox: DropboxClient,
  identity: IdentityKeys,
  convId: Uint8Array,
  msgId: Uint8Array,
  requiredAcks: number,
): void {
  try {
    const receipt = buildSignedReceipt(identity, convId, msgId, requiredAcks)
    dropbox.submitReceipt(receipt).catch(() => {})
  } catch {
    // Receipt emission is best-effort
  }
}

async function sendEnvelope(
  conversationId: string,
  envelope: ReturnType<typeof createMessage>,
  receipt?: { identity: IdentityKeys; convId: Uint8Array; requiredAcks: number },
): Promise<void> {
  const dropbox = getDropbox()
  const data = serializeEnvelope(envelope)
  const convIdBytes = hexToBytes(conversationId)
  await dropbox.postMessage(convIdBytes, data)
  if (receipt) {
    submitReceiptBestEffort(
      dropbox,
      receipt.identity,
      receipt.convId,
      envelope.msg_id,
      receipt.requiredAcks,
    )
  }
}

// ---- Invite ----

function formatConversation(conv: store.StoredConversation): Conversation {
  return {
    id: conv.id,
    name: conv.name || `${conv.type || 'chat'}-${conv.id.slice(0, 8)}`,
    type: conv.type || 'direct',
    participants: conv.participants || [],
    createdAt: conv.createdAt || null,
    inviteToken: conv.inviteToken || undefined,
  }
}

function dedupeHex(values: string[]): string[] {
  const seen = new Set<string>()
  const deduped: string[] = []
  for (const value of values) {
    const normalized = value.trim().toLowerCase()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    deduped.push(normalized)
  }
  return deduped
}

function listParticipantKeyIDs(publicKeysHex: string[]): string[] {
  return dedupeHex(publicKeysHex.map((publicKeyHex) => {
    const publicKey = hexToBytes(publicKeyHex)
    return bytesToHex(keyIDFromPublicKey(publicKey))
  }))
}

function mergeConversationParticipants(
  profileId: string,
  conversationId: string,
  publicKey: Uint8Array,
): void {
  const publicKeyHex = bytesToHex(publicKey)
  const keyIdHex = bytesToHex(keyIDFromPublicKey(publicKey))
  store.updateConversation(profileId, conversationId, (conv) => {
    const participantPublicKeys = dedupeHex([...(conv.participantPublicKeys || []), publicKeyHex])
    const participants = dedupeHex([...(conv.participants || []), keyIdHex, ...listParticipantKeyIDs(participantPublicKeys)])
    return {
      ...conv,
      participants,
      participantPublicKeys,
    }
  })
}

const NON_MEMBER_SYSTEM_BODY_TYPES = new Set([
  'gate.executed',
  'gate.result',
  'gate.expired',
  'gate.invalidated',
  'gate.config',
  'gov.applied',
  'gov.invalidated',
  'group_add',
  'group_remove',
  'group_rekey',
])

function shouldTrackSenderAsParticipant(
  conv: store.StoredConversation | null,
  bodyType: string,
  senderKidHex: string,
): boolean {
  const normalizedKid = senderKidHex.toLowerCase()
  if ((conv?.participants || []).some((participant) => participant.toLowerCase() === normalizedKid)) {
    return true
  }
  return !NON_MEMBER_SYSTEM_BODY_TYPES.has(bodyType)
}

function listKnownParticipantPublicKeys(
  conv: store.StoredConversation | null,
  identity?: IdentityKeys | null,
): Uint8Array[] {
  const allHex = dedupeHex([
    ...(conv?.participantPublicKeys || []),
    identity ? bytesToHex(identity.publicKey) : '',
  ])
  return allHex.map((publicKeyHex) => hexToBytes(publicKeyHex))
}

function listEligibleSignerKids(
  conv: store.StoredConversation | null,
  identity?: IdentityKeys | null,
): string[] {
  if (conv?.participants?.length) {
    return dedupeHex(conv.participants).map((kidHex) => base64UrlEncode(hexToBytes(kidHex)))
  }
  return dedupeHex(listKnownParticipantPublicKeys(conv, identity).map((publicKey) =>
    bytesToHex(keyIDFromPublicKey(publicKey)),
  )).map((kidHex) => base64UrlEncode(hexToBytes(kidHex)))
}

function defaultGovernanceApprovals(
  conv: store.StoredConversation | null,
  identity?: IdentityKeys | null,
  options?: {
    proposalType?: 'floor_change' | 'rules_change' | 'member_add' | 'member_remove'
    removedMemberCount?: number
  },
): number {
  const eligibleCount = Math.max(1, listEligibleSignerKids(conv, identity).length)
  if (options?.proposalType === 'member_remove') {
    return Math.max(1, eligibleCount - (options.removedMemberCount || 0))
  }
  return eligibleCount
}

function findGovernanceProposalInHistory(
  profileId: string,
  conversationId: string,
  proposalId: string,
): Record<string, unknown> {
  const history = store.getHistory(profileId, conversationId)
  for (const message of history) {
    if (message.bodyType !== 'gov.propose') continue
    try {
      const parsed = JSON.parse(message.text) as Record<string, unknown>
      if (parsed.proposal_id === proposalId) {
        return parsed
      }
    } catch {
      continue
    }
  }
  throw new Error(`Governance proposal ${proposalId} not found in conversation history`)
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
    participantPublicKeys: dedupeHex([
      bytesToHex(invite.inviter_ik_pk),
      bytesToHex(identity.publicKey),
    ]),
    createdAt: new Date().toISOString(),
    currentEpoch: 0,
    inviteToken: token,
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
    participantPublicKeys: dedupeHex([
      bytesToHex(invite.inviter_ik_pk),
      bytesToHex(identity.publicKey),
    ]),
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

  await sendEnvelope(conversationId, envelope, {
    identity,
    convId: convCrypto.id,
    requiredAcks: Math.max(MIN_RECEIPT_ACKS, convCrypto.participants.length),
  })

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

  let convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) return { messages: [] }

  const dropbox = getDropbox()
  const fromSeq = store.loadCursor(profileId, conversationId)
  const convIdBytes = hexToBytes(conversationId)
  const result = await dropbox.receiveMessages(convIdBytes, fromSeq, 200)

  const selfKeyIdHex = bytesToHex(identity.keyID).toLowerCase()
  const acceptedMessages: ChatMessage[] = []
  const processedMsgIds: Uint8Array[] = []

  for (const rawEnvelope of result.messages) {
    const activeConvCrypto = convCrypto
    if (!activeConvCrypto) {
      break
    }
    let envelope
    try {
      envelope = deserializeEnvelope(rawEnvelope)
    } catch {
      continue
    }

    let decrypted
    try {
      decrypted = decryptMessage(envelope, activeConvCrypto)
    } catch {
      continue
    }

    const senderKidHex = bytesToHex(new Uint8Array(decrypted.inner.sender_kid)).toLowerCase()
    const bodyType = decrypted.inner.body_type || 'text'
    const rawBodyBytes = new Uint8Array(decrypted.inner.body)
    const bodyText = groupBodyToJson(bodyType, rawBodyBytes) ?? new TextDecoder().decode(rawBodyBytes)
    const createdAt = new Date(envelope.created_ts * 1000).toISOString()

    // Apply group membership/epoch state changes
    applyGroupEvent(profileId, conversationId, bodyType, rawBodyBytes, identity)
    if (bodyType === 'group_rekey') {
      convCrypto = getConvCrypto(profileId, conversationId)
      if (!convCrypto) {
        continue
      }
    }

    const conv = store.findConversation(profileId, conversationId)
    if (shouldTrackSenderAsParticipant(conv, bodyType, senderKidHex)) {
      mergeConversationParticipants(profileId, conversationId, new Uint8Array(decrypted.inner.sender_ik_pk))
    }

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

    processedMsgIds.push(envelope.msg_id)
  }

  if (result.sequence > fromSeq) {
    store.saveCursor(profileId, conversationId, result.sequence)
  }

  // Emit read receipts for all successfully processed messages (fire-and-forget)
  if (processedMsgIds.length > 0 && convCrypto) {
    const requiredAcks = Math.max(MIN_RECEIPT_ACKS, convCrypto.participants.length)
    for (const msgId of processedMsgIds) {
      submitReceiptBestEffort(dropbox, identity, convCrypto.id, msgId, requiredAcks)
    }
  }

  return { messages: acceptedMessages }
}

// ---- Gate operations ----

export async function gateRunRequest(
  profileId: string, profileName: string, conversationId: string,
  recipe: GateRecipe,
  recipeName: string, _gateUrl: string, args: Record<string, string>, minimumApprovals = 1,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  const resolved = resolveRecipe(recipe, args)
  let requestBody: unknown = null
  if (resolved.body) {
    requestBody = JSON.parse(new TextDecoder().decode(resolved.body))
  } else if (args._body) {
    try { requestBody = JSON.parse(args._body) } catch { requestBody = args._body }
  }

  const requestId = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + 3600000).toISOString()
  const expiresAtUnix = Math.floor(Date.now() / 1000) + 3600
  const kidB64 = base64UrlEncode(identity.keyID)
  const payloadHash = computePayloadHash(requestBody ?? null)

  const conv = store.findConversation(profileId, conversationId)
  const eligibleSignerKids = listEligibleSignerKids(conv, identity)
  // Determine threshold from recipe or default to participant count
  const requiredApprovals = Math.max(recipe.threshold ?? eligibleSignerKids.length, minimumApprovals, 1)

  const signable = {
    conv_id: conversationId,
    request_id: requestId,
    verb: recipe.verb,
    target_endpoint: resolved.endpoint,
    target_service: recipe.service,
    target_url: resolved.target_url,
    expires_at_unix: expiresAtUnix,
    payload_hash: payloadHash,
    eligible_signer_kids: eligibleSignerKids,
    required_approvals: requiredApprovals,
  }

  const sig = signRequest(identity.privateKey, signable)
  const sigB64 = base64UrlEncode(sig)

  const gateMsg = {
    type: 'gate.request',
    recipe_name: recipeName,
    conv_id: conversationId,
    request_id: requestId,
    verb: recipe.verb,
    target_endpoint: resolved.endpoint,
    target_service: recipe.service,
    target_url: resolved.target_url,
    expires_at: expiresAt,
    signer_kid: kidB64,
    signature: sigB64,
    arguments: Object.keys(args).length > 0 ? args : undefined,
    payload: requestBody ?? undefined,
    eligible_signer_kids: eligibleSignerKids,
    required_approvals: requiredApprovals,
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

  const kidB64 = base64UrlEncode(identity.keyID)
  const payloadHash = computePayloadHash(reqMsg.payload ?? null)

  const signable = {
    conv_id: reqMsg.conv_id as string,
    request_id: requestId,
    verb: reqMsg.verb as string,
    target_endpoint: reqMsg.target_endpoint as string,
    target_service: reqMsg.target_service as string,
    target_url: reqMsg.target_url as string,
    expires_at_unix: Math.floor(new Date(reqMsg.expires_at as string).getTime() / 1000),
    payload_hash: payloadHash,
    eligible_signer_kids: (reqMsg.eligible_signer_kids as string[]) || [],
    required_approvals: (reqMsg.required_approvals as number) || 1,
  }

  const reqHash = hashRequest(signable)
  const approvalSignable = {
    conv_id: reqMsg.conv_id as string,
    request_id: requestId,
    request_hash: reqHash,
  }

  const sig = signApproval(identity.privateKey, approvalSignable)
  const sigB64 = base64UrlEncode(sig)

  const approvalBody = {
    type: 'gate.approval',
    conv_id: reqMsg.conv_id,
    request_id: requestId,
    signer_kid: kidB64,
    signature: sigB64,
  }

  const bodyText = JSON.stringify(approvalBody)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.approval')
}

export async function gateDisapproveRequest(
  profileId: string, profileName: string, conversationId: string, requestId: string
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  const kidB64 = base64UrlEncode(identity.keyID)

  const disapprovalBody = {
    type: 'gate.disapproval',
    conv_id: conversationId,
    request_id: requestId,
    signer_kid: kidB64,
  }

  const bodyText = JSON.stringify(disapprovalBody)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.disapproval')
}

export async function gatePromoteRequest(
  profileId: string, profileName: string, conversationId: string,
  gatewayKid: string, threshold: number
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  // Build participants map: base64url kid → base64url public key (gateway excluded)
  const conv = store.findConversation(profileId, conversationId)
  const participants: Record<string, string> = {}
  const knownPublicKeys = listKnownParticipantPublicKeys(conv, identity)
  for (const pk of knownPublicKeys) {
    const kid = base64UrlEncode(keyIDFromPublicKey(pk))
    if (kid === gatewayKid) continue // Exclude gateway
    participants[kid] = base64UrlEncode(pk)
  }

  const promotePayload = {
    type: 'gate.promote',
    conv_id: conversationId,
    gateway_kid: gatewayKid,
    participants,
    rules: [{ service: '*', endpoint: '*', verb: '*', m: threshold }],
    floor: threshold,
  }

  const bodyText = JSON.stringify(promotePayload)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.promote')
}

export async function bootstrapGatewayForConversation(
  profileId: string,
  conversationId: string,
  gateServerUrl: string,
): Promise<GatewayBootstrap> {
  const convCrypto = getConvCrypto(profileId, conversationId)
  if (!convCrypto) throw new Error(`Conversation ${conversationId} not found`)

  const baseUrl = gateServerUrl.trim().replace(/\/+$/, '')
  if (!baseUrl) {
    throw new Error('Gateway server URL is required')
  }

  const response = await fetch(`${baseUrl}/v1/promote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      conv_id: conversationId,
      conv_aead_key: base64UrlEncode(convCrypto.keys.aeadKey),
      conv_nonce_key: base64UrlEncode(convCrypto.keys.nonceKey),
      conv_epoch: convCrypto.currentEpoch,
    }),
  })

  if (!response.ok) {
    throw new Error(`Gateway bootstrap failed: HTTP ${response.status} ${await response.text()}`)
  }

  const data = await response.json() as { gateway_public_key?: unknown; gateway_kid?: unknown }
  if (typeof data.gateway_public_key !== 'string' || typeof data.gateway_kid !== 'string') {
    throw new Error('Gateway bootstrap returned an invalid response')
  }

  store.updateConversation(profileId, conversationId, (conv) => ({
    ...conv,
    gateway: {
      publicKey: data.gateway_public_key as string,
      keyId: data.gateway_kid as string,
    },
  }))

  return {
    gatewayPublicKey: data.gateway_public_key,
    gatewayKid: data.gateway_kid,
  }
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
  const selfKidB64 = base64UrlEncode(identity.keyID)

  if (gatewayPublicKey) {
    gwPubKeyBytes = decodeGatewayPublicKey(gatewayPublicKey)
  } else {
    const conv = store.findConversation(profileId, conversationId)
    if (conv?.gateway?.publicKey) {
      gwPubKeyBytes = decodeGatewayPublicKey(conv.gateway.publicKey)
    }
  }

  if (!gwPubKeyBytes) {
    const conv = store.findConversation(profileId, conversationId)
    for (const publicKey of listKnownParticipantPublicKeys(conv, identity)) {
      const pKid = base64UrlEncode(keyIDFromPublicKey(publicKey))
      if (pKid !== selfKidB64) {
        gwPubKeyBytes = publicKey
        break
      }
    }
    if (!gwPubKeyBytes && conv?.participants) {
      // conv.participants stores hex key IDs; compare in hex
      const selfKidHex = bytesToHex(identity.keyID).toLowerCase()
      for (const participantKeyId of conv.participants) {
        if (participantKeyId.toLowerCase() !== selfKidHex) {
          throw new Error('Gateway participant public key is not known yet; receive a message from that participant first, or provide gatewayPublicKey')
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
  const encryptedBlob = base64UrlEncode(sealed)

  const secretPayload = {
    type: 'gate.secret',
    secret_id: secretId,
    service,
    header_name: headerName || 'Authorization',
    header_template: headerTemplate || 'Bearer {value}',
    encrypted_blob: encryptedBlob,
    sender_kid: selfKidB64,
  }

  const bodyText = JSON.stringify(secretPayload)
  return sendMessageToConversation(profileId, profileName, conversationId, bodyText, 'gate.secret')
}

// ---- Governance operations ----

export async function govProposeFloorChange(
  profileId: string,
  profileName: string,
  conversationId: string,
  proposedFloor: number,
  requiredApprovals?: number,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')
  if (proposedFloor < 1) throw new Error('Proposed floor must be at least 1')

  const conv = store.findConversation(profileId, conversationId)
  const eligibleSignerKids = listEligibleSignerKids(conv, identity)
  const proposal = createProposalBody(identity, {
    convId: conversationId,
    proposalType: 'floor_change',
    proposedFloor,
    eligibleSignerKids,
    requiredApprovals: requiredApprovals ?? defaultGovernanceApprovals(conv, identity, { proposalType: 'floor_change' }),
    expiresInSeconds: 3600,
  })

  return sendMessageToConversation(
    profileId,
    profileName,
    conversationId,
    JSON.stringify(proposal),
    'gov.propose',
  )
}

export async function govProposeMemberAdd(
  profileId: string,
  profileName: string,
  conversationId: string,
  memberPublicKey: string,
  requiredApprovals?: number,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const conv = store.findConversation(profileId, conversationId)
  const publicKey = decodeIdentityPublicKey(memberPublicKey)
  const eligibleSignerKids = listEligibleSignerKids(conv, identity)
  const proposal = createProposalBody(identity, {
    convId: conversationId,
    proposalType: 'member_add',
    proposedMembers: [{
      kid: base64UrlEncode(keyIDFromPublicKey(publicKey)),
      publicKey: base64UrlEncode(publicKey),
    }],
    eligibleSignerKids,
    requiredApprovals: requiredApprovals ?? defaultGovernanceApprovals(conv, identity, { proposalType: 'member_add' }),
    expiresInSeconds: 3600,
  })

  return sendMessageToConversation(
    profileId,
    profileName,
    conversationId,
    JSON.stringify(proposal),
    'gov.propose',
  )
}

export async function govProposeMemberRemove(
  profileId: string,
  profileName: string,
  conversationId: string,
  memberKeyId: string,
  requiredApprovals?: number,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const conv = store.findConversation(profileId, conversationId)
  const eligibleSignerKids = listEligibleSignerKids(conv, identity)
  const proposal = createProposalBody(identity, {
    convId: conversationId,
    proposalType: 'member_remove',
    removedMemberKids: [base64UrlEncode(decodeIdentityKeyID(memberKeyId))],
    eligibleSignerKids,
    requiredApprovals: requiredApprovals ?? defaultGovernanceApprovals(conv, identity, {
      proposalType: 'member_remove',
      removedMemberCount: 1,
    }),
    expiresInSeconds: 3600,
  })

  return sendMessageToConversation(
    profileId,
    profileName,
    conversationId,
    JSON.stringify(proposal),
    'gov.propose',
  )
}

export async function govApproveProposal(
  profileId: string,
  profileName: string,
  conversationId: string,
  proposalId: string,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const proposal = findGovernanceProposalInHistory(profileId, conversationId, proposalId)
  const proposalHash = hashProposal({
    conv_id: proposal.conv_id as string,
    proposal_id: proposal.proposal_id as string,
    proposal_type: proposal.proposal_type as 'floor_change' | 'rules_change' | 'member_add' | 'member_remove',
    proposed_floor: proposal.proposed_floor as number | undefined,
    proposed_rules: proposal.proposed_rules as Array<{ service: string; endpoint: string; verb: string; m: number }> | undefined,
    proposed_members: proposal.proposed_members as Array<{ kid: string; public_key: string }> | undefined,
    removed_member_kids: proposal.removed_member_kids as string[] | undefined,
    eligible_signer_kids: proposal.eligible_signer_kids as string[],
    required_approvals: proposal.required_approvals as number,
    expires_at_unix: Math.floor(new Date(proposal.expires_at as string).getTime() / 1000),
  })

  const approval = {
    type: 'gov.approve',
    conv_id: proposal.conv_id,
    proposal_id: proposal.proposal_id,
    signer_kid: base64UrlEncode(identity.keyID),
    signature: base64UrlEncode(signGovApproval(identity.privateKey, {
      conv_id: proposal.conv_id as string,
      proposal_id: proposal.proposal_id as string,
      proposal_hash: proposalHash,
    })),
  }

  return sendMessageToConversation(
    profileId,
    profileName,
    conversationId,
    JSON.stringify(approval),
    'gov.approve',
  )
}

export async function govDisapproveProposal(
  profileId: string,
  profileName: string,
  conversationId: string,
  proposalId: string,
): Promise<ChatMessage> {
  const identity = loadIdentityKeys(profileId)
  if (!identity) throw new Error('No identity found')

  const disapproval = {
    type: 'gov.disapprove',
    conv_id: conversationId,
    proposal_id: proposalId,
    signer_kid: base64UrlEncode(identity.keyID),
  }

  return sendMessageToConversation(
    profileId,
    profileName,
    conversationId,
    JSON.stringify(disapproval),
    'gov.disapprove',
  )
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
