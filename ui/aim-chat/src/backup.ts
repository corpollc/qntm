import { base64UrlDecode, base64UrlEncode, validateIdentity, validateGatewayIdentity, restoreGroupSession, groupSessionConversation, createGroupLink, keyIDFromPublicKey, deserializeEnvelope, parseGroupGenesisBody, QSP1Suite, marshalCanonical } from '@corpollc/qntm'
import { MAX_GROUP_CONTROL_RECEIPTS, GROUP_RELEASE_REASONS, type StoreData, type StoredConversation, type StoredGroupOperation } from './store'
import { groupAdditionIntent, groupAdditionChallenge, groupRenewalChallenge, groupRefreshIntent, assertGroupOperationEvidenceBudget, MAX_GROUP_OPERATION_REVISIONS,
  validateGroupRemovalTarget } from './group-operation'

export const MAX_BACKUP_BYTES = 10 * 1024 * 1024
const STORE_KEY = 'aim-store'
const FORMAT = 'qntm-aim-backup'
const ITERATIONS = 600_000
const encoder = new TextEncoder()
const fail = (path: string): never => { throw new Error(`Invalid backup: ${path}.`) }
type Obj = Record<string, any>

function object(value: unknown, path: string, fields?: string[]): Obj {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(path)
  const obj = value as Obj
  if (Object.keys(obj).some(key => ['__proto__', 'constructor', 'prototype'].includes(key) || (fields && !fields.includes(key)))) fail(path)
  return obj
}
function text(value: unknown, path: string, max = 1024, empty = false): string {
  if (typeof value !== 'string' || (!empty && !value.length) || value.length > max) fail(path)
  return value as string
}
function list(value: unknown, path: string, max = 10_000): any[] {
  if (!Array.isArray(value) || value.length > max) fail(path)
  return value as any[]
}
function integer(value: unknown, path: string, min = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < min) fail(path)
  return value as number
}
function hex(value: unknown, bytes: number, path: string): string {
  const s = text(value, path, bytes * 2)
  if (!new RegExp(`^[a-f0-9]{${bytes * 2}}$`).test(s)) fail(path)
  return s
}
function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!, v => parseInt(v, 16))
}
function b64(value: unknown, path: string, length?: number): Uint8Array {
  const s = text(value, path, MAX_BACKUP_BYTES * 2)
  if (!/^[A-Za-z0-9_-]+$/.test(s)) fail(path)
  const bytes = base64UrlDecode(s)
  if ((length !== undefined && bytes.length !== length) || encode64(bytes) !== s) fail(path)
  return bytes
}
// The core encoder is intended for small protocol fields; avoid argument limits for backups.
function encode64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192))
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function date(value: unknown, path: string) {
  if (!Number.isFinite(Date.parse(text(value, path, 64)))) fail(path)
}
function url(value: unknown, path: string) {
  let parsed: URL
  try { parsed = new URL(text(value, path, 2048)) } catch { return fail(path) }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) fail(path)
}
function unique(values: string[], path: string) {
  if (new Set(values).size !== values.length) fail(path)
}
function parsedJSON(json: string): Obj {
  if (typeof json !== 'string' || json.length > MAX_BACKUP_BYTES || encoder.encode(json).length > MAX_BACKUP_BYTES) fail('file exceeds 10 MiB')
  let parsed: unknown
  try { parsed = JSON.parse(json) } catch { return fail('JSON syntax') }
  return object(parsed, 'root object')
}

/** Validate all persisted fields before any storage mutation; no network access. */
export function validateBackup(json: string): StoreData {
  const data = object(parsedJSON(json), 'store fields', ['activeProfileId', 'profiles', 'identities', 'conversations', 'history', 'contacts', 'guidanceContacts', 'contactPins', 'cursors', 'dropboxUrl'])
  const profiles = list(data.profiles, 'profiles', 100)
  const profileIds = profiles.map(p => {
    object(p, 'profile fields', ['id', 'name'])
    if (!/^[a-z0-9][a-z0-9_-]{0,127}$/.test(text(p.id, 'profile ID', 128)) || ['constructor', 'prototype'].includes(p.id)) fail('profile ID')
    text(p.name, 'profile name', 1024)
    return p.id as string
  })
  unique(profileIds, 'duplicate profile IDs')
  text(data.activeProfileId, 'active profile', 128, true)
  if (data.activeProfileId && !profileIds.includes(data.activeProfileId)) fail('active profile is missing')
  url(data.dropboxUrl, 'relay URL')
  // Guidance pins were introduced after the original backup format.
  if (data.guidanceContacts === undefined) data.guidanceContacts = {}
  if (data.contactPins === undefined) data.contactPins = {}
  for (const name of ['identities', 'conversations', 'history', 'contacts', 'guidanceContacts', 'contactPins', 'cursors']) {
    object(data[name], name)
    if (Object.keys(data[name]).some(id => !profileIds.includes(id))) fail(`${name} references a missing profile`)
  }
  for (const identity of Object.values(data.identities) as Obj[]) {
    object(identity, 'identity fields', ['privateKey', 'publicKey', 'keyId'])
    const privateKey = hexBytes(hex(identity.privateKey, 64, 'private key'))
    const publicKey = hexBytes(hex(identity.publicKey, 32, 'public key'))
    const keyID = hexBytes(hex(identity.keyId, 16, 'identity key ID'))
    try { validateIdentity({ privateKey, publicKey, keyID }) } catch { fail('identity key pair does not match') }
    if (identity.privateKey.slice(64) !== identity.publicKey) fail('private key public suffix does not match')
  }
  for (const pid of profileIds) {
    const conversations = list(data.conversations[pid] ?? [], 'conversations', 1000)
    unique(conversations.map(c => hex(object(c, 'conversation').id, 16, 'conversation ID')), 'duplicate conversation IDs')
    for (const conv of conversations) {
      object(conv, 'conversation fields', ['id', 'name', 'type', 'keys', 'participants', 'participantPublicKeys', 'gateway', 'createdAt', 'currentEpoch', 'inviteToken', 'group'])
      text(conv.name, 'conversation name', 1024, true)
      if (!['direct', 'group', 'announce'].includes(conv.type)) fail('conversation type')
      object(conv.keys, 'conversation keys', ['root', 'aeadKey', 'nonceKey'])
      for (const key of ['root', 'aeadKey', 'nonceKey']) hex(conv.keys[key], 32, 'conversation key')
      const participants = list(conv.participants, 'participants', 1000).map(p => hex(p, 16, 'participant key ID'))
      unique(participants, 'duplicate participant key IDs')
      if (conv.participantPublicKeys !== undefined) {
        const keys = list(conv.participantPublicKeys, 'participant public keys', 1000).map(p => hex(p, 32, 'participant public key'))
        unique(keys, 'duplicate participant public keys')
      }
      date(conv.createdAt, 'conversation creation time')
      integer(conv.currentEpoch, 'conversation epoch')
      if (conv.inviteToken !== undefined) text(conv.inviteToken, 'invite token', 65536)
      if (conv.gateway != null) validateGateway(conv.gateway, conv)
      if (conv.group !== undefined) {
        if (conv.type !== 'group' || conv.gateway != null || conv.inviteToken !== undefined) fail('contact group boundary')
        const identity = data.identities[pid]
        if (!identity) fail('contact group identity missing')
        const localIdentity = { privateKey: hexBytes(identity.privateKey), publicKey: hexBytes(identity.publicKey), keyID: hexBytes(identity.keyId) }
        const host = object(conv.group, 'group host fields', ['session', 'cursor', 'bootstrapSequence', 'removedSequence', 'pending', 'receipts', 'controlReceipts', 'releasedOperations', 'operation', 'relayUrl', 'inviterPublicKey', 'revision'])
        const checkpoint = restoreGroupSession(localIdentity, host.session)
        if (checkpoint.conversationId !== conv.id) fail('group checkpoint conversation mismatch')
        const crypto = groupSessionConversation(checkpoint)
        const encodedHex = (value: Uint8Array) => Array.from(value, b => b.toString(16).padStart(2, '0')).join('')
        for (const key of ['root', 'aeadKey', 'nonceKey'] as const) if (conv.keys[key] !== encodedHex(crypto.keys[key])) fail('group checkpoint key mismatch')
        const rosterKeys = parseGroupGenesisBody(base64UrlDecode(checkpoint.snapshot)).founding_members.map(member => encodedHex(member.public_key)).sort()
        if (!Array.isArray(conv.participantPublicKeys) || [...conv.participantPublicKeys].sort().join(',') !== rosterKeys.join(',')) fail('group checkpoint public keys mismatch')
        if (conv.currentEpoch !== checkpoint.epoch || [...conv.participants].sort().join(',') !== crypto.participants.map(encodedHex).sort().join(',')) fail('group checkpoint roster mismatch')
        integer(host.cursor, 'group cursor'); integer(host.bootstrapSequence, 'group bootstrap sequence'); integer(host.revision, 'group revision')
        if (host.bootstrapSequence > host.cursor || (data.cursors[pid]?.[conv.id] ?? 0) !== host.cursor) fail('group cursor mismatch')
        if (host.removedSequence !== undefined) integer(host.removedSequence, 'group removal sequence', 1)
        url(host.relayUrl, 'group relay URL')
        createGroupLink({ conversationId: hexBytes(conv.id), inviterPublicKey: hexBytes(hex(host.inviterPublicKey, 32, 'group inviter key')), relayUrl: host.relayUrl })
        const pending = list(host.pending, 'pending group ciphertext', 256)
        let pendingBytes = 0
        for (const row of pending) { object(row, 'pending row', ['seq', 'wire']); integer(row.seq, 'pending sequence', 1); if (row.seq > host.cursor) fail('pending sequence exceeds cursor'); pendingBytes += b64(row.wire, 'pending ciphertext').length }
        if (pendingBytes > 4 * 1024 * 1024) fail('pending group ciphertext exceeds 4 MiB')
        for (const seq of list(host.receipts, 'group receipts', 10_000)) integer(seq, 'group receipt', 1)
        if (host.controlReceipts !== undefined) {
          const identities: string[] = []
          for (const row of list(host.controlReceipts, 'group control receipts', MAX_GROUP_CONTROL_RECEIPTS)) {
            const item = object(row, 'group control receipt', ['id', 'digest', 'epoch', 'sequence', 'valid', 'bodyType'])
            hex(item.id, 16, 'control receipt id'); hex(item.digest, 32, 'control receipt digest')
            integer(item.epoch, 'control receipt epoch'); integer(item.sequence, 'control receipt sequence', 1)
            if (item.sequence > host.cursor) fail('control receipt sequence exceeds cursor')
            if (typeof item.valid !== 'boolean') fail('control receipt validity')
            if (!['group_genesis', 'group_add', 'group_remove', 'group_rekey'].includes(item.bodyType)) fail('control receipt body type')
            identities.push(`${item.id}:${item.digest}`)
          }
          unique(identities, 'duplicate control receipt identity')
        }
        if (host.releasedOperations !== undefined) {
          // Released removals keep only uncertain ciphertext and its pin: no
          // predicted checkpoint, no delivery claim, one flat bounded list.
          const archive = list(host.releasedOperations, 'released group operations', MAX_GROUP_OPERATION_REVISIONS)
          const conversationWire = (value: unknown, path: string) => {
            if (encodedHex(deserializeEnvelope(b64(value, path)).conv_id) !== conv.id) fail(`${path} conversation`)
          }
          const removalTarget = (value: unknown, path: string) => {
            const target = object(value, path, ['keyId', 'publicKey', 'record', 'admission'])
            try { validateGroupRemovalTarget(target as Parameters<typeof validateGroupRemovalTarget>[0]) } catch { fail(path) }
          }
          for (const value of archive) {
            const row = object(value, 'released operation fields', ['kind', 'controls', 'welcomes', 'delivered', 'target', 'origin', 'superseded', 'delivery', 'releasedReason', 'releasedAt'])
            if (!['remove', 'removal_rekey'].includes(row.kind) || row.delivery !== 'unknown' || !GROUP_RELEASE_REASONS.includes(row.releasedReason)) fail('released operation kind')
            integer(row.releasedAt, 'released operation time')
            const controls = list(row.controls, 'released controls', 2)
            integer(row.delivered, 'released delivered count')
            if (controls.length !== (row.kind === 'remove' ? 2 : 1) || list(row.welcomes, 'released welcomes', 0).length) fail('released operation shape')
            for (const wire of controls) conversationWire(wire, 'released control')
            if (row.kind === 'remove') {
              if (row.origin !== undefined) fail('released removal origin')
              if (row.target !== undefined) removalTarget(row.target, 'released removal target')
            } else {
              if (row.target !== undefined) fail('released repair target')
              const origin = object(row.origin, 'released repair origin fields', ['kind', 'controls', 'welcomes', 'delivered', 'target', 'delivery'])
              integer(origin.delivered, 'released origin delivered count')
              if (origin.kind !== 'remove' || origin.delivery !== 'unknown' || list(origin.controls, 'released origin controls', 2).length !== 2
                || list(origin.welcomes, 'released origin welcomes', 0).length) fail('released repair origin')
              for (const wire of origin.controls) conversationWire(wire, 'released origin control')
              if (origin.target !== undefined) removalTarget(origin.target, 'released origin target')
            }
            for (const item of row.superseded === undefined ? [] : list(row.superseded, 'released superseded operations', MAX_GROUP_OPERATION_REVISIONS)) {
              const old = object(item, 'released superseded fields', ['kind', 'controls', 'welcomes', 'delivered', 'delivery'])
              integer(old.delivered, 'released superseded delivered count')
              if (old.kind !== row.kind || old.delivery !== 'unknown' || list(old.controls, 'released superseded controls', 1).length !== 1
                || list(old.welcomes, 'released superseded welcomes', 0).length) fail('released superseded shape')
              conversationWire(old.controls[0], 'released superseded control')
            }
          }
          if (marshalCanonical(archive).length > 4 * 1024 * 1024) fail('released group operations exceed 4 MiB')
        }
        if (host.operation !== null) {
          const op = object(host.operation, 'group operation fields', ['kind', 'controls', 'welcomes', 'delivered', 'expected', 'recipient', 'admission', 'recoveryChallenge', 'origin', 'superseded', 'target'])
          if (!['addition', 'addition_rekey', 'refresh', 'renewal', 'remove', 'removal_rekey', 'rekey', 'create'].includes(op.kind)) fail('group operation kind')
          const expected = restoreGroupSession(localIdentity, op.expected)
          if (expected.conversationId !== conv.id) fail('group operation conversation mismatch')
          const controls = list(op.controls, 'saved group controls', 2), welcomes = list(op.welcomes, 'saved group welcomes', 128)
          const expectedControls = ({ addition: 2, addition_rekey: 1, remove: 2, removal_rekey: 1, rekey: 1, create: 1, refresh: 0, renewal: 0 } as Record<string, number>)[op.kind]
          if (controls.length !== expectedControls || (['addition', 'refresh', 'renewal'].includes(op.kind) ? !welcomes.length : welcomes.length !== 0)) fail('group operation shape')
          if (op.kind !== 'remove' && op.target !== undefined) fail('unexpected removal target field')
          if (op.kind === 'remove' && op.target !== undefined) {
            const target = object(op.target, 'removal target fields', ['keyId', 'publicKey', 'record', 'admission'])
            try { validateGroupRemovalTarget(target as Parameters<typeof validateGroupRemovalTarget>[0]) } catch { fail('removal target binding') }
            // The saved expected checkpoint already excludes the pinned incarnation.
            if (parseGroupGenesisBody(base64UrlDecode(expected.snapshot)).founding_members.some(member => encodedHex(member.key_id) === target.keyId)) fail('removal target still present in expected roster')
          }
          if (op.kind === 'removal_rekey') {
            if (op.recipient !== undefined || op.admission !== undefined || op.recoveryChallenge !== undefined) fail('unexpected removal repair fields')
            const origin = object(op.origin, 'original removal fields', ['kind', 'controls', 'welcomes', 'delivered', 'target', 'delivery'])
            if (origin.kind !== 'remove' || origin.delivery !== 'unknown') fail('original removal context')
            const originalControls = list(origin.controls, 'original removal controls', 2), originalWelcomes = list(origin.welcomes, 'original removal welcomes', 0)
            if (originalControls.length !== 2 || originalWelcomes.length !== 0 || integer(origin.delivered, 'original removal delivered count') !== 0) fail('original removal shape')
            const repair = deserializeEnvelope(b64(controls[0], 'saved removal repair'))
            const removal = deserializeEnvelope(b64(originalControls[0], 'original removal wire')), rekey = deserializeEnvelope(b64(originalControls[1], 'original completing rekey wire'))
            for (const envelope of [repair, removal, rekey]) {
              if (encodedHex(envelope.conv_id) !== conv.id || envelope.conv_epoch !== expected.epoch - 1) fail('removal repair epoch binding')
            }
            if (origin.target !== undefined) {
              const target = object(origin.target, 'original removal target fields', ['keyId', 'publicKey', 'record', 'admission'])
              try { validateGroupRemovalTarget(target as Parameters<typeof validateGroupRemovalTarget>[0]) } catch { fail('original removal target binding') }
            }
          }
          if (op.kind === 'renewal' || op.kind === 'addition_rekey') {
            const recipient = hex(op.recipient, 32, 'renewal recipient'), kid = encodedHex(keyIDFromPublicKey(hexBytes(recipient)))
            const accepted = expected.admissions[kid]
            const acceptedCompletion = accepted?.completion
            const roster = parseGroupGenesisBody(base64UrlDecode(expected.snapshot)).founding_members
            if (!roster.some(member => encodedHex(member.public_key) === recipient) || !acceptedCompletion) fail('recovery recipient admission binding')
            if (op.kind === 'renewal') {
              const admission = object(op.admission, 'renewal admission', ['addId', 'addDigest', 'sourceEpoch', 'completion'])
              const completion = object(admission.completion, 'renewal completion', ['rekeyId', 'rekeyDigest'])
              if (welcomes.length !== 1 || admission.addId !== accepted.addId || admission.addDigest !== accepted.addDigest
                || admission.sourceEpoch !== accepted.sourceEpoch || completion.rekeyId !== acceptedCompletion!.rekeyId
                || completion.rekeyDigest !== acceptedCompletion!.rekeyDigest) fail('renewal admission binding')
              groupRenewalChallenge(localIdentity, op as Extract<StoredGroupOperation, { kind: 'renewal' }>)
            } else {
              if (op.admission !== undefined || op.origin === undefined) fail('rotation repair fields')
              const wire = b64(controls[0], 'saved rotation repair'), rekey = deserializeEnvelope(wire)
              if (encodedHex(rekey.msg_id) !== acceptedCompletion!.rekeyId || encodedHex(new QSP1Suite().hash(wire)) !== acceptedCompletion!.rekeyDigest
                || rekey.conv_epoch !== accepted.sourceEpoch || expected.epoch !== accepted.sourceEpoch + 1) fail('rotation repair completion binding')
            }
            if (op.origin !== undefined) {
              const origin = object(op.origin, 'original addition fields', ['kind', 'controls', 'welcomes', 'delivered', 'recipient', 'admission', 'recoveryChallenge', 'delivery'])
              if (origin.kind !== 'addition' || origin.delivery !== 'unknown' || origin.recipient !== recipient) fail('original addition context')
              const originalControls = list(origin.controls, 'original addition controls', 2), originalWelcomes = list(origin.welcomes, 'original addition welcomes', 1)
              if (originalControls.length !== 2 || originalWelcomes.length !== 1) fail('original addition shape')
              integer(origin.delivered, 'original delivered welcome count')
              if (origin.delivered > originalWelcomes.length) fail('original delivered welcome count')
              const proof = object(origin.admission, 'original addition proof', ['addId', 'addDigest'])
              const wire = b64(originalControls[0], 'original addition wire'), addition = deserializeEnvelope(wire)
              if (proof.addId !== accepted.addId || proof.addDigest !== accepted.addDigest
                || proof.addId !== encodedHex(addition.msg_id) || proof.addDigest !== encodedHex(new QSP1Suite().hash(wire))
                || addition.conv_epoch !== accepted.sourceEpoch) fail('original addition proof binding')
              if (origin.recoveryChallenge !== null) hex(origin.recoveryChallenge, 32, 'original recovery challenge')
              for (const wire of [...originalControls, ...originalWelcomes]) {
                if (encodedHex(deserializeEnvelope(b64(wire, 'original encrypted envelope')).conv_id) !== conv.id) fail('original addition envelope context')
              }
              groupAdditionChallenge(localIdentity, { kind: 'addition', controls: originalControls, welcomes: originalWelcomes,
                expected, delivered: origin.delivered, recipient, recoveryChallenge: origin.recoveryChallenge })
            }

          } else if (op.kind !== 'removal_rekey') {
            if (op.admission !== undefined || op.origin !== undefined || !['refresh', 'rekey'].includes(op.kind) && op.superseded !== undefined) fail('unexpected renewal fields')
            if (op.kind === 'addition') {
              if (op.recipient !== undefined) {
                const recipient = hex(op.recipient, 32, 'addition recipient'), kid = encodedHex(keyIDFromPublicKey(hexBytes(recipient)))
                if (!expected.admissions[kid]?.completion) fail('addition recipient provenance')
              }
              if (op.recoveryChallenge !== undefined && op.recoveryChallenge !== null) hex(op.recoveryChallenge, 32, 'addition recovery challenge')
              if (op.recipient !== undefined || op.recoveryChallenge !== undefined) {
                const addition = op as Extract<StoredGroupOperation, { kind: 'addition' }>
                groupAdditionChallenge(localIdentity, addition, groupAdditionIntent(localIdentity, addition))
              }
            } else if (op.kind === 'refresh') {
              if (op.recipient !== undefined) hex(op.recipient, 32, 'refresh recipient')
              if (op.recoveryChallenge !== undefined && op.recoveryChallenge !== null) hex(op.recoveryChallenge, 32, 'refresh recovery challenge')
              groupRefreshIntent(localIdentity, op as Extract<StoredGroupOperation, { kind: 'refresh' }>)
            } else if (op.recipient !== undefined || op.recoveryChallenge !== undefined) fail('unexpected addition fields')
          }
          if (['renewal', 'addition_rekey', 'refresh', 'removal_rekey', 'rekey'].includes(op.kind)) {
            const superseded = op.superseded === undefined ? [] : list(op.superseded, 'superseded operations', MAX_GROUP_OPERATION_REVISIONS)
            const kinds = ({ refresh: ['refresh'], removal_rekey: ['removal_rekey'], rekey: ['rekey'] } as Record<string, string[]>)[op.kind] ?? ['addition_rekey', 'renewal']
            for (const value of superseded) {
              const item = object(value, 'superseded operation fields', ['kind', 'controls', 'welcomes', 'delivered', 'delivery'])
              if (!kinds.includes(item.kind) || item.delivery !== 'unknown') fail('superseded operation kind')
              const rotation = ['addition_rekey', 'removal_rekey', 'rekey'].includes(item.kind)
              const oldControls = list(item.controls, 'superseded controls', 1), oldWelcomes = list(item.welcomes, 'superseded welcomes', 1)
              if (oldControls.length !== (rotation ? 1 : 0) || oldWelcomes.length !== (rotation ? 0 : 1)) fail('superseded operation shape')
              if (integer(item.delivered, 'superseded delivered count') > oldWelcomes.length) fail('superseded delivered count')
              for (const wire of [...oldControls, ...oldWelcomes]) {
                if (encodedHex(deserializeEnvelope(b64(wire, 'superseded ciphertext')).conv_id) !== conv.id) fail('superseded operation conversation')
              }
            }
            assertGroupOperationEvidenceBudget(op.origin, superseded)
          }
          if (['renewal', 'addition_rekey'].includes(op.kind) && op.recoveryChallenge !== undefined) fail('unexpected recovery challenge field')
          for (const wire of [...controls, ...welcomes]) {
            const envelope = deserializeEnvelope(b64(wire, 'saved group wire'))
            if (encodedHex(envelope.conv_id) !== conv.id) fail('saved operation envelope conversation mismatch')
          }
          integer(op.delivered, 'delivered welcomes')
          if (op.delivered > welcomes.length) fail('delivered welcome count')
        }
      }
    }
    for (const [id, messages] of Object.entries(object(data.history[pid] ?? {}, 'history'))) {
      hex(id, 16, 'history conversation ID')
      for (const msg of list(messages, 'messages', 10_000)) {
        object(msg, 'message fields', ['id', 'conversationId', 'direction', 'sender', 'senderKey', 'bodyType', 'text', 'createdAt', 'groupBinding'])
        text(msg.id, 'message ID', 256)
        if (msg.conversationId !== id) fail('message conversation mismatch')
        if (!['incoming', 'outgoing'].includes(msg.direction)) fail('message direction')
        text(msg.sender, 'sender name', 1024, true)
        text(msg.senderKey, 'sender key', 128, true)
        text(msg.bodyType, 'body type', 256)
        text(msg.text, 'message text', 1024 * 1024, true)
        date(msg.createdAt, 'message creation time')
        if (msg.groupBinding !== undefined) {
          const binding = object(msg.groupBinding, 'group history binding', ['digest', 'epoch', 'valid'])
          hex(binding.digest, 32, 'group history digest'); integer(binding.epoch, 'group history epoch')
          if (typeof binding.valid !== 'boolean') fail('group history validity')
          hex(msg.id, 16, 'group history message ID')
          if (!(data.conversations[pid] ?? []).some((conv: StoredConversation) => conv.id === id && conv.group)) fail('group history conversation missing')
        }
      }
    }
    for (const [id, cursor] of Object.entries(object(data.cursors[pid] ?? {}, 'cursors'))) {
      hex(id, 16, 'cursor conversation ID'); integer(cursor, 'cursor')
    }
    for (const [key, name] of Object.entries(object(data.contacts[pid] ?? {}, 'contacts'))) {
      text(key, 'contact key', 256); text(name, 'contact name', 1024)
    }
    for (const [kid, pk] of Object.entries(object(data.contactPins[pid] ?? {}, 'contact pins'))) {
      hex(kid, 16, 'contact pin key ID')
      const key = hexBytes(hex(pk, 32, 'contact pin public key'))
      createGroupLink({ conversationId: new Uint8Array(16), inviterPublicKey: key, relayUrl: data.dropboxUrl })
      if (Array.from(keyIDFromPublicKey(key), b => b.toString(16).padStart(2, '0')).join('') !== kid) fail('contact pin key ID mismatch')
    }
    const contacts = list(data.guidanceContacts[pid] ?? [], 'guidance contacts', 1000)
    unique(contacts.map(c => text(object(c, 'guidance contact').id, 'guidance ID', 128)), 'duplicate guidance IDs')
    for (const contact of contacts) {
      object(contact, 'guidance fields', ['id', 'category', 'name', 'kind', 'conversationId', 'recipientKeyId', 'relayUrl'])
      if (!['legal', 'ethical', 'law_enforcement'].includes(contact.category)) fail('guidance category')
      if (!['human', 'agent', 'organization'].includes(contact.kind)) fail('guidance contact type')
      text(contact.name, 'guidance name', 120)
      hex(contact.conversationId, 16, 'guidance conversation ID')
      hex(contact.recipientKeyId, 16, 'guidance recipient key ID')
      url(contact.relayUrl, 'guidance relay URL')
    }
  }
  return data as StoreData
}

function validateGateway(value: unknown, conv: Obj) {
  const gw = object(value, 'gateway fields', ['status', 'invitationId', 'floor', 'pending', 'publicKey', 'keyId'])
  if (!validateGatewayIdentity(gw.publicKey, gw.keyId)) fail('gateway identity')
  if (gw.status !== undefined && !['pending', 'active'].includes(gw.status)) fail('gateway status')
  if (gw.floor !== undefined) integer(gw.floor, 'gateway floor', 1)
  if (gw.invitationId !== undefined) text(gw.invitationId, 'gateway invitation ID', 256)
  if (gw.pending !== undefined) {
    const pending = object(gw.pending, 'pending gateway fields', ['invitation', 'request', 'url', 'messageId', 'text'])
    const invitation = object(pending.invitation, 'gateway invitation', ['invitation_id', 'inviter_public_key', 'gateway_public_key', 'gateway_kid', 'expires_at'])
    const request = object(pending.request, 'gateway bootstrap', ['invitation_id', 'inviter_public_key', 'sealed'])
    text(invitation.invitation_id, 'gateway invitation ID', 256)
    b64(invitation.inviter_public_key, 'gateway inviter', 32)
    integer(invitation.expires_at, 'gateway invitation expiry', 1)
    if (invitation.gateway_public_key !== gw.publicKey || invitation.gateway_kid !== gw.keyId || request.invitation_id !== invitation.invitation_id || request.inviter_public_key !== invitation.inviter_public_key) fail('gateway invitation mismatch')
    b64(request.sealed, 'sealed gateway bootstrap')
    url(pending.url, 'gateway URL')
    hex(pending.messageId, 16, 'gateway invitation message ID')
    text(pending.text, 'gateway invitation text', 65536)
    let body: Obj
    try { body = JSON.parse(pending.text) } catch { return fail('gateway invitation text') }
    if (!body || body.type !== 'gate.promote' || body.conv_id !== conv.id || body.invitation_id !== invitation.invitation_id || body.gateway_kid !== gw.keyId) fail('gateway invitation context')
  }
}

export interface BackupSummary {
  profiles: Array<{ name: string; id: string; keyId: string | null }>
  conversations: number
  messages: number
  relayUrl: string
  contactPins: Array<{ profile: string; name: string; key: string; publicKey: string }>
  contactGroups: Array<{ profile: string; name: string; id: string; relayUrl: string; removed: boolean; recovery: boolean }>
  guidance: Array<{ profile: string; name: string; category: string; recipientKeyId: string; conversationId: string; relayUrl: string }>
  gateways: Array<{ profile: string; conversationId: string; keyId: string; status: string; url?: string }>
}
function summary(data: StoreData): BackupSummary {
  return {
    profiles: data.profiles.map(p => ({ ...p, keyId: data.identities[p.id]?.keyId ?? null })),
    conversations: Object.values(data.conversations).reduce((n, rows) => n + rows.length, 0),
    messages: Object.values(data.history).reduce((n, convs) => n + Object.values(convs).reduce((m, rows) => m + rows.length, 0), 0),
    relayUrl: data.dropboxUrl,
    contactPins: data.profiles.flatMap(p => Object.entries(data.contactPins?.[p.id] ?? {}).map(([key, publicKey]) => ({ profile: p.name, name: data.contacts[p.id]?.[key] || key, key, publicKey }))),
    contactGroups: data.profiles.flatMap(p => (data.conversations[p.id] ?? []).filter(c => c.group).map(c => ({ profile: p.name, name: c.name, id: c.id, relayUrl: c.group!.relayUrl, removed: c.group!.session.removed, recovery: !!c.group!.session.recovery }))),
    guidance: data.profiles.flatMap(p => (data.guidanceContacts[p.id] ?? []).map(c => ({ profile: p.name, ...c }))),
    gateways: data.profiles.flatMap(p => (data.conversations[p.id] ?? []).filter(c => c.gateway).map(c => ({ profile: p.name, conversationId: c.id, keyId: c.gateway!.keyId, status: c.gateway!.status ?? 'legacy', url: c.gateway!.pending?.url }))),
  }
}
export function rawBackup(): string {
  return localStorage.getItem(STORE_KEY) ?? JSON.stringify({ activeProfileId: '', profiles: [], identities: {}, conversations: {}, history: {}, contacts: {}, guidanceContacts: {}, cursors: {}, dropboxUrl: 'https://inbox.qntm.corpo.llc' })
}
export function importBackup(json: string): void {
  const data = validateBackup(json)
  // One atomic localStorage write; quota failures leave the prior value intact.
  localStorage.setItem(STORE_KEY, JSON.stringify(data))
}
export interface BackupReview { incoming: BackupSummary; current: BackupSummary | null; encrypted: boolean }
// Keep key material and replacement snapshots out of UI props and preview strings.
const reviews = new WeakMap<BackupReview, { json: string; previous: string | null }>()
export async function prepareBackup(json: string, password = ''): Promise<BackupReview> {
  const parsed = parsedJSON(json)
  const encrypted = parsed.format === FORMAT
  const cleartext = encrypted ? await decryptBackup(parsed, password) : json
  const incoming = validateBackup(cleartext)
  let current: BackupSummary | null = null
  try { current = summary(validateBackup(rawBackup())) } catch { /* Corrupted local data can still be replaced explicitly. */ }
  const review = { incoming: summary(incoming), current, encrypted }
  reviews.set(review, { json: JSON.stringify(incoming), previous: localStorage.getItem(STORE_KEY) })
  return review
}
export function restoreBackup(review: BackupReview): void {
  const saved = reviews.get(review)
  if (!saved) throw new Error('Review this backup before restoring it.')
  if (localStorage.getItem(STORE_KEY) !== saved.previous) throw new Error('Local data changed. Review the backup again before replacing it.')
  importBackup(saved.json)
  reviews.delete(review)
}

async function passwordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  text(password, 'password', 1024)
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: new Uint8Array(salt) }, material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
const associatedData = encoder.encode(`${FORMAT}:1:PBKDF2-SHA256:${ITERATIONS}:AES-256-GCM`)
export async function exportEncryptedBackup(password: string): Promise<string> {
  if (password.length < 12) throw new Error('Use a backup password of at least 12 characters.')
  const cleartext = JSON.stringify(validateBackup(rawBackup()))
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await passwordKey(password, salt)
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: associatedData, tagLength: 128 }, key, encoder.encode(cleartext))
  const json = JSON.stringify({ format: FORMAT, version: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, cipher: 'AES-256-GCM', salt: base64UrlEncode(salt), iv: base64UrlEncode(iv), ciphertext: encode64(new Uint8Array(ciphertext)) })
  parsedJSON(json) // Exported files must fit the same import limit.
  return json
}
async function decryptBackup(parsed: Obj, password: string): Promise<string> {
  object(parsed, 'encrypted backup fields', ['format', 'version', 'kdf', 'iterations', 'cipher', 'salt', 'iv', 'ciphertext'])
  if (parsed.version !== 1 || parsed.kdf !== 'PBKDF2-SHA256' || parsed.iterations !== ITERATIONS || parsed.cipher !== 'AES-256-GCM') fail('unsupported encryption format')
  const salt = b64(parsed.salt, 'salt', 16), iv = b64(parsed.iv, 'nonce', 12), ciphertext = b64(parsed.ciphertext, 'ciphertext')
  if (ciphertext.length < 16) fail('ciphertext')
  if (!password) throw new Error('Enter the password for this encrypted backup.')
  const key = await passwordKey(password, salt)
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: associatedData, tagLength: 128 }, key, new Uint8Array(ciphertext))
    return new TextDecoder('utf-8', { fatal: true }).decode(plain)
  } catch { throw new Error('Cannot decrypt backup: incorrect password or damaged file.') }
}
