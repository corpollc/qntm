/** Browser host for authenticated ordinary groups. Protocol rules live in qntm. */
import {
  base64UrlDecode, base64UrlEncode, keyIDFromPublicKey, validateIdentity, QSP1Suite,
  createInvite, deriveConversationKeys, createConversation, addParticipant, createGroupGenesisBody,
  parseGroupGenesisBody, GroupState, createGroupSession, restoreGroupSession,
  groupSessionConversation, createGroupControlMessage, createGroupRemoveBody, parseGroupRemoveBody,
  prepareGroupSessionAddition, prepareGroupSessionRekey, prepareGroupWelcomeRefresh, prepareGroupAdmissionRenewal,
  assertGroupAdditionAccepted, assertGroupWelcomeRefreshCurrent, assertGroupAdmissionRenewalCurrent, assertGroupCanSend,
  receiveGroupEvent, checkGroupReplayCoverage, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch, checkExpiredGroupControl, requireGroupRecovery,
  createGroupLink, parseGroupLink, openGroupWelcome, groupSessionFromWelcome,
  serializeEnvelope, deserializeEnvelope, isGroupWelcomeEnvelope, createMessage, defaultTTL, DropboxClient,
} from '@corpollc/qntm'
import type { Identity, GroupSessionState, GroupAddition, GroupWelcomeRefresh, GroupAdmissionRenewal, SubscriptionMessage } from '@corpollc/qntm'
import * as store from './store'
import { groupAdditionIntent, groupAdditionChallenge, groupRenewalChallenge, groupRefreshIntent, sameGroupOperationValue,
  appendGroupOperationEvidence, assertGroupOperationEvidenceBudget, groupRemovalTarget, assertGroupRemovalTargetCurrent } from './group-operation'

export const hex = (value: Uint8Array) => Array.from(value, b => b.toString(16).padStart(2, '0')).join('')
export function bytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(value)) throw new Error('Invalid hexadecimal value')
  return Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16))
}
function identityFor(profile: string): Identity {
  const saved = store.getIdentity(profile)
  if (!saved) throw new Error('Create an identity first')
  const identity = { privateKey: bytes(saved.privateKey), publicKey: bytes(saved.publicKey), keyID: bytes(saved.keyId) }
  validateIdentity(identity)
  return identity
}
const suite = new QSP1Suite()
const groupState = (session: GroupSessionState) => { const state = new GroupState(); state.applyGenesis(parseGroupGenesisBody(base64UrlDecode(session.snapshot))); return state }
const queues = new Map<string, Promise<unknown>>()
/** Web Locks serialize tabs; the fallback also serializes one JS realm in tests. */
export async function withGroupLock<T>(profile: string, id: string, action: () => Promise<T>): Promise<T> {
  const name = `qntm-group:${profile}:${id}`
  if (globalThis.navigator?.locks) return navigator.locks.request(name, action)
  if (typeof window !== 'undefined') throw new Error('This browser needs Web Locks support to safely update contact groups across tabs')
  const pending = (queues.get(name) ?? Promise.resolve()).catch(() => {}).then(action)
  queues.set(name, pending)
  try { return await pending } finally { if (queues.get(name) === pending) queues.delete(name) }
}
function load(profile: string, id: string): store.StoredConversation & { group: store.StoredGroup } {
  const record = store.findConversation(profile, id)
  if (!record?.group) throw new Error('This conversation has no authenticated contact-group checkpoint')
  if (record.gateway) throw new Error('Gateway groups use gateway governance; contact-group operations are unavailable')
  record.group.session = restoreGroupSession(identityFor(profile), record.group.session)
  if (record.group.session.conversationId !== id) throw new Error('Group checkpoint does not match this conversation')
  return record as store.StoredConversation & { group: store.StoredGroup }
}
function save(profile: string, record: store.StoredConversation & { group: store.StoredGroup }, history = store.getHistory(profile, record.id)) {
  const expected = record.group.revision
  const conv = groupSessionConversation(record.group.session)
  record.keys = { root: hex(conv.keys.root), aeadKey: hex(conv.keys.aeadKey), nonceKey: hex(conv.keys.nonceKey) }
  record.currentEpoch = conv.currentEpoch
  record.participants = conv.participants.map(hex)
  record.participantPublicKeys = groupState(record.group.session).snapshot().founding_members.map(m => hex(m.public_key))
  record.group.revision++
  store.commitGroup(profile, record, history, expected)
}
export function pinContact(profile: string, name: string, publicKey: string) {
  if (!name.trim() || name.trim().length > 128) throw new Error('Enter a contact name of at most 128 characters')
  const key = /^[0-9a-fA-F]{64}$/.test(publicKey.trim()) ? bytes(publicKey.trim()) : base64UrlDecode(publicKey.trim())
  // The group-link validator uses the shared strict Ed25519 public-key validator.
  createGroupLink({ conversationId: new Uint8Array(16), inviterPublicKey: key, relayUrl: store.getDropboxUrl() })
  store.saveContactPin(profile, hex(keyIDFromPublicKey(key)), hex(key), name.trim())
}
function contactKey(profile: string, keyId: string) {
  const contact = store.listContactPins(profile).find(c => c.key === keyId)
  if (!contact) throw new Error('Pin and verify this contact’s full public key first')
  return bytes(contact.publicKey)
}
function challengeBytes(challenge?: string) {
  if (!challenge?.trim()) return undefined
  if (!/^[0-9a-fA-F]{64}$/.test(challenge.trim())) throw new Error('Recovery challenge must be 64 hexadecimal characters')
  return bytes(challenge.trim())
}
export function publicGroupLink(profile: string, id: string): string {
  const record = load(profile, id)
  return createGroupLink({ conversationId: bytes(id), inviterPublicKey: identityFor(profile).publicKey, relayUrl: record.group.relayUrl })
}
function wireId(wire: string) { return hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id) }
const CONTROL_BODY_TYPES = new Set<store.StoredGroupControlBody>(['group_genesis', 'group_add', 'group_remove', 'group_rekey'])
function controlReceipts(group: store.StoredGroup) {
  return group.controlReceipts ??= []
}
/** Every control the saved journal still relies on: the current controls and,
 * for a repair, the original accepted controls its proof is derived from. */
function journalControls(group: store.StoredGroup) {
  return [...(group.operation?.controls ?? []), ...(group.operation?.origin?.controls ?? [])]
}
function pendingControlIds(group: store.StoredGroup) {
  return new Set(journalControls(group).map(wireId))
}
function latchControlReceipt(group: store.StoredGroup, wire: string, receipt: store.StoredGroupControlReceipt) {
  const rows = controlReceipts(group)
  const existing = rows.find(row => row.id === receipt.id && row.digest === receipt.digest)
  if (existing) {
    if (existing.valid === false) return
    existing.epoch = receipt.epoch; existing.sequence = receipt.sequence; existing.bodyType = receipt.bodyType
    return
  }
  if (!journalControls(group).includes(wire) && !rows.some(row => row.id === receipt.id)) return
  rows.push(receipt)
  const pinned = pendingControlIds(group)
  while (rows.length > store.MAX_GROUP_CONTROL_RECEIPTS) {
    let drop = rows.findIndex(row => !pinned.has(row.id) && row.valid)
    if (drop < 0) drop = rows.findIndex(row => !pinned.has(row.id))
    if (drop < 0) break
    rows.splice(drop, 1)
  }
}
function invalidateControlReceipts(group: store.StoredGroup, afterEpoch = -1, superseded = new Set<string>()) {
  for (const receipt of group.controlReceipts ?? []) {
    if (receipt.epoch > afterEpoch || superseded.has(receipt.id)) receipt.valid = false
  }
}
/** Exact authenticated pending-control proof. Seen is only a bounded cache. */
export function controlAccepted(group: store.StoredGroup, wire: string) {
  const envelope = deserializeEnvelope(base64UrlDecode(wire)), mid = hex(envelope.msg_id), digest = hex(suite.hash(base64UrlDecode(wire)))
  const known = group.session.seen[mid]
  if (known && known.digest !== digest) throw new Error('Saved control conflicts with accepted ciphertext')
  let accepted = false
  for (const receipt of group.controlReceipts ?? []) {
    if (receipt.id !== mid || receipt.digest !== digest) continue
    if (receipt.valid === false) return false
    if (receipt.valid === true && receipt.epoch === envelope.conv_epoch && Number.isSafeInteger(receipt.sequence)
      && receipt.sequence > 0 && receipt.sequence <= group.cursor && CONTROL_BODY_TYPES.has(receipt.bodyType)) accepted = true
  }
  if (accepted) return true
  return Boolean(known && known.epoch === envelope.conv_epoch)
}
function invalidateHistory(history: store.StoredMessage[], afterEpoch = -1) {
  for (const message of history) {
    if (message.groupBinding && message.groupBinding.epoch > afterEpoch) message.groupBinding.valid = false
  }
}
/** Durable history is separate from the bounded cryptographic replay cache. */
export function isCurrentGroupMessage(profile: string, id: string, message: store.StoredMessage): boolean {
  const host = store.findConversation(profile, id)?.group, binding = message.groupBinding
  return !!host && !host.session.recovery && !!binding?.valid && store.getHistory(profile, id).some(saved =>
    saved.id === message.id && saved.groupBinding?.valid === true
      && saved.groupBinding.digest === binding.digest && saved.groupBinding.epoch === binding.epoch)
}

/** Caller holds the group lock. All rows count for coverage, including other
 * recipients' welcomes and unreadable ciphertext; only verified bodies dispatch. */
export function applyGroupBatch(profile: string, id: string, entries: SubscriptionMessage[], head: number, includeBeforeBootstrap = false): store.StoredMessage[] {
  const identity = identityFor(profile), record = load(profile, id), host = record.group
  if (head < host.cursor) return [] // Concurrent catch-up already committed this batch.
  let state = checkGroupReplayCoverage(host.session, host.cursor, head, [...entries.map(e => e.seq), ...host.receipts.filter(seq => seq > host.cursor && seq <= head)])
  const history = store.getHistory(profile, id), delivered: store.StoredMessage[] = []
  const pending = new Map(host.pending.map(row => [`${row.seq}:${row.wire}`, row]))
  for (const row of entries) {
    if (row.seq <= host.bootstrapSequence && !includeBeforeBootstrap) continue
    const wire = base64UrlEncode(row.envelope)
    pending.set(`${row.seq}:${wire}`, { seq: row.seq, wire })
  }
  if (!includeBeforeBootstrap && !state.recovery) {
    // Check the whole queued batch against the saved epoch before any plaintext
    // can become visible. Welcome installation uses its stricter signed-context
    // preflight, which can recognize the exact admission ciphertext.
    for (const row of pending.values()) {
      let envelope
      try { envelope = deserializeEnvelope(base64UrlDecode(row.wire)) } catch { continue }
      if (!isGroupWelcomeEnvelope(envelope)) state = checkGroupUnverifiableEpoch(state, envelope, row.seq)
    }
  }
  let progress = true
  while (progress && !state.recovery) {
    progress = false
    for (const [key, row] of [...pending].sort((a, b) => a[1].seq - b[1].seq)) {
      let envelope
      try { envelope = deserializeEnvelope(base64UrlDecode(row.wire)) } catch { pending.delete(key); continue }
      if (host.operation?.kind === 'create' && host.operation.controls.includes(row.wire)) {
        // Own prepared genesis is trusted local seed state. Seeing its exact wire
        // proves delivery without granting authority to a repeated genesis.
        const digest = hex(suite.hash(base64UrlDecode(row.wire)))
        state.seen[hex(envelope.msg_id)] = { digest, epoch: envelope.conv_epoch }
        latchControlReceipt(host, row.wire, { id: hex(envelope.msg_id), digest, epoch: envelope.conv_epoch, sequence: row.seq, valid: true, bodyType: 'group_genesis' })
        pending.delete(key); continue
      }
      if (isGroupWelcomeEnvelope(envelope)) { pending.delete(key); continue }
      if (!Number.isSafeInteger(envelope.expiry_ts) || !Number.isSafeInteger(envelope.conv_epoch)) { pending.delete(key); continue }
      if (envelope.expiry_ts < Math.floor(Date.now() / 1000)) {
        state = checkExpiredGroupControl(identity, state, envelope, row.seq)
        if (state.recovery) break
        if (envelope.conv_epoch > state.epoch && !state.removed) continue
        pending.delete(key); continue
      }
      try {
        const applied = receiveGroupEvent(identity, envelope, state)
        if (!state.removed && applied.state.removed) host.removedSequence = Math.max(host.removedSequence ?? 0, row.seq)
        if (applied.rewound) {
          const superseded = new Set(state.rekeys.filter(frame => frame.epoch >= envelope.conv_epoch).map(frame => frame.messageId))
          invalidateHistory(history, envelope.conv_epoch)
          invalidateControlReceipts(host, envelope.conv_epoch, superseded)
        }
        state = applied.rewound ? requireGroupRecovery(applied.state, Math.max(row.seq, head), 'missing_history') : applied.state
        pending.delete(key)
        progress = true
        if (state.recovery) break
        if (!applied.duplicate) {
          const inner = applied.message.inner, type = inner.body_type
          if (CONTROL_BODY_TYPES.has(type as store.StoredGroupControlBody)) {
            latchControlReceipt(host, row.wire, { id: hex(envelope.msg_id), digest: hex(suite.hash(base64UrlDecode(row.wire))),
              epoch: envelope.conv_epoch, sequence: row.seq, valid: true, bodyType: type as store.StoredGroupControlBody })
          }
          if (!type.startsWith('group_')) {
            const msg: store.StoredMessage = { id: hex(envelope.msg_id), conversationId: id,
              direction: hex(inner.sender_kid) === hex(identity.keyID) ? 'outgoing' : 'incoming',
              sender: hex(inner.sender_kid), senderKey: hex(inner.sender_kid), bodyType: type,
              text: new TextDecoder().decode(inner.body), createdAt: new Date(envelope.created_ts * 1000).toISOString(),
              groupBinding: { digest: hex(suite.hash(base64UrlDecode(row.wire))), epoch: envelope.conv_epoch, valid: true } }
            const same = history.find(existing => existing.id === msg.id && existing.groupBinding?.valid
              && existing.groupBinding.digest === msg.groupBinding!.digest && existing.groupBinding.epoch === msg.groupBinding!.epoch)
            if (!same) {
              for (const existing of history) if (existing.id === msg.id && existing.groupBinding) existing.groupBinding.valid = false
              history.push(msg); delivered.push(msg)
            }
          }
        }
      } catch {
        // Future keys or a competing rekey may make this readable in another pass.
        const accepted = state.seen[hex(envelope.msg_id)]
        if (envelope.conv_epoch < state.epoch || state.removed
          || accepted && accepted.digest !== hex(suite.hash(base64UrlDecode(row.wire)))) pending.delete(key)
      }
    }
  }
  if (state.recovery) pending.clear()
  const waiting = [...pending.values()]
  if (waiting.length > 256 || waiting.reduce((n, row) => n + base64UrlDecode(row.wire).length, 0) > 4 * 1024 * 1024) throw new Error('Pending group ciphertext limit reached; receive progress was not saved')
  host.session = state; host.cursor = head; host.pending = waiting; host.receipts = host.receipts.filter(seq => seq > head)
  save(profile, record, history)
  return state.recovery ? [] : delivered
}
async function syncUnlocked(profile: string, id: string) {
  const record = load(profile, id)
  const batch = await new DropboxClient(record.group.relayUrl).receiveMessages(bytes(id), record.group.operation?.kind === 'create' ? 0 : record.group.cursor)
  if (batch.sequence < record.group.cursor) throw new Error('Relay head moved behind saved group history')
  return applyGroupBatch(profile, id, batch.entries, batch.sequence)
}
export function syncContactGroup(profile: string, id: string) { return withGroupLock(profile, id, () => syncUnlocked(profile, id)) }
function operationValue(op: store.StoredGroupOperation): GroupAddition | GroupWelcomeRefresh | GroupAdmissionRenewal {
  const conversation = groupSessionConversation(op.expected), state = groupState(op.expected)
  const welcomes = op.welcomes.map(wire => deserializeEnvelope(base64UrlDecode(wire)) as GroupAddition['welcomes'][number])
  if (op.kind === 'addition') return { conversation, state, welcomes,
    addition: deserializeEnvelope(base64UrlDecode(op.controls[0])), rekey: deserializeEnvelope(base64UrlDecode(op.controls[1])) }
  if (op.kind === 'renewal') return { conversation, state, welcomes, recipient: bytes(op.recipient),
    admission: op.admission, admissions: op.expected.admissions }
  return { conversation, state, welcomes }
}
function operationRecord(profile: string, id: string, op: store.StoredGroupOperation) {
  const record = load(profile, id)
  if (!sameGroupOperationValue(record.group.operation, op)) throw new Error('The saved operation changed; retry against its latest progress')
  return record
}
type AdditionOperation = Extract<store.StoredGroupOperation, { kind: 'addition' | 'addition_rekey' }>
function additionProof(identity: Identity, record: ReturnType<typeof load>, op: AdditionOperation) {
  const intent = groupAdditionIntent(identity, op), accepted = record.group.session.admissions[intent.kid]
  return { ...intent, accepted: accepted && accepted.addId === intent.proof.addId && accepted.addDigest === intent.proof.addDigest ? accepted : undefined }
}
function assertExactAdditionCurrent(identity: Identity, record: ReturnType<typeof load>, op: Extract<store.StoredGroupOperation, { kind: 'addition' }>) {
  const proof = additionProof(identity, record, op)
  if (!proof.accepted?.completion || proof.accepted.completion.rekeyId !== hex(proof.rekey.msg_id)
    || proof.accepted.completion.rekeyDigest !== hex(suite.hash(proof.rekeyWire))) throw new Error('Original completing rekey is no longer canonical')
  assertGroupWelcomeRefreshCurrent(identity, record.group.session, operationValue(op))
}
function assertPendingRotationCurrent(identity: Identity, record: ReturnType<typeof load>, op: AdditionOperation, proof = additionProof(identity, record, op)) {
  const state = record.group.session
  assertGroupCanSend(identity, { ...state, needsRekey: false })
  if (!proof.accepted || proof.accepted.completion || !state.needsRekey || proof.accepted.sourceEpoch !== state.epoch) throw new Error('Admission is not awaiting its completing rotation')
  const envelope = deserializeEnvelope(base64UrlDecode(op.controls[op.kind === 'addition' ? 1 : 0]))
  if (envelope.expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('Saved completing rotation expired')
  const trial = receiveGroupEvent(identity, envelope, state).state
  if (trial.root !== op.expected.root || trial.snapshot !== op.expected.snapshot || trial.epoch !== op.expected.epoch) {
    throw new Error('Saved rotation differs from the current roster; its operation is preserved')
  }
}
function additionOrigin(op: AdditionOperation, intent: ReturnType<typeof additionProof>, challenge: string | null): store.StoredGroupAdditionOrigin {
  return op.kind === 'addition_rekey' ? structuredClone(op.origin) : { kind: 'addition', controls: [...op.controls], welcomes: [...op.welcomes], delivered: op.delivered,
    recipient: hex(intent.recipient), admission: intent.proof, recoveryChallenge: challenge, delivery: 'unknown' }
}
function currentRefreshIntent(identity: Identity, record: ReturnType<typeof load>, op: Extract<store.StoredGroupOperation, { kind: 'refresh' }>) {
  assertGroupCanSend(identity, record.group.session)
  const intent = groupRefreshIntent(identity, op)
  if (!parseGroupGenesisBody(base64UrlDecode(record.group.session.snapshot)).founding_members.some(member => hex(member.public_key) === hex(intent.recipient))) {
    throw new Error('Original refresh recipient is no longer a current member; operation preserved')
  }
  return intent
}
function reconcileRefresh(profile: string, id: string, op: Extract<store.StoredGroupOperation, { kind: 'refresh' }>) {
  const record = operationRecord(profile, id, op), identity = identityFor(profile), state = record.group.session
  const intent = currentRefreshIntent(identity, record, op)
  try { assertGroupWelcomeRefreshCurrent(identity, state, operationValue(op)); return op } catch { /* Replace only stale generic delivery. */ }
  const refreshed = prepareGroupWelcomeRefresh(identity, state, [intent.recipient], undefined,
    intent.challenge ? bytes(intent.challenge) : undefined, record.group.cursor)
  const next: typeof op = { kind: 'refresh', controls: [], welcomes: refreshed.welcomes.map(welcome => base64UrlEncode(serializeEnvelope(welcome))), delivered: 0,
    recipient: hex(intent.recipient), recoveryChallenge: intent.challenge,
    expected: createGroupSession(identity, refreshed.conversation, refreshed.state, { signedEpoch: state.signedEpoch, admissions: state.admissions }),
    superseded: appendGroupOperationEvidence(op) }
  record.group.operation = next; save(profile, record)
  return next
}
function reconcileRenewal(profile: string, id: string, op: Extract<store.StoredGroupOperation, { kind: 'renewal' }>) {
  const record = operationRecord(profile, id, op), identity = identityFor(profile), state = record.group.session
  assertGroupCanSend(identity, state)
  const recipient = bytes(op.recipient), admission = state.admissions[hex(keyIDFromPublicKey(recipient))]
  if (!admission?.completion || admission.addId !== op.admission.addId || admission.addDigest !== op.admission.addDigest) {
    throw new Error('Original addition is no longer the accepted admission; its operation is preserved')
  }
  try { assertGroupAdmissionRenewalCurrent(identity, state, operationValue(op) as GroupAdmissionRenewal); return op } catch { /* Replace only stale current-admission delivery. */ }
  const challenge = groupRenewalChallenge(identity, op)
  const renewed = prepareGroupAdmissionRenewal(identity, state, recipient, { addId: op.admission.addId, addDigest: op.admission.addDigest }, undefined,
    challenge ? bytes(challenge) : undefined, record.group.cursor)
  const next: typeof op = { ...op, welcomes: renewed.welcomes.map(welcome => base64UrlEncode(serializeEnvelope(welcome))), delivered: 0,
    expected: createGroupSession(identity, renewed.conversation, renewed.state, { signedEpoch: state.signedEpoch, admissions: renewed.admissions }),
    admission: renewed.admission, superseded: appendGroupOperationEvidence(op) }
  record.group.operation = next; save(profile, record)
  return next
}
type RemovalOperation = Extract<store.StoredGroupOperation, { kind: 'remove' | 'removal_rekey' }>
/** Prove the original removal only from exact authenticated receive evidence. */
function removalProof(record: ReturnType<typeof load>, op: RemovalOperation) {
  const intent = op.kind === 'removal_rekey' ? op.origin : op
  if (intent.kind !== 'remove' || intent.controls.length !== 2 || intent.welcomes.length) throw new Error('Invalid saved removal shape')
  const wire = base64UrlDecode(intent.controls[0]), removal = deserializeEnvelope(wire)
  if (!sameGroupOperationValue(serializeEnvelope(removal), wire) || hex(removal.conv_id) !== record.id) throw new Error('Invalid saved removal context')
  return { accepted: controlAccepted(record.group, intent.controls[0]), source: removal.conv_epoch, removal, wire }
}
/** An accepted removal is finished once any verified rotation left its source epoch. */
function removalCompleted(record: ReturnType<typeof load>, op: RemovalOperation) {
  const proof = removalProof(record, op)
  return proof.accepted && record.group.session.epoch > proof.source
}
/** Exact saved rotation ciphertext stays exact only while it still applies. */
function assertRotationCurrent(identity: Identity, state: GroupSessionState, wire: string, expected: GroupSessionState) {
  const envelope = deserializeEnvelope(base64UrlDecode(wire))
  if (envelope.expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('Saved rotation expired')
  if (envelope.conv_epoch !== state.epoch) throw new Error('Saved control belongs to an older group epoch; its operation is preserved')
  const trial = receiveGroupEvent(identity, envelope, state).state
  if (trial.root !== expected.root || trial.snapshot !== expected.snapshot || trial.epoch !== expected.epoch) {
    throw new Error('Saved rotation differs from the current roster; its operation is preserved')
  }
}
function rotationJournal(identity: Identity, state: GroupSessionState) {
  const rotation = prepareGroupSessionRekey(identity, state), trial = receiveGroupEvent(identity, rotation.rekey, state).state
  return { controls: [base64UrlEncode(serializeEnvelope(rotation.rekey))], welcomes: [] as string[], delivered: 0,
    expected: createGroupSession(identity, rotation.conversation, rotation.state, { signedEpoch: state.signedEpoch, admissions: trial.admissions }) }
}
/** Finish an accepted removal from current membership; never re-remove. Returns
 * null once a verified rotation already left the removal's source epoch. */
function reconcileRemoval(profile: string, id: string, op: RemovalOperation): store.StoredGroupOperation | null {
  const record = operationRecord(profile, id, op), identity = identityFor(profile), state = record.group.session
  const proof = removalProof(record, op)
  if (!proof.accepted) {
    // Absent targets, predicted roots and acknowledgements prove nothing. A
    // same-epoch, unexpired removal keeps its exact bytes for retry.
    if (op.kind === 'removal_rekey') throw new Error('Original removal is no longer verified in current history; its operation is preserved')
    if (state.epoch !== proof.source) throw new Error('Saved removal was superseded before its acceptance was verified; its operation is preserved')
    if (proof.removal.expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('Saved removal expired before its acceptance was verified; its operation is preserved')
    try { receiveGroupEvent(identity, proof.removal, state) } catch (error) {
      if (error instanceof Error && /Stale|epoch|member|Invalid/.test(error.message)) throw error
      throw new Error('Saved removal cannot be verified against the current branch; its operation is preserved')
    }
    return op
  }
  if (state.epoch > proof.source) return null
  if (!state.needsRekey) throw new Error('Accepted removal is not awaiting its completing rotation; its operation is preserved')
  assertGroupCanSend(identity, { ...state, needsRekey: false })
  try { assertRotationCurrent(identity, state, op.controls[op.kind === 'remove' ? 1 : 0], op.expected); return op } catch { /* Expired, other branch or changed roster: stage a current rotation. */ }
  const origin: store.StoredGroupRemovalOrigin = op.kind === 'removal_rekey' ? structuredClone(op.origin)
    : { kind: 'remove', controls: [...op.controls], welcomes: [], delivered: op.delivered, ...(op.target ? { target: structuredClone(op.target) } : {}), delivery: 'unknown' }
  const superseded = op.kind === 'removal_rekey' ? appendGroupOperationEvidence(op) : []
  assertGroupOperationEvidenceBudget(origin, superseded)
  const next: store.StoredGroupOperation = { kind: 'removal_rekey', ...rotationJournal(identity, state), origin, ...(superseded.length ? { superseded } : {}) }
  record.group.operation = next; save(profile, record)
  return next
}
/** Keep an exact rotation, finish a superseded one, or renew a still-current intent. */
function reconcileRotation(profile: string, id: string, op: Extract<store.StoredGroupOperation, { kind: 'rekey' }>): store.StoredGroupOperation | null {
  const record = operationRecord(profile, id, op), identity = identityFor(profile), state = record.group.session
  if (op.controls.length !== 1 || op.welcomes.length) throw new Error('Invalid saved rotation shape')
  const wire = base64UrlDecode(op.controls[0]), envelope = deserializeEnvelope(wire)
  if (!sameGroupOperationValue(serializeEnvelope(envelope), wire) || hex(envelope.conv_id) !== record.id) throw new Error('Invalid saved rotation context')
  if (controlAccepted(record.group, op.controls[0])) return op
  assertGroupCanSend(identity, { ...state, needsRekey: false })
  if (state.epoch > envelope.conv_epoch) return null // Any verified later rotation fulfils a standalone rotation intent.
  try { assertRotationCurrent(identity, state, op.controls[0], op.expected); return op } catch { /* Expired, other branch or changed roster: stage a current rotation. */ }
  const superseded = appendGroupOperationEvidence(op)
  const next: store.StoredGroupOperation = { kind: 'rekey', ...rotationJournal(identity, state), superseded }
  record.group.operation = next; save(profile, record)
  return next
}
/** Called under the shared Web Lock immediately before a repair rotation POST. */
function shouldPostRemovalRekey(identity: Identity, record: ReturnType<typeof load>, op: Extract<store.StoredGroupOperation, { kind: 'removal_rekey' }>) {
  const state = record.group.session, proof = removalProof(record, op)
  if (!proof.accepted) throw new Error('Original removal is no longer verified in current history; its operation is preserved')
  if (state.epoch > proof.source) return false // Another member's verified rotation finished the removal.
  if (state.epoch !== proof.source || !state.needsRekey) throw new Error('Accepted removal is not awaiting its completing rotation; its operation is preserved')
  assertGroupCanSend(identity, { ...state, needsRekey: false })
  assertRotationCurrent(identity, state, op.controls[0], op.expected)
  return true
}
function reconcileAddition(profile: string, id: string, op: store.StoredGroupOperation): store.StoredGroupOperation | null {
  if (op.kind === 'refresh') return reconcileRefresh(profile, id, op)
  if (op.kind === 'renewal') return reconcileRenewal(profile, id, op)
  if (op.kind === 'remove' || op.kind === 'removal_rekey') return reconcileRemoval(profile, id, op)
  if (op.kind === 'rekey') return reconcileRotation(profile, id, op)
  if (op.kind !== 'addition' && op.kind !== 'addition_rekey') return op
  const record = operationRecord(profile, id, op), identity = identityFor(profile), state = record.group.session
  const intent = additionProof(identity, record, op)
  if (!intent.accepted) {
    if (op.kind === 'addition_rekey' || state.epoch > intent.addition.conv_epoch || state.needsRekey || state.admissions[intent.kid]) {
      throw new Error('Original addition is no longer the accepted admission; its operation is preserved')
    }
    return op
  }
  if (!intent.accepted.completion) {
    assertGroupCanSend(identity, { ...state, needsRekey: false })
    if (!state.needsRekey || intent.accepted.sourceEpoch !== state.epoch) throw new Error('Admission is not awaiting its completing rotation')
    try { assertPendingRotationCurrent(identity, record, op, intent); return op } catch { /* Expired or changed roster; stage a new current rotation. */ }
    const challenge = groupAdditionChallenge(identity, op, intent), rotation = prepareGroupSessionRekey(identity, state)
    const trial = receiveGroupEvent(identity, rotation.rekey, state).state, origin = additionOrigin(op, intent, challenge)
    const superseded = op.kind === 'addition_rekey' ? appendGroupOperationEvidence(op) : []
    assertGroupOperationEvidenceBudget(origin, superseded)
    const next: store.StoredGroupOperation = { kind: 'addition_rekey', controls: [base64UrlEncode(serializeEnvelope(rotation.rekey))], welcomes: [], delivered: 0,
      expected: createGroupSession(identity, rotation.conversation, rotation.state, { signedEpoch: state.signedEpoch, admissions: trial.admissions }),
      recipient: hex(intent.recipient), origin, ...(superseded.length ? { superseded } : {}) }
    record.group.operation = next; save(profile, record)
    return next
  }
  assertGroupCanSend(identity, state)
  if (op.kind === 'addition') try { assertExactAdditionCurrent(identity, record, op); return op } catch { /* Current keys or delivery window changed. */ }
  const challenge = groupAdditionChallenge(identity, op, intent)
  const renewed = prepareGroupAdmissionRenewal(identity, state, intent.recipient, intent.proof, undefined,
    challenge ? bytes(challenge) : undefined, record.group.cursor)
  const next: store.StoredGroupOperation = { kind: 'renewal', controls: [], delivered: 0,
    welcomes: renewed.welcomes.map(welcome => base64UrlEncode(serializeEnvelope(welcome))),
    expected: createGroupSession(identity, renewed.conversation, renewed.state, { signedEpoch: state.signedEpoch, admissions: renewed.admissions }),
    recipient: hex(intent.recipient), admission: renewed.admission,
    origin: additionOrigin(op, intent, challenge), ...(op.kind === 'addition_rekey' ? { superseded: appendGroupOperationEvidence(op) } : {}) }
  assertGroupOperationEvidenceBudget(next.origin, next.superseded ?? [])
  record.group.operation = next; save(profile, record)
  return next
}
/** Called under the shared Web Lock immediately before a control POST. */
function shouldPostControl(identity: Identity, record: ReturnType<typeof load>, op: store.StoredGroupOperation, wire: string) {
  const state = record.group.session, envelope = deserializeEnvelope(base64UrlDecode(wire))
  assertGroupCanSend(identity, { ...state, needsRekey: false })
  if (op.kind === 'addition' || op.kind === 'addition_rekey') {
    const proof = additionProof(identity, record, op)
    if (op.kind === 'addition' && wire === op.controls[0]) {
      if (proof.accepted) return false
      if (state.needsRekey || state.epoch !== envelope.conv_epoch || state.admissions[proof.kid]) {
        throw new Error('Original addition is no longer safe to publish; its operation is preserved')
      }
    } else {
      if (!proof.accepted) throw new Error('Original addition is no longer the accepted admission')
      if (proof.accepted.completion) return false
      assertPendingRotationCurrent(identity, record, op, proof)
    }
  }
  if (controlAccepted(record.group, wire)) return false
  if (envelope.expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('The saved operation expired; its ciphertext is retained for recovery')
  if (!['addition', 'addition_rekey', 'create'].includes(op.kind) && envelope.conv_epoch !== state.epoch) {
    throw new Error('Saved control belongs to an older group epoch; its operation is preserved')
  }
  if (op.kind !== 'create') {
    const applied = receiveGroupEvent(identity, envelope, state)
    if (op.kind === 'remove' && !applied.duplicate && applied.message.inner.body_type === 'group_remove') {
      assertGroupRemovalTargetCurrent(state, op.target, parseGroupRemoveBody(applied.message.inner.body).removed_members.map(hex))
    }
  }
  return true
}
function finishOperation(profile: string, id: string, op: store.StoredGroupOperation) {
  const record = operationRecord(profile, id, op)
  record.group.operation = null; save(profile, record)
  return publicGroupLink(profile, id)
}
async function resumeUnlocked(profile: string, id: string, reconcile = false): Promise<string> {
  let record = load(profile, id), op = record.group.operation
  if (!op) return publicGroupLink(profile, id)
  // Delivery is already acknowledged. Cleanup must not depend on later expiry,
  // removal or recovery, and does not release any additional ciphertext.
  if (op.welcomes.length > 0 && op.delivered === op.welcomes.length) return finishOperation(profile, id, op)
  await syncUnlocked(profile, id)
  record = operationRecord(profile, id, op)
  if (record.group.session.recovery) throw new Error('Recover missing group history before retrying this operation')
  if (record.group.session.removed) throw new Error('You have been removed from this group')
  const identity = identityFor(profile)
  if (reconcile) {
    const next = reconcileAddition(profile, id, op)
    if (!next) return finishOperation(profile, id, op) // Verified later rotation already fulfilled this intent.
    op = next
  }
  const dropbox = new DropboxClient(record.group.relayUrl)
  const removalFinished = (current: ReturnType<typeof load>, saved: store.StoredGroupOperation) =>
    (saved.kind === 'remove' || saved.kind === 'removal_rekey') && removalCompleted(current, saved)
  for (const wire of op.controls) {
    record = operationRecord(profile, id, op)
    if (op.kind === 'removal_rekey' ? !shouldPostRemovalRekey(identity, record, op) : !shouldPostControl(identity, record, op, wire)) continue
    const seq = await dropbox.postMessage(bytes(id), base64UrlDecode(wire))
    record = operationRecord(profile, id, op)
    if (op.kind === 'create') { record.group.receipts.push(seq); save(profile, record) }
    await syncUnlocked(profile, id); record = operationRecord(profile, id, op)
    if (op.kind === 'addition' || op.kind === 'addition_rekey') {
      const proof = additionProof(identity, record, op)
      if (proof.accepted && (op.kind === 'addition' && wire === op.controls[0] || proof.accepted.completion)) continue
    }
    if (wire === op.controls.at(-1) && removalFinished(record, op)) continue // A helper's verified rotation may have finished the accepted removal.
    if (!controlAccepted(record.group, wire)) throw new Error('The relay has not replayed the saved control; retry this operation')
  }
  if (reconcile && (op.kind === 'addition' || op.kind === 'addition_rekey')) op = reconcileAddition(profile, id, op)!
  if (op.kind === 'addition_rekey') throw new Error('Completing rotation is not yet verified in relay replay; retry this operation')
  record = operationRecord(profile, id, op)
  const controlsAccepted = op.controls.every(wire => controlAccepted(record.group, wire)) || removalFinished(record, op)
  if (!op.welcomes.length && !controlsAccepted && (record.group.session.root !== op.expected.root || record.group.session.snapshot !== op.expected.snapshot || record.group.session.epoch !== op.expected.epoch)) {
    throw new Error('Saved operation no longer matches the accepted group state')
  }
  for (let index = op.delivered; index < op.welcomes.length; index++) {
    record = operationRecord(profile, id, op)
    const wire = op.welcomes[index]
    if (deserializeEnvelope(base64UrlDecode(wire)).expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('The saved welcome expired; ask a current member to refresh it')
    if (op.kind === 'renewal') assertGroupAdmissionRenewalCurrent(identity, record.group.session, operationValue(op) as GroupAdmissionRenewal)
    else if (op.kind === 'addition' && reconcile) assertExactAdditionCurrent(identity, record, op)
    else if (op.kind === 'addition') assertGroupAdditionAccepted(identity, record.group.session, operationValue(op) as GroupAddition)
    else if (op.kind === 'refresh') { currentRefreshIntent(identity, record, op); assertGroupWelcomeRefreshCurrent(identity, record.group.session, operationValue(op)) }
    const seq = await dropbox.postMessage(bytes(id), base64UrlDecode(wire))
    record = operationRecord(profile, id, op)
    record.group.receipts.push(seq); record.group.operation!.delivered = index + 1; save(profile, record)
    op = record.group.operation!
  }
  return finishOperation(profile, id, op)
}
export function retryContactGroup(profile: string, id: string) { return withGroupLock(profile, id, () => resumeUnlocked(profile, id, true)) }
export async function createContactGroup(profile: string, name: string): Promise<string> {
  const identity = identityFor(profile), invite = createInvite(identity, 'group'), conversation = createConversation(invite, deriveConversationKeys(invite))
  addParticipant(conversation, identity.publicKey)
  const genesis = createGroupGenesisBody(name.trim() || 'Contact group', '', identity, []), state = new GroupState()
  state.applyGenesis(parseGroupGenesisBody(genesis))
  const session = createGroupSession(identity, conversation, state), id = hex(conversation.id)
  const envelope = createGroupControlMessage(identity, conversation, 'group_genesis', genesis, defaultTTL())
  const group: store.StoredGroup = { session, cursor: 0, bootstrapSequence: 0, pending: [], receipts: [], controlReceipts: [], revision: 0,
    operation: { kind: 'create', controls: [base64UrlEncode(serializeEnvelope(envelope))], welcomes: [], delivered: 0, expected: session },
    relayUrl: store.getDropboxUrl(), inviterPublicKey: hex(identity.publicKey) }
  store.commitGroup(profile, { id, name: name.trim() || 'Contact group', type: 'group', keys: { root: hex(conversation.keys.root), aeadKey: hex(conversation.keys.aeadKey), nonceKey: hex(conversation.keys.nonceKey) }, participants: [hex(identity.keyID)], participantPublicKeys: [hex(identity.publicKey)], currentEpoch: 0, createdAt: new Date().toISOString(), group }, [])
  await retryContactGroup(profile, id)
  return id
}
export async function changeContactGroup(profile: string, id: string, action: 'add' | 'remove' | 'refresh' | 'rekey', contact?: string, challenge?: string): Promise<string> {
  return withGroupLock(profile, id, async () => {
    await syncUnlocked(profile, id)
    const record = load(profile, id), identity = identityFor(profile), session = record.group.session
    if (record.group.operation) throw new Error('Retry the saved group operation before starting another')
    const controls = [], welcomes = []
    let expected = session
    let renewal: GroupAdmissionRenewal | undefined, target: store.StoredGroupRemovalTarget | undefined
    if (action === 'add') {
      const op = prepareGroupSessionAddition(identity, session, [contactKey(profile, contact!)], undefined, challengeBytes(challenge), record.group.cursor)
      controls.push(op.addition, op.rekey); welcomes.push(...op.welcomes)
    } else if (action === 'refresh') {
      const recipient = contactKey(profile, contact!), admission = session.admissions[hex(keyIDFromPublicKey(recipient))]
      const op = admission?.completion
        ? (renewal = prepareGroupAdmissionRenewal(identity, session, recipient,
          { addId: admission.addId, addDigest: admission.addDigest }, undefined, challengeBytes(challenge), record.group.cursor))
        : prepareGroupWelcomeRefresh(identity, session, [recipient], undefined, challengeBytes(challenge), record.group.cursor)
      welcomes.push(...op.welcomes)
    } else if (action === 'remove') {
      assertGroupCanSend(identity, session)
      const key = keyIDFromPublicKey(contactKey(profile, contact!))
      const remove = createGroupControlMessage(identity, groupSessionConversation(session), 'group_remove', createGroupRemoveBody([key], 'Removed by a group member'))
      controls.push(remove)
      expected = receiveGroupEvent(identity, remove, session).state
      target = groupRemovalTarget(session, hex(key))
      controls.push(prepareGroupSessionRekey(identity, expected).rekey)
    } else controls.push(prepareGroupSessionRekey(identity, session).rekey)
    expected = session
    for (const control of controls) expected = receiveGroupEvent(identity, control, expected).state
    const operation = { controls: controls.map(c => base64UrlEncode(serializeEnvelope(c))), welcomes: welcomes.map(c => base64UrlEncode(serializeEnvelope(c))), delivered: 0, expected }
    record.group.operation = renewal
      ? { ...operation, kind: 'renewal', recipient: hex(renewal.recipient), admission: renewal.admission }
      : action === 'add' ? { ...operation, kind: 'addition', recipient: hex(contactKey(profile, contact!)), recoveryChallenge: challengeBytes(challenge) ? challenge!.trim().toLowerCase() : null }
      : action === 'refresh' ? { ...operation, kind: 'refresh', recipient: hex(contactKey(profile, contact!)), recoveryChallenge: challengeBytes(challenge) ? challenge!.trim().toLowerCase() : null }
      : action === 'remove' ? { ...operation, kind: 'remove', target }
      : { ...operation, kind: 'rekey' }
    save(profile, record)
    return resumeUnlocked(profile, id)
  })
}
export async function openContactGroup(profile: string, link: string, name = ''): Promise<string> {
  const locator = parseGroupLink(link), id = hex(locator.conversationId), identity = identityFor(profile)
  return withGroupLock(profile, id, async () => {
    const existing = store.findConversation(profile, id)
    if (existing && !existing.group) throw new Error('This group is already saved using an older membership flow')
    if (existing?.gateway) throw new Error('Gateway groups must use their governance flow')
    if (existing?.group && existing.group.relayUrl !== locator.relayUrl) throw new Error('Group link changes the saved relay; verify the destination before migrating')
    const batch = await new DropboxClient(locator.relayUrl).receiveMessages(locator.conversationId, 0)
    // Rows at or before the saved cursor were already covered by the replay that
    // committed it; re-feeding them cannot add coverage and would re-run the
    // unverifiable-epoch preflight on this member's own consumed admission rows.
    if (existing?.group) applyGroupBatch(profile, id, batch.entries.filter(row => row.seq > existing.group!.cursor), batch.sequence)
    const previous = store.findConversation(profile, id)
    if (previous?.group && !previous.group.session.recovery && !previous.group.session.removed && !previous.group.session.needsRekey) return id
    const candidates = []
    for (const entry of batch.entries) {
      try { candidates.push({ entry, welcome: openGroupWelcome(identity, entry.envelope, locator) }) } catch { /* Other recipients, invalid signatures, expired welcomes. */ }
    }
    candidates.sort((a, b) => {
      const epoch = b.welcome.conversation.currentEpoch - a.welcome.conversation.currentEpoch
      if (epoch) return epoch
      const aAddition = a.welcome.purpose === 'addition', bAddition = b.welcome.purpose === 'addition'
      if (aAddition !== bAddition) return aAddition ? 1 : -1
      // Only an addition's own top-level rekey ID participates in canonical
      // ordering. Refresh/renewal provenance describes an older admission.
      if (a.welcome.purpose === 'addition' && b.welcome.purpose === 'addition') {
        const rekey = hex(a.welcome.rekeyId).localeCompare(hex(b.welcome.rekeyId))
        if (rekey) return rekey
      }
      return b.entry.seq - a.entry.seq
    })
    let error: unknown
    for (const { entry, welcome } of candidates) {
      try {
        if (previous?.group?.removedSequence && welcome.purpose === 'addition' && entry.seq <= previous.group.removedSequence) throw new Error('This admission predates your saved removal')
        // Inspect the complete captured replay before storing or dispatching
        // bodies. A new member cannot verify a competing source-epoch rekey
        // using roots from before their admission.
        const session = checkGroupWelcomeReplay(
          groupSessionFromWelcome(identity, welcome, entry.seq, previous?.group?.session),
          welcome, batch.sequence, batch.entries,
        )
        const conv = welcome.conversation
        const group: store.StoredGroup = { session, cursor: welcome.replayFromSequence, bootstrapSequence: welcome.replayFromSequence, removedSequence: previous?.group?.removedSequence,
          pending: [], receipts: previous?.group?.receipts ?? [],
          controlReceipts: (previous?.group?.controlReceipts ?? []).map(row => ({ ...row, valid: false })),
          operation: previous?.group?.operation ?? null,
          relayUrl: locator.relayUrl, inviterPublicKey: hex(locator.inviterPublicKey), revision: (previous?.group?.revision ?? -1) + 1 }
        const record: store.StoredConversation = { id, name: name.trim() || previous?.name || welcome.state.snapshot().group_name, type: 'group',
          keys: { root: hex(conv.keys.root), aeadKey: hex(conv.keys.aeadKey), nonceKey: hex(conv.keys.nonceKey) },
          participants: conv.participants.map(hex), participantPublicKeys: welcome.state.snapshot().founding_members.map(m => hex(m.public_key)),
          currentEpoch: conv.currentEpoch, createdAt: previous?.createdAt || new Date().toISOString(), group }
        const history = store.getHistory(profile, id)
        // A replacement checkpoint authenticates current keys, not the lineage
        // of archived plaintext. Keep that archive private without reviving its
        // display/dispatch eligibility merely because an ID appears again.
        invalidateHistory(history)
        store.commitGroup(profile, record, history, previous?.group?.revision)
        applyGroupBatch(profile, id, batch.entries, batch.sequence, true)
        return id
      } catch (e) { error ??= e }
    }
    throw error ?? new Error('No current welcome for this identity; ask the contact who added you to refresh it')
  })
}
export async function sendContactGroupMessage(profile: string, id: string, text: string, bodyType = 'text'): Promise<store.StoredMessage> {
  return withGroupLock(profile, id, async () => {
    await syncUnlocked(profile, id)
    const record = load(profile, id), identity = identityFor(profile)
    if (record.group.operation) throw new Error('Retry the saved group operation before sending')
    assertGroupCanSend(identity, record.group.session)
    if (bodyType.startsWith('gate.') || bodyType.startsWith('gov.') || bodyType.startsWith('group_')) throw new Error('Contact groups use their membership controls; gateway handoff is not available yet')
    const envelope = createMessage(identity, groupSessionConversation(record.group.session), bodyType, new TextEncoder().encode(text), undefined, defaultTTL())
    const seq = await new DropboxClient(record.group.relayUrl).postMessage(bytes(id), serializeEnvelope(envelope))
    const message: store.StoredMessage = { id: hex(envelope.msg_id), conversationId: id, direction: 'outgoing', sender: hex(identity.keyID), senderKey: hex(identity.keyID), bodyType, text, createdAt: new Date(envelope.created_ts * 1000).toISOString(),
      groupBinding: { digest: hex(suite.hash(serializeEnvelope(envelope))), epoch: envelope.conv_epoch, valid: true } }
    record.group.receipts.push(seq)
    save(profile, record, [...store.getHistory(profile, id), message])
    return message
  })
}
