/** Browser host for authenticated ordinary groups. Protocol rules live in qntm. */
import {
  base64UrlDecode, base64UrlEncode, keyIDFromPublicKey, validateIdentity, QSP1Suite,
  createInvite, deriveConversationKeys, createConversation, addParticipant, createGroupGenesisBody,
  parseGroupGenesisBody, GroupState, createGroupSession, restoreGroupSession,
  groupSessionConversation, createGroupControlMessage, createGroupRemoveBody,
  prepareGroupSessionAddition, prepareGroupSessionRekey, prepareGroupWelcomeRefresh, prepareGroupAdmissionRenewal,
  assertGroupAdditionAccepted, assertGroupWelcomeRefreshCurrent, assertGroupAdmissionRenewalCurrent, assertGroupCanSend,
  receiveGroupEvent, checkGroupReplayCoverage, checkGroupWelcomeReplay, checkGroupUnverifiableEpoch, checkExpiredGroupControl, requireGroupRecovery,
  createGroupLink, parseGroupLink, openGroupWelcome, groupSessionFromWelcome,
  serializeEnvelope, deserializeEnvelope, isGroupWelcomeEnvelope, createMessage, defaultTTL, DropboxClient,
} from '@corpollc/qntm'
import type { Identity, GroupSessionState, GroupAddition, GroupWelcomeRefresh, GroupAdmissionRenewal, SubscriptionMessage } from '@corpollc/qntm'
import * as store from './store'

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
function controlAccepted(session: GroupSessionState, wire: string) {
  return session.seen[wireId(wire)]?.digest === hex(suite.hash(base64UrlDecode(wire)))
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
        state.seen[hex(envelope.msg_id)] = { digest: hex(suite.hash(base64UrlDecode(row.wire))), epoch: envelope.conv_epoch }
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
        if (applied.rewound) invalidateHistory(history, envelope.conv_epoch)
        state = applied.rewound ? requireGroupRecovery(applied.state, Math.max(row.seq, head), 'missing_history') : applied.state
        pending.delete(key)
        progress = true
        if (state.recovery) break
        if (!applied.duplicate) {
          const inner = applied.message.inner, type = inner.body_type
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
async function resumeUnlocked(profile: string, id: string): Promise<string> {
  await syncUnlocked(profile, id)
  let record = load(profile, id), op = record.group.operation
  if (!op) return publicGroupLink(profile, id)
  if (record.group.session.recovery) throw new Error('Recover missing group history before retrying this operation')
  if (record.group.session.removed) throw new Error('You have been removed from this group')
  const dropbox = new DropboxClient(record.group.relayUrl)
  for (const wire of op.controls) {
    if (controlAccepted(record.group.session, wire)) continue
    const envelope = deserializeEnvelope(base64UrlDecode(wire))
    if (envelope.expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('The saved operation expired; its ciphertext is retained for recovery')
    const seq = await dropbox.postMessage(bytes(id), base64UrlDecode(wire))
    if (op.kind === 'create') { record.group.receipts.push(seq); save(profile, record) }
    await syncUnlocked(profile, id); record = load(profile, id)
    if (!controlAccepted(record.group.session, wire)) throw new Error('The relay has not replayed the saved control; retry this operation')
  }
  const identity = identityFor(profile)
  if (op.kind === 'addition') assertGroupAdditionAccepted(identity, record.group.session, operationValue(op) as GroupAddition)
  else if (op.kind === 'renewal') assertGroupAdmissionRenewalCurrent(identity, record.group.session, operationValue(op) as GroupAdmissionRenewal)
  else if (op.kind === 'refresh') assertGroupWelcomeRefreshCurrent(identity, record.group.session, operationValue(op))
  else if (record.group.session.root !== op.expected.root || record.group.session.snapshot !== op.expected.snapshot || record.group.session.epoch !== op.expected.epoch) throw new Error('Saved operation no longer matches the accepted group state')
  for (let index = op.delivered; index < op.welcomes.length; index++) {
    const wire = op.welcomes[index]
    if (deserializeEnvelope(base64UrlDecode(wire)).expiry_ts < Math.floor(Date.now() / 1000)) throw new Error('The saved welcome expired; ask a current member to refresh it')
    const seq = await dropbox.postMessage(bytes(id), base64UrlDecode(wire))
    record.group.receipts.push(seq); record.group.operation!.delivered = index + 1; save(profile, record)
  }
  record.group.operation = null; save(profile, record)
  return publicGroupLink(profile, id)
}
export function retryContactGroup(profile: string, id: string) { return withGroupLock(profile, id, () => resumeUnlocked(profile, id)) }
export async function createContactGroup(profile: string, name: string): Promise<string> {
  const identity = identityFor(profile), invite = createInvite(identity, 'group'), conversation = createConversation(invite, deriveConversationKeys(invite))
  addParticipant(conversation, identity.publicKey)
  const genesis = createGroupGenesisBody(name.trim() || 'Contact group', '', identity, []), state = new GroupState()
  state.applyGenesis(parseGroupGenesisBody(genesis))
  const session = createGroupSession(identity, conversation, state), id = hex(conversation.id)
  const envelope = createGroupControlMessage(identity, conversation, 'group_genesis', genesis, defaultTTL())
  const group: store.StoredGroup = { session, cursor: 0, bootstrapSequence: 0, pending: [], receipts: [], revision: 0,
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
    let renewal: GroupAdmissionRenewal | undefined
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
      controls.push(prepareGroupSessionRekey(identity, expected).rekey)
    } else controls.push(prepareGroupSessionRekey(identity, session).rekey)
    expected = session
    for (const control of controls) expected = receiveGroupEvent(identity, control, expected).state
    const operation = { controls: controls.map(c => base64UrlEncode(serializeEnvelope(c))), welcomes: welcomes.map(c => base64UrlEncode(serializeEnvelope(c))), delivered: 0, expected }
    record.group.operation = renewal
      ? { ...operation, kind: 'renewal', recipient: hex(renewal.recipient), admission: renewal.admission }
      : { ...operation, kind: action === 'add' ? 'addition' : action }
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
    if (existing?.group) applyGroupBatch(profile, id, batch.entries, batch.sequence)
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
          pending: [], receipts: previous?.group?.receipts ?? [], operation: previous?.group?.operation ?? null,
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
