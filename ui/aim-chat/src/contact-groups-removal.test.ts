/** An accepted removal or standalone rotation whose saved rekey went stale finishes from current membership. */
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateIdentity, DropboxClient, createMessage, groupSessionConversation, serializeEnvelope, deserializeEnvelope,
  receiveGroupEvent, base64UrlDecode, base64UrlEncode, prepareGroupSessionRekey, prepareGroupWelcomeRefresh, createGroupLink,
  createGroupControlMessage, createGroupRemoveBody, createGroupAddBody, assertGroupCanSend, marshalCanonical } from '@corpollc/qntm'
import type { SubscriptionMessage, GroupSessionState } from '@corpollc/qntm'
import * as store from './store'
import { validateBackup, rawBackup, exportEncryptedBackup, prepareBackup, restoreBackup } from './backup'
import { createContactGroup, changeContactGroup, pinContact, openContactGroup, syncContactGroup, sendContactGroupMessage, hex, retryContactGroup, controlAccepted, applyGroupBatch } from './contact-groups'
import { groupRemovalTarget, MAX_GROUP_OPERATION_REVISIONS } from './group-operation'

const relay = new Map<string, SubscriptionMessage[]>()
const heads = new Map<string, number>()
let failPost = false
function profile(name: string, identity = generateIdentity()) {
  const p = store.createProfile(name)
  store.saveIdentity(p.id, { privateKey: hex(identity.privateKey), publicKey: hex(identity.publicKey), keyId: hex(identity.keyID) })
  return { id: p.id, identity }
}
type Profile = ReturnType<typeof profile>
async function post(id: string, envelope: ReturnType<typeof createMessage>) {
  await new DropboxClient('http://localhost').postMessage(Uint8Array.from(id.match(/../g)!, b => parseInt(b, 16)), serializeEnvelope(envelope))
}
function session(profile: string, id: string) { return store.findConversation(profile, id)!.group!.session }
function host(profile: string, id: string) { return store.findConversation(profile, id)!.group! }
function operation(profile: string, id: string) { return host(profile, id).operation }
const posts = () => vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))
const envelopeOf = (wire: string) => deserializeEnvelope(base64UrlDecode(wire))
function expireRekey(op: store.StoredGroupOperation) {
  const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now())
  clock.mockReturnValue((envelopeOf(op.controls.at(-1)!).expiry_ts + 1) * 1000)
  return clock
}
async function group(alice: Profile, members: Profile[], name = 'Removal recovery') {
  const id = await createContactGroup(alice.id, name)
  for (const member of members) {
    pinContact(alice.id, member.id, hex(member.identity.publicKey))
    await openContactGroup(member.id, await changeContactGroup(alice.id, id, 'add', hex(member.identity.keyID)))
  }
  return id
}
/** Owner removes the target with a short-lived rekey; only the rekey POST is
 * uncertain. Acceptance of the removal comes from production receive. */
async function stageRemoval(alice: Profile, id: string, target: Profile, delivery: 'unposted' | 'lost_ack' | 'none' = 'unposted', ttl = 60) {
  const current = session(alice.id, id)
  const remove = createGroupControlMessage(alice.identity, groupSessionConversation(current), 'group_remove', createGroupRemoveBody([target.identity.keyID], 'stale rotation'))
  const afterRemove = receiveGroupEvent(alice.identity, remove, current).state
  const rotation = prepareGroupSessionRekey(alice.identity, afterRemove, ttl)
  const expected = receiveGroupEvent(alice.identity, rotation.rekey, afterRemove).state
  const op: store.StoredGroupOperation = { kind: 'remove', controls: [remove, rotation.rekey].map(envelope => base64UrlEncode(serializeEnvelope(envelope))), welcomes: [], delivered: 0, expected,
    target: groupRemovalTarget(current, hex(target.identity.keyID)) }
  store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation: op } }))
  if (delivery !== 'none') await post(id, remove)
  if (delivery === 'lost_ack') await post(id, rotation.rekey)
  await syncContactGroup(alice.id, id)
  return structuredClone(operation(alice.id, id)!)
}
function craft(identity: Profile['identity'], state: GroupSessionState, type: 'group_add' | 'group_remove', body: Uint8Array) {
  return createGroupControlMessage(identity, groupSessionConversation(state), type, body)
}
async function lowerIdRotation(identity: Profile['identity'], source: GroupSessionState, below: string) {
  let competing = prepareGroupSessionRekey(identity, source)
  for (let n = 0; hex(competing.rekey.msg_id) >= below && n < 512; n++) competing = prepareGroupSessionRekey(identity, source)
  expect(hex(competing.rekey.msg_id) < below).toBe(true)
  return competing.rekey
}
function journalsBeforePost(profile: string) {
  const captured: store.StoredGroupOperation[] = []
  const original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
  vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
    const saved = store.findConversation(profile, hex(cid))?.group?.operation
    if (saved) captured.push(structuredClone(saved))
    return original.call(this, cid, wire)
  })
  return captured
}
afterEach(() => vi.unstubAllGlobals())
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto)
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: async (_name: string, action: () => unknown) => action() } })
  localStorage.clear(); relay.clear(); heads.clear(); failPost = false
  vi.restoreAllMocks()
  vi.spyOn(DropboxClient.prototype, 'postMessage').mockImplementation(async (id, envelope) => {
    if (failPost) throw new Error('Delivery uncertain')
    const cid = hex(id), entries = relay.get(cid) ?? []
    const existing = entries.find(row => hex(deserializeEnvelope(row.envelope).msg_id) === hex(deserializeEnvelope(envelope).msg_id))
    if (existing) return existing.seq
    const seq = (heads.get(cid) ?? 0) + 1; heads.set(cid, seq)
    entries.push({ seq, envelope }); relay.set(cid, entries)
    return seq
  })
  vi.spyOn(DropboxClient.prototype, 'receiveMessages').mockImplementation(async (id, from = 0) => {
    const entries = (relay.get(hex(id)) ?? []).filter(row => row.seq > from)
    return { entries, messages: entries.map(row => row.envelope), sequence: heads.get(hex(id)) ?? 0 }
  })
})

describe('browser removal and rotation recovery', () => {
  it.each(['sole survivor', 'helper present'] as const)('finishes an accepted removal whose rekey expired from the current roster (%s)', async roster => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol')
    const id = await group(alice, roster === 'sole survivor' ? [bob] : [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    const source = envelopeOf(original.controls[0]).conv_epoch
    expect(session(alice.id, id).needsRekey).toBe(true)
    expect(store.findConversation(alice.id, id)!.participants).not.toContain(hex(bob.identity.keyID))
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(true)
    expect(controlAccepted(host(alice.id, id), original.controls[1])).toBe(false)
    expect(original.target).toEqual({ keyId: hex(bob.identity.keyID), publicKey: hex(bob.identity.publicKey), record: expect.any(String), admission: expect.objectContaining({ completion: expect.any(Object) }) })
    if (roster === 'helper present') await syncContactGroup(carol.id, id)
    expireRekey(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    const captured = journalsBeforePost(alice.id)
    await retryContactGroup(alice.id, id)
    expect(posts()).toHaveLength(1); expect(posts()[0]).not.toBe(original.controls[1])
    expect(envelopeOf(posts()[0]).conv_epoch).toBe(source)
    expect(captured).toEqual([{ kind: 'removal_rekey', controls: [posts()[0]], welcomes: [], delivered: 0, expected: captured[0].expected,
      origin: { kind: 'remove', controls: original.controls, welcomes: [], delivered: 0, target: original.target, delivery: 'unknown' } }])
    expect(captured[0].expected.root).not.toBe(original.expected.root); expect(captured[0].expected.rekeys).toEqual([])
    expect(operation(alice.id, id)).toBeNull()
    expect(session(alice.id, id)).toMatchObject({ epoch: source + 1, needsRekey: false, root: captured[0].expected.root })
    expect(store.findConversation(alice.id, id)!.participants).toHaveLength(roster === 'sole survivor' ? 1 : 2)
    await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).removed).toBe(true)
    await expect(sendContactGroupMessage(bob.id, id, 'removed')).rejects.toThrow(/removed/i)
    if (roster === 'helper present') {
      await syncContactGroup(carol.id, id)
      expect(session(carol.id, id)).toMatchObject({ epoch: source + 1, needsRekey: false, root: session(alice.id, id).root })
      await sendContactGroupMessage(carol.id, id, 'helper after completed removal')
      await syncContactGroup(alice.id, id)
      expect(store.getVisibleHistory(alice.id, id).at(-1)?.text).toBe('helper after completed removal')
    }
    expect(() => validateBackup(rawBackup())).not.toThrow()
  })

  it('keeps the repair journal through a lost ACK and encrypted-backup restart, then finishes without a second POST', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageRemoval(alice, id, bob)
    expireRekey(original)
    const base = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    const repair: string[] = []
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      repair.push(base64UrlEncode(wire)); await base.call(this, cid, wire); throw new Error('Delivery uncertain')
    })
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const saved = operation(alice.id, id)!
    expect(saved.kind).toBe('removal_rekey'); expect(saved.controls).toEqual(repair)
    expect(session(alice.id, id)).toMatchObject({ epoch: 1, needsRekey: true }) // No predicted keys from an ACK.
    const encrypted = await exportEncryptedBackup('synthetic removal repair backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic removal repair backup password'))
    expect(operation(alice.id, id)).toEqual(saved)
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(base); vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(posts()).toEqual([])
    expect(operation(alice.id, id)).toBeNull(); expect(session(alice.id, id).epoch).toBe(2)
    expect(relay.get(id)!.filter(row => base64UrlEncode(row.envelope) === repair[0])).toHaveLength(1)
  })

  it.each(['before retry', 'immediately before POST'] as const)('finishes an accepted removal through a helper rotation %s without posting', async when => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    expireRekey(original)
    const complete = async () => { await changeContactGroup(carol.id, id, 'rekey'); expect(session(carol.id, id).epoch).toBe(3) }
    if (when === 'before retry') await complete()
    else {
      const original = vi.mocked(DropboxClient.prototype.receiveMessages).getMockImplementation()!
      // The helper's rotation lands while the retry's own replay is in flight;
      // the resident receive commits it before the repair is released.
      vi.mocked(DropboxClient.prototype.receiveMessages).mockImplementationOnce(async function (this: DropboxClient, ...args) {
        await complete(); return original.apply(this, args)
      })
    }
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    // Only the helper's own rotation reaches the relay; the owner posts nothing.
    expect(posts().map(wire => hex(envelopeOf(wire).msg_id))).toEqual(when === 'before retry' ? [] : [session(carol.id, id).rekeys.at(-1)!.messageId])
    expect(operation(alice.id, id)).toBeNull()
    expect(session(alice.id, id)).toMatchObject({ epoch: 3, root: session(carol.id, id).root, needsRekey: false })
    expect(store.findConversation(alice.id, id)!.participants).toHaveLength(2)
  })

  it('never re-removes a later readmission after a helper completed the removal', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    expireRekey(original)
    await changeContactGroup(carol.id, id, 'rekey')
    pinContact(carol.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(carol.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).epoch).toBe(4)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toBeNull()
    expect(session(alice.id, id).epoch).toBe(4)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    await sendContactGroupMessage(bob.id, id, 'readmitted and still present')
    await syncContactGroup(alice.id, id)
    expect(store.getVisibleHistory(alice.id, id).at(-1)?.text).toBe('readmitted and still present')
  })

  it('completes the current roster after a same-epoch readmission without a second removal', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    // A racing member re-adds the target inside the removal's source epoch.
    await post(id, craft(carol.identity, session(carol.id, id), 'group_add', createGroupAddBody(carol.identity, [bob.identity.publicKey])))
    expireRekey(original)
    await syncContactGroup(alice.id, id)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(posts()).toHaveLength(1); expect(envelopeOf(posts()[0]).conv_epoch).toBe(2)
    expect(operation(alice.id, id)).toBeNull()
    expect(session(alice.id, id).epoch).toBe(3)
    expect(store.findConversation(alice.id, id)!.participants).toHaveLength(3)
    expect(session(alice.id, id).admissions[hex(bob.identity.keyID)].completion?.rekeyId).toBe(hex(envelopeOf(posts()[0]).msg_id))
  })

  it.each(['pinned', 'legacy'] as const)('refuses to publish an unaccepted exact removal against a same-epoch readmission (%s journal)', async journal => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    let original = await stageRemoval(alice, id, bob, 'none')
    if (journal === 'legacy') {
      store.updateConversation(alice.id, id, conv => { delete (conv.group!.operation as { target?: unknown }).target; return conv })
      original = structuredClone(operation(alice.id, id)!)
      expect(original).not.toHaveProperty('target')
    }
    await syncContactGroup(carol.id, id)
    const state = session(carol.id, id)
    await post(id, craft(carol.identity, state, 'group_remove', createGroupRemoveBody([bob.identity.keyID])))
    await post(id, craft(carol.identity, state, 'group_add', createGroupAddBody(carol.identity, [bob.identity.publicKey])))
    await syncContactGroup(alice.id, id)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/later admission|original admission/)
    expect(posts()).toEqual([])
    expect(operation(alice.id, id)).toEqual(original)
    expect(() => validateBackup(rawBackup())).not.toThrow()
  })

  it('pauses for recovery when a lower-ID competitor beats the posted replacement rotation and keeps the journal after proof invalidation', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    const source = structuredClone(session(carol.id, id))
    expireRekey(original)
    const base = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    let repair: string | undefined
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      repair = base64UrlEncode(wire); await base.call(this, cid, wire); throw new Error('Delivery uncertain')
    })
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(base)
    const competing = await lowerIdRotation(carol.identity, source, hex(envelopeOf(repair!).msg_id))
    await post(id, competing)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    // The browser treats every verified rewind as a recovery boundary: the
    // repair stays journaled and nothing is released against the losing branch.
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/history/i)
    expect(posts()).toEqual([])
    const pending = operation(alice.id, id)!
    expect(pending.kind).toBe('removal_rekey')
    expect(session(alice.id, id).recovery?.reason).toBe('missing_history')
    expect(session(alice.id, id)).toMatchObject({ epoch: 3, root: receiveGroupEvent(carol.identity, competing, source).state.root })
    expect(host(alice.id, id).controlReceipts!.some(row => row.id === hex(envelopeOf(repair!).msg_id) && row.valid === false)).toBe(true)
    // The same-epoch competitor cannot invalidate the removal itself.
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(true)
    // A challenged replacement welcome from the canonical branch restores
    // authority but, by design, invalidates all earlier private control proof.
    const canonical = receiveGroupEvent(carol.identity, competing, source).state
    pinContact(carol.id, 'Alice', hex(alice.identity.publicKey))
    store.updateConversation(carol.id, id, conv => ({ ...conv, group: { ...conv.group!, session: canonical, cursor: heads.get(id)!, pending: [] } }))
    const link = await changeContactGroup(carol.id, id, 'refresh', hex(alice.identity.keyID), session(alice.id, id).recovery!.challenge)
    await openContactGroup(alice.id, link)
    expect(session(alice.id, id)).toMatchObject({ recovery: null, epoch: 3, removed: false })
    expect(store.findConversation(alice.id, id)!.participants).not.toContain(hex(bob.identity.keyID))
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(false)
    expect(operation(alice.id, id)).toEqual(pending)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/no longer verified|superseded/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(pending)
  }, 20_000)

  it('preserves a removal invalidated by a lower branch without deriving any rotation', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    const state = session(alice.id, id), frame = state.rekeys.at(-1)!
    const branch = { ...state, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot, rekeys: [], seen: {}, admissions: structuredClone(frame.admissions), needsRekey: true, recovery: null }
    await post(id, await lowerIdRotation(alice.identity, branch, frame.messageId))
    await syncContactGroup(alice.id, id)
    // The creator recovers its own rewind before retry can run; this mirrors a
    // challenged welcome replacement leaving the removal proof invalidated.
    store.updateConversation(alice.id, id, conv => { conv.group!.session.recovery = null; return conv })
    expect(session(alice.id, id).epoch).toBe(2)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(false)
    expireRekey(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/current branch|preserved/)
    expect(posts()).toEqual([])
    expect(operation(alice.id, id)).toEqual(original)
  })

  it.each(['recovery', 'sender removed', 'journal changed', 'roster changed', 'removal unproven'] as const)('rechecks authority and proof immediately before the repair POST (%s)', async barrier => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    const helperState = session(carol.id, id)
    expireRekey(original)
    const mid = hex(envelopeOf(original.controls[0]).msg_id), commit = store.commitGroup
    let staged = false
    // The change lands through a resident receive in another tab immediately
    // after the repair is journaled and before its release check re-reads state.
    vi.spyOn(store, 'commitGroup').mockImplementation((profileId, conv, history, expected) => {
      commit(profileId, conv, history, expected)
      if (staged || conv.group?.operation?.kind !== 'removal_rekey') return
      staged = true
      if (barrier === 'roster changed') {
        const add = craft(carol.identity, helperState, 'group_add', createGroupAddBody(carol.identity, [generateIdentity().publicKey]))
        const seq = (heads.get(id) ?? 0) + 1; heads.set(id, seq); relay.get(id)!.push({ seq, envelope: serializeEnvelope(add) })
        applyGroupBatch(alice.id, id, [{ seq, envelope: serializeEnvelope(add) }], seq)
        return
      }
      store.updateConversation(alice.id, id, current => {
        if (barrier === 'recovery') current.group!.session.recovery = { reason: 'missing_history', afterSequence: current.group!.cursor, challenge: 'ab'.repeat(32) }
        else if (barrier === 'sender removed') current.group!.session.removed = true
        else if (barrier === 'journal changed') current.group!.operation!.delivered = 1
        else { delete current.group!.session.seen[mid]; current.group!.controlReceipts!.find(row => row.id === mid)!.valid = false }
        return current
      })
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(barrier === 'roster changed' ? /recipients|roster/ : barrier === 'journal changed' ? /changed/ : barrier === 'removal unproven' ? /no longer verified/ : barrier === 'recovery' ? /history/i : /removed/i)
    expect(posts()).toEqual([])
    const saved = operation(alice.id, id)!
    expect(saved.kind).toBe(barrier === 'journal changed' ? 'removal_rekey' : 'removal_rekey')
    expect(saved.kind === 'removal_rekey' && saved.origin.controls).toEqual(original.controls)
    if (barrier === 'roster changed') expect(store.findConversation(alice.id, id)!.participants).toHaveLength(3)
  })

  it.each(['none', 'revisions', 'bytes'] as const)('keeps repeated expired repairs flat and enforces the %s evidence bound', async bound => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageRemoval(alice, id, bob)
    const clock = expireRekey(original)
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const first = structuredClone(operation(alice.id, id)!)
    expect(first.kind).toBe('removal_rekey'); expect(first).not.toHaveProperty('superseded')
    clock.mockReturnValue((envelopeOf(first.controls[0]).expiry_ts + 1) * 1000)
    if (bound !== 'none') {
      store.updateConversation(alice.id, id, conv => {
        const op = conv.group!.operation as Extract<store.StoredGroupOperation, { kind: 'removal_rekey' }>
        op.superseded = Array.from({ length: bound === 'revisions' ? MAX_GROUP_OPERATION_REVISIONS : 1 }, () => ({ kind: 'removal_rekey' as const,
          controls: bound === 'bytes' ? ['A'.repeat(4 * 1024 * 1024)] : [...op.controls], welcomes: [], delivered: 0, delivery: 'unknown' as const }))
        return conv
      })
      const pending = operation(alice.id, id)!
      failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
      await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/evidence.*limit/i)
      expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(pending)
      return
    }
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const second = structuredClone(operation(alice.id, id)!)
    expect(second.kind).toBe('removal_rekey'); expect(second.controls).not.toEqual(first.controls)
    expect(second.origin).toEqual(first.origin)
    expect(second.origin).toEqual({ kind: 'remove', controls: original.controls, welcomes: [], delivered: 0, target: original.target, delivery: 'unknown' })
    expect(second.superseded).toEqual([{ kind: 'removal_rekey', controls: first.controls, welcomes: [], delivered: 0, delivery: 'unknown' }])
    expect(() => validateBackup(rawBackup())).not.toThrow()
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(posts()).toEqual(second.controls); expect(operation(alice.id, id)).toBeNull(); expect(session(alice.id, id).epoch).toBe(2)
  })

  it('keeps the original intent and posts nothing when repair staging fails to persist', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageRemoval(alice, id, bob)
    expireRekey(original)
    const realCommit = store.commitGroup
    vi.spyOn(store, 'commitGroup').mockImplementation((profileId, conv, history, expected) => {
      if (conv.group?.operation?.kind === 'removal_rekey') throw new Error('simulated storage failure')
      return realCommit(profileId, conv, history, expected)
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('simulated storage failure')
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(original)
  })

  it.each(['valid', 'missing', 'invalidated', 'unverified epoch', 'wrong digest', 'future sequence'] as const)('requires authenticated receipt evidence for the removal after cache eviction (%s)', async evidence => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageRemoval(alice, id, bob)
    expireRekey(original)
    const mid = hex(envelopeOf(original.controls[0]).msg_id)
    store.updateConversation(alice.id, id, conv => {
      conv.group!.session.seen = {}
      const rows = conv.group!.controlReceipts!, row = rows.find(item => item.id === mid)!
      expect(row).toMatchObject({ bodyType: 'group_remove', valid: true })
      if (evidence === 'missing') conv.group!.controlReceipts = rows.filter(item => item.id !== mid)
      else if (evidence === 'invalidated') row.valid = false
      else if (evidence === 'unverified epoch') row.epoch += 1
      else if (evidence === 'wrong digest') row.digest = '00'.repeat(32)
      else if (evidence === 'future sequence') row.sequence = conv.group!.cursor + 1
      return conv
    })
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(evidence === 'valid')
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    if (evidence === 'valid') {
      await retryContactGroup(alice.id, id)
      expect(posts()).toHaveLength(1); expect(operation(alice.id, id)).toBeNull(); expect(session(alice.id, id).epoch).toBe(2)
      return
    }
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow()
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(original)
  })

  it('keeps the removal receipt after real eviction by authenticated controls and pins it through journal replacement', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob)
    await syncContactGroup(carol.id, id)
    const mid = hex(envelopeOf(original.controls[0]).msg_id), helperState = session(carol.id, id)
    // Synthetic pressure to the legal 8192 seen bound keeps the accepted
    // removal marker; real authenticated same-epoch controls then evict it.
    store.updateConversation(alice.id, id, conv => {
      const seen = conv.group!.session.seen, next: Record<string, { digest: string; epoch: number }> = { [mid]: seen[mid] }
      for (let index = 1; Object.keys(next).length < 8192; index++) {
        const dummy = index.toString(16).padStart(32, '0')
        if (!next[dummy]) next[dummy] = { digest: '00'.repeat(32), epoch: 0 }
      }
      conv.group!.session.seen = next
      return conv
    })
    for (let index = 0; index < 2; index++) await post(id, craft(carol.identity, helperState, 'group_add', createGroupAddBody(carol.identity, [generateIdentity().publicKey])))
    await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).seen[mid]).toBeUndefined()
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(true)
    // Synthetic receipt pressure to the legal bound: unrelated valid rows fill the
    // list, so the next latch must evict an unpinned row, never the origin proof.
    store.updateConversation(alice.id, id, conv => {
      const rows = conv.group!.controlReceipts!
      for (let index = 1; rows.length < store.MAX_GROUP_CONTROL_RECEIPTS; index++) {
        rows.push({ id: index.toString(16).padStart(32, '0'), digest: '11'.repeat(32), epoch: 0, sequence: 1, valid: true, bodyType: 'group_rekey' })
      }
      return conv
    })
    expireRekey(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(posts()).toHaveLength(1)
    expect(operation(alice.id, id)).toBeNull(); expect(session(alice.id, id).epoch).toBe(3)
    expect(store.findConversation(alice.id, id)!.participants).toHaveLength(4)
    expect(store.findConversation(alice.id, id)!.participants).not.toContain(hex(bob.identity.keyID))
    expect(host(alice.id, id).controlReceipts!.length).toBeLessThanOrEqual(store.MAX_GROUP_CONTROL_RECEIPTS)
    expect(host(alice.id, id).controlReceipts!.find(row => row.id === mid)).toMatchObject({ valid: true, bodyType: 'group_remove' })
    expect(host(alice.id, id).controlReceipts!.find(row => row.id === hex(envelopeOf(posts()[0]).msg_id))).toMatchObject({ valid: true, bodyType: 'group_rekey' })
  }, 20_000)

  it.each(['expired', 'superseded'] as const)('preserves an unaccepted %s removal with a precise error and no new removal', async stale => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageRemoval(alice, id, bob, 'none')
    if (stale === 'expired') vi.spyOn(Date, 'now').mockReturnValue((envelopeOf(original.controls[0]).expiry_ts + 1) * 1000)
    else { await syncContactGroup(carol.id, id); await changeContactGroup(carol.id, id, 'rekey') }
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(stale)
    await expect(changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))).rejects.toThrow(/Retry the saved/)
    expect(posts().filter(wire => hex(deserializeEnvelope(base64UrlDecode(wire)).conv_id) === id && envelopeOf(wire).conv_epoch === 2)).toEqual([])
    expect(operation(alice.id, id)).toEqual(original)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
  })

  async function stagedRotation(actor: Profile, id: string, delivery: 'unposted' | 'lost_ack' = 'unposted', ttl = 60) {
    const current = session(actor.id, id), rotation = prepareGroupSessionRekey(actor.identity, current, ttl)
    const expected = receiveGroupEvent(actor.identity, rotation.rekey, current).state
    const op: store.StoredGroupOperation = { kind: 'rekey', controls: [base64UrlEncode(serializeEnvelope(rotation.rekey))], welcomes: [], delivered: 0, expected }
    store.updateConversation(actor.id, id, conv => ({ ...conv, group: { ...conv.group!, operation: op } }))
    if (delivery === 'lost_ack') await post(id, rotation.rekey)
    await syncContactGroup(actor.id, id)
    return structuredClone(operation(actor.id, id)!)
  }

  it.each(['expired', 'rewound branch', 'roster changed', 'exact', 'superseded', 'lost ACK'] as const)('keeps a standalone rotation intent exact, renews it or finishes it (%s)', async stale => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    await syncContactGroup(bob.id, id)
    const original = await stagedRotation(bob, id, stale === 'lost ACK' ? 'lost_ack' : 'unposted')
    const source = envelopeOf(original.controls[0]).conv_epoch
    expect(source).toBe(2)
    if (stale === 'expired') expireRekey(original)
    else if (stale === 'rewound branch') {
      // A lower-ID competitor from the previous epoch rewinds every saved member
      // into recovery. A challenged welcome from the canonical branch restores
      // the member's authority; the exact old rotation bytes never apply again.
      const state = session(alice.id, id), frame = state.rekeys.at(-1)!
      const branch = { ...state, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot, rekeys: [], seen: {}, admissions: structuredClone(frame.admissions), needsRekey: true, recovery: null }
      const competitor = await lowerIdRotation(alice.identity, branch, frame.messageId)
      await post(id, competitor)
      await syncContactGroup(bob.id, id)
      expect(session(bob.id, id).recovery?.reason).toBe('missing_history')
      const canonical = receiveGroupEvent(alice.identity, competitor, branch).state
      const refresh = prepareGroupWelcomeRefresh(alice.identity, canonical, [bob.identity.publicKey], undefined, base64UrlDecode(base64UrlEncode(Uint8Array.from(session(bob.id, id).recovery!.challenge.match(/../g)!, b => parseInt(b, 16)))), heads.get(id)!)
      await post(id, refresh.welcomes[0])
      await openContactGroup(bob.id, createGroupLink({ conversationId: Uint8Array.from(id.match(/../g)!, b => parseInt(b, 16)), inviterPublicKey: alice.identity.publicKey, relayUrl: store.getDropboxUrl() }))
      expect(session(bob.id, id)).toMatchObject({ recovery: null, epoch: 2, root: canonical.root })
      expect(operation(bob.id, id)).toEqual(original)
    } else if (stale === 'roster changed') {
      await post(id, craft(alice.identity, session(alice.id, id), 'group_add', createGroupAddBody(alice.identity, [generateIdentity().publicKey])))
    } else if (stale === 'superseded') await changeContactGroup(alice.id, id, 'rekey')
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    const captured = journalsBeforePost(bob.id)
    await retryContactGroup(bob.id, id)
    expect(operation(bob.id, id)).toBeNull(); expect(session(bob.id, id).needsRekey).toBe(false)
    expect(session(bob.id, id).epoch).toBe(source + 1)
    if (stale === 'superseded' || stale === 'lost ACK') expect(posts()).toEqual([])
    else if (stale === 'exact') expect(posts()).toEqual(original.controls)
    else {
      expect(posts()).toHaveLength(1); expect(posts()[0]).not.toBe(original.controls[0])
      expect(envelopeOf(posts()[0]).conv_epoch).toBe(source)
      expect(captured[0]).toMatchObject({ kind: 'rekey', controls: posts(), superseded: [{ kind: 'rekey', controls: original.controls, welcomes: [], delivered: 0, delivery: 'unknown' }] })
      expect(captured[0]).not.toHaveProperty('origin')
      if (stale === 'roster changed') expect(store.findConversation(bob.id, id)!.participants).toHaveLength(4)
    }
    if (stale === 'rewound branch') {
      // The rewound owner recovers through the member's challenged refresh.
      await syncContactGroup(alice.id, id)
      expect(session(alice.id, id).recovery?.reason).toBe('missing_history')
      pinContact(bob.id, 'Alice', hex(alice.identity.publicKey))
      await openContactGroup(alice.id, await changeContactGroup(bob.id, id, 'refresh', hex(alice.identity.keyID), session(alice.id, id).recovery!.challenge))
    }
    await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).recovery).toBeNull()
    expect(session(alice.id, id).root).toBe(session(bob.id, id).root)
    await sendContactGroupMessage(bob.id, id, 'rotation settled')
    await syncContactGroup(alice.id, id)
    expect(store.getVisibleHistory(alice.id, id).at(-1)?.text).toBe('rotation settled')
    expect(() => validateBackup(rawBackup())).not.toThrow()
  }, 20_000)

  it.each(['sender removed', 'recovery', 'evidence limit'] as const)('never lets a stale rotation bypass current authority or evidence bounds (%s)', async barrier => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    await syncContactGroup(bob.id, id)
    const original = await stagedRotation(bob, id)
    expireRekey(original)
    if (barrier === 'sender removed') await changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))
    else store.updateConversation(bob.id, id, conv => {
      if (barrier === 'recovery') conv.group!.session.recovery = { reason: 'missing_history', afterSequence: conv.group!.cursor, challenge: 'ab'.repeat(32) }
      else (conv.group!.operation as Extract<store.StoredGroupOperation, { kind: 'rekey' }>).superseded = Array.from({ length: MAX_GROUP_OPERATION_REVISIONS }, () => ({ kind: 'rekey' as const, controls: [...original.controls], welcomes: [], delivered: 0, delivery: 'unknown' as const }))
      return conv
    })
    const pending = operation(bob.id, id)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(bob.id, id)).rejects.toThrow(barrier === 'sender removed' ? /removed/i : barrier === 'recovery' ? /history/i : /limit/i)
    expect(posts()).toEqual([]); expect(operation(bob.id, id)).toEqual(pending)
  })

  it('round-trips new removal journals through encrypted backups and rejects corrupt target, origin and evidence fields', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageRemoval(alice, id, bob)
    const before = rawBackup(), data = JSON.parse(before)
    const remove = data.conversations[alice.id][0].group.operation
    expect(remove.target).toEqual(original.target)
    const encrypted = await exportEncryptedBackup('synthetic removal target backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic removal target backup password'))
    expect(operation(alice.id, id)).toEqual(original)
    const bad = (mutate: (op: any) => void) => { const invalid = structuredClone(data); mutate(invalid.conversations[alice.id][0].group.operation); expect(() => validateBackup(JSON.stringify(invalid))).toThrow() }
    bad(op => { op.target.keyId = hex(alice.identity.keyID) })
    bad(op => { op.target.publicKey = hex(alice.identity.publicKey) })
    bad(op => { op.target.record = base64UrlEncode(new TextEncoder().encode('not a member record')) })
    bad(op => { op.target.record = op.target.record + 'A' })
    bad(op => { op.target.admission = { addId: 'zz' } })
    bad(op => { op.target.admission.completion = null })
    bad(op => { op.target.extra = true })
    bad(op => { op.kind = 'rekey'; op.controls = [op.controls[1]] })
    bad(op => { op.superseded = [] })
    const legacy = structuredClone(data); delete legacy.conversations[alice.id][0].group.operation.target
    expect(() => validateBackup(JSON.stringify(legacy))).not.toThrow()
    expireRekey(original)
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const repaired = JSON.parse(rawBackup()), repair = repaired.conversations[alice.id][0].group.operation
    expect(repair.kind).toBe('removal_rekey')
    expect(() => validateBackup(rawBackup())).not.toThrow()
    const badRepair = (mutate: (op: any) => void) => { const invalid = structuredClone(repaired); mutate(invalid.conversations[alice.id][0].group.operation); expect(() => validateBackup(JSON.stringify(invalid))).toThrow() }
    badRepair(op => { delete op.origin })
    badRepair(op => { op.origin.kind = 'addition' })
    badRepair(op => { op.origin.delivery = 'accepted' })
    badRepair(op => { op.origin.controls = [op.origin.controls[0]] })
    badRepair(op => { op.origin.welcomes = [op.origin.controls[0]] })
    badRepair(op => { op.origin.target.keyId = hex(alice.identity.keyID) })
    badRepair(op => { op.origin.expected = op.expected })
    badRepair(op => { op.controls = [op.origin.controls[1]]; op.expected.epoch += 1 })
    badRepair(op => { op.recipient = hex(bob.identity.publicKey) })
    badRepair(op => { op.target = op.origin.target })
    badRepair(op => { op.superseded = [{ kind: 'addition_rekey', controls: op.controls, welcomes: [], delivered: 0, delivery: 'unknown' }] })
    badRepair(op => { op.superseded = [{ kind: 'removal_rekey', controls: [], welcomes: [op.controls[0]], delivered: 0, delivery: 'unknown' }] })
    badRepair(op => { op.superseded = [{ kind: 'removal_rekey', controls: op.controls, welcomes: [], delivered: 0, delivery: 'unknown', origin: op.origin }] })
    const legacyOrigin = structuredClone(repaired); delete legacyOrigin.conversations[alice.id][0].group.operation.origin.target
    expect(() => validateBackup(JSON.stringify(legacyOrigin))).not.toThrow()
    const rotation = structuredClone(repaired), op = rotation.conversations[alice.id][0].group.operation
    rotation.conversations[alice.id][0].group.operation = { kind: 'rekey', controls: op.controls, welcomes: [], delivered: 0, expected: op.expected,
      superseded: [{ kind: 'rekey', controls: op.origin.controls.slice(1), welcomes: [], delivered: 0, delivery: 'unknown' }] }
    expect(() => validateBackup(JSON.stringify(rotation))).not.toThrow()
    rotation.conversations[alice.id][0].group.operation.superseded[0].kind = 'removal_rekey'
    expect(() => validateBackup(JSON.stringify(rotation))).toThrow()
    expect(rawBackup()).toBe(JSON.stringify(repaired))
  })

  it('pins the target through the production remove action and blocks a same-epoch readmission of that identity on exact retry', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    await syncContactGroup(carol.id, id)
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))).rejects.toThrow('Delivery uncertain')
    const saved = operation(alice.id, id)!
    expect(saved.kind).toBe('remove'); expect(saved.target?.keyId).toBe(hex(bob.identity.keyID))
    expect(saved.target?.admission).toEqual(session(alice.id, id).admissions[hex(bob.identity.keyID)])
    expect(marshalCanonical(saved.target)).toEqual(marshalCanonical(groupRemovalTarget(session(alice.id, id), hex(bob.identity.keyID))))
    failPost = false
    const state = session(carol.id, id)
    await post(id, craft(carol.identity, state, 'group_remove', createGroupRemoveBody([bob.identity.keyID])))
    await post(id, craft(carol.identity, state, 'group_add', createGroupAddBody(carol.identity, [bob.identity.publicKey])))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/original admission/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(saved)
    assertGroupCanSend(alice.identity, { ...session(alice.id, id), needsRekey: false })
  })
})
