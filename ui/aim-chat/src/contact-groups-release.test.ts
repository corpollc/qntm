/** Explicit local release of a stale, unproven saved removal: no POST, no acceptance claim, evidence kept. */
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateIdentity, DropboxClient, createMessage, groupSessionConversation, serializeEnvelope, deserializeEnvelope,
  receiveGroupEvent, base64UrlDecode, base64UrlEncode, prepareGroupSessionRekey, prepareGroupWelcomeRefresh, createGroupLink,
  createGroupControlMessage, createGroupRemoveBody, createGroupAddBody, marshalCanonical } from '@corpollc/qntm'
import type { SubscriptionMessage, GroupSessionState } from '@corpollc/qntm'
import * as store from './store'
import { validateBackup, rawBackup, exportEncryptedBackup, prepareBackup, restoreBackup } from './backup'
import { createContactGroup, changeContactGroup, pinContact, openContactGroup, syncContactGroup, sendContactGroupMessage, hex,
  retryContactGroup, releaseContactGroupRetry, controlAccepted } from './contact-groups'
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
const cid = (id: string) => Uint8Array.from(id.match(/../g)!, b => parseInt(b, 16))
async function post(id: string, envelope: ReturnType<typeof createMessage>) {
  await new DropboxClient('http://localhost').postMessage(cid(id), serializeEnvelope(envelope))
}
function session(profile: string, id: string) { return store.findConversation(profile, id)!.group!.session }
function host(profile: string, id: string) { return store.findConversation(profile, id)!.group! }
function operation(profile: string, id: string) { return host(profile, id).operation }
function archive(profile: string, id: string) { return host(profile, id).releasedOperations ?? [] }
const posts = () => vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))
const envelopeOf = (wire: string) => deserializeEnvelope(base64UrlDecode(wire))
async function group(alice: Profile, members: Profile[], name = 'Removal release') {
  const id = await createContactGroup(alice.id, name)
  for (const member of members) {
    pinContact(alice.id, member.id, hex(member.identity.publicKey))
    await openContactGroup(member.id, await changeContactGroup(alice.id, id, 'add', hex(member.identity.keyID)))
  }
  return id
}
/** The production remove journal shape with short-lived controls, never posted.
 * Only the lifetime is a fixture choice: controls, reducer trial and target pin
 * come from the same factories the remove action uses. */
function unpostedRemoval(identity: Profile['identity'], state: GroupSessionState, targetKid: string, ttl = 60): store.StoredGroupOperation {
  const conversation = groupSessionConversation(state)
  const remove = createGroupControlMessage(identity, conversation, 'group_remove', createGroupRemoveBody([Uint8Array.from(targetKid.match(/../g)!, b => parseInt(b, 16))], 'unposted removal'), ttl)
  const afterRemove = receiveGroupEvent(identity, remove, state).state
  const rotation = prepareGroupSessionRekey(identity, afterRemove, ttl)
  const expected = receiveGroupEvent(identity, rotation.rekey, afterRemove).state
  return { kind: 'remove', controls: [remove, rotation.rekey].map(envelope => base64UrlEncode(serializeEnvelope(envelope))), welcomes: [], delivered: 0, expected,
    target: groupRemovalTarget(state, targetKid) }
}
async function stageUnposted(actor: Profile, id: string, target: Profile, ttl = 60) {
  await syncContactGroup(actor.id, id)
  const op = unpostedRemoval(actor.identity, session(actor.id, id), hex(target.identity.keyID), ttl)
  store.updateConversation(actor.id, id, conv => ({ ...conv, group: { ...conv.group!, operation: op } }))
  return structuredClone(operation(actor.id, id)!)
}
function expireRemoval(op: store.StoredGroupOperation) {
  return vi.spyOn(Date, 'now').mockReturnValue((envelopeOf(op.controls[0]).expiry_ts + 1) * 1000)
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
afterEach(() => vi.unstubAllGlobals())
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto)
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: async (_name: string, action: () => unknown) => action() } })
  localStorage.clear(); relay.clear(); heads.clear(); failPost = false
  vi.restoreAllMocks()
  vi.spyOn(DropboxClient.prototype, 'postMessage').mockImplementation(async (id, envelope) => {
    if (failPost) throw new Error('Delivery uncertain')
    const key = hex(id), entries = relay.get(key) ?? []
    const existing = entries.find(row => hex(deserializeEnvelope(row.envelope).msg_id) === hex(deserializeEnvelope(envelope).msg_id))
    if (existing) return existing.seq
    const seq = (heads.get(key) ?? 0) + 1; heads.set(key, seq)
    entries.push({ seq, envelope }); relay.set(key, entries)
    return seq
  })
  vi.spyOn(DropboxClient.prototype, 'receiveMessages').mockImplementation(async (id, from = 0) => {
    const entries = (relay.get(hex(id)) ?? []).filter(row => row.seq > from)
    return { entries, messages: entries.map(row => row.envelope), sequence: heads.get(hex(id)) ?? 0 }
  })
})

describe('browser release of a stale unproven removal', () => {
  it.each(['pinned', 'legacy'] as const)('releases an expired unposted removal (%s journal), keeps its evidence and restores sending without excluding anyone', async journal => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    let original = await stageUnposted(alice, id, bob)
    if (journal === 'legacy') {
      store.updateConversation(alice.id, id, conv => { delete (conv.group!.operation as { target?: unknown }).target; return conv })
      original = structuredClone(operation(alice.id, id)!)
    }
    const clock = expireRemoval(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/expired before its acceptance/)
    const result = await releaseContactGroupRetry(alice.id, id)
    expect(result).toEqual({ released: true, reason: 'expired', epoch: 1, members: 2, removed: false, needsRekey: false, releasedOperations: 1 })
    expect(posts()).toEqual([])
    expect(operation(alice.id, id)).toBeNull()
    expect(archive(alice.id, id)).toEqual([{ kind: 'remove', controls: original.controls, welcomes: [], delivered: 0,
      ...(journal === 'pinned' ? { target: original.target } : {}), delivery: 'unknown', releasedReason: 'expired', releasedAt: Math.floor(clock() / 1000) }])
    expect(archive(alice.id, id)[0]).not.toHaveProperty('expected')
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    expect(session(alice.id, id)).toMatchObject({ needsRekey: false, removed: false, recovery: null })
    expect(() => validateBackup(rawBackup())).not.toThrow()
    await sendContactGroupMessage(alice.id, id, 'after release')
    await syncContactGroup(bob.id, id)
    expect(store.getVisibleHistory(bob.id, id).at(-1)?.text).toBe('after release')
    await sendContactGroupMessage(bob.id, id, 'still present')
    await syncContactGroup(alice.id, id)
    expect(store.getVisibleHistory(alice.id, id).at(-1)?.text).toBe('still present')
    // A later explicit removal is a fresh current-epoch decision with its own pin.
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))
    expect(posts()).toHaveLength(2); expect(posts()).not.toContain(original.controls[0])
    expect(session(alice.id, id).epoch).toBe(2)
    await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).removed).toBe(true)
    expect(archive(alice.id, id)).toHaveLength(1)
  })

  it('refuses a verified removal and a still exactly retryable one', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageUnposted(alice, id, bob)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(/still exactly retryable/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(original); expect(archive(alice.id, id)).toEqual([])
    // Post the removal through the relay so production receive proves it.
    await post(id, envelopeOf(original.controls[0]))
    await syncContactGroup(alice.id, id)
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(true)
    expireRemoval(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(/verified in current history/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(original)
    // Plain retry owns the proven case and repairs it.
    await retryContactGroup(alice.id, id)
    expect(operation(alice.id, id)).toBeNull(); expect(session(alice.id, id).epoch).toBe(2)
  })

  it('refuses still-applying original bytes even when they are carried as a repair origin', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageUnposted(alice, id, bob)
    const repair: store.StoredGroupOperation = {
      kind: 'removal_rekey', controls: [original.controls[1]], welcomes: [], delivered: 0, expected: original.expected,
      origin: { kind: 'remove', controls: original.controls, welcomes: [], delivered: 0, ...(original.target ? { target: original.target } : {}), delivery: 'unknown' },
    }
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation: repair } }))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(/still exactly retryable/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(repair); expect(archive(alice.id, id)).toEqual([])
  })

  it.each(['refresh', 'rekey', 'addition', 'none'] as const)('refuses when the saved operation is %s', async kind => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob])
    if (kind !== 'none') {
      pinContact(alice.id, 'Carol', hex(carol.identity.publicKey))
      failPost = true
      await expect(kind === 'refresh' ? changeContactGroup(alice.id, id, 'refresh', hex(bob.identity.keyID))
        : kind === 'rekey' ? changeContactGroup(alice.id, id, 'rekey') : changeContactGroup(alice.id, id, 'add', hex(carol.identity.keyID))).rejects.toThrow('Delivery uncertain')
      failPost = false
    }
    const pending = operation(alice.id, id)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(kind === 'none' ? /No saved group operation/ : /not an unproven removal/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(pending)
  })

  it('refuses while group history is incomplete', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageUnposted(alice, id, bob)
    expireRemoval(original)
    store.updateConversation(alice.id, id, conv => { conv.group!.session.recovery = { reason: 'missing_history', afterSequence: conv.group!.cursor, challenge: 'ab'.repeat(32) }; return conv })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(/history/i)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(original); expect(session(alice.id, id).recovery).not.toBeNull()
  })

  it('releases a removal superseded by a peer rotation without excluding the target', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageUnposted(alice, id, bob)
    await changeContactGroup(carol.id, id, 'rekey')
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/superseded/)
    const result = await releaseContactGroupRetry(alice.id, id)
    expect(result).toMatchObject({ released: true, reason: 'superseded', epoch: 3, members: 3, needsRekey: false })
    expect(posts()).toEqual([]); expect(archive(alice.id, id)[0].controls).toEqual(original.controls)
    await sendContactGroupMessage(alice.id, id, 'everyone still here')
    await syncContactGroup(bob.id, id)
    expect(store.getVisibleHistory(bob.id, id).at(-1)?.text).toBe('everyone still here')
  })

  it('releases a removal from another branch after a challenged welcome replacement, preserving the archive through it', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    await syncContactGroup(bob.id, id)
    const original = await stageUnposted(bob, id, carol)
    const state = session(alice.id, id), frame = state.rekeys.at(-1)!
    const branch = { ...state, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot, rekeys: [], seen: {}, admissions: structuredClone(frame.admissions), needsRekey: true, recovery: null }
    const competitor = await lowerIdRotation(alice.identity, branch, frame.messageId)
    await post(id, competitor)
    await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).recovery?.reason).toBe('missing_history')
    await expect(releaseContactGroupRetry(bob.id, id)).rejects.toThrow(/history/i)
    const canonical = receiveGroupEvent(alice.identity, competitor, branch).state
    const challenge = Uint8Array.from(session(bob.id, id).recovery!.challenge.match(/../g)!, b => parseInt(b, 16))
    await post(id, prepareGroupWelcomeRefresh(alice.identity, canonical, [bob.identity.publicKey], undefined, challenge, heads.get(id)!).welcomes[0])
    await openContactGroup(bob.id, createGroupLink({ conversationId: cid(id), inviterPublicKey: alice.identity.publicKey, relayUrl: store.getDropboxUrl() }))
    expect(session(bob.id, id)).toMatchObject({ recovery: null, epoch: 2, root: canonical.root })
    expect(operation(bob.id, id)).toEqual(original)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    const result = await releaseContactGroupRetry(bob.id, id)
    expect(result).toMatchObject({ released: true, reason: 'wrong_branch', epoch: 2, members: 3 })
    expect(posts()).toEqual([])
    const saved = archive(bob.id, id)
    expect(saved).toHaveLength(1); expect(saved[0].controls).toEqual(original.controls)
    expect(store.findConversation(bob.id, id)!.participants).toContain(hex(carol.identity.keyID))
    // A second challenged replacement keeps the private archive.
    store.updateConversation(bob.id, id, conv => { conv.group!.session.recovery = { reason: 'missing_history', afterSequence: conv.group!.cursor, challenge: 'cd'.repeat(32) }; return conv })
    await post(id, prepareGroupWelcomeRefresh(alice.identity, canonical, [bob.identity.publicKey], undefined, Uint8Array.from('cd'.repeat(32).match(/../g)!, b => parseInt(b, 16)), heads.get(id)!).welcomes[0])
    await openContactGroup(bob.id, createGroupLink({ conversationId: cid(id), inviterPublicKey: alice.identity.publicKey, relayUrl: store.getDropboxUrl() }))
    expect(session(bob.id, id).recovery).toBeNull(); expect(archive(bob.id, id)).toEqual(saved)
  }, 20_000)

  it.each(['pinned', 'legacy'] as const)('releases a changed same-epoch incarnation without re-removing the readmitted target (%s journal)', async journal => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    let original = await stageUnposted(alice, id, bob)
    if (journal === 'legacy') {
      store.updateConversation(alice.id, id, conv => { delete (conv.group!.operation as { target?: unknown }).target; return conv })
      original = structuredClone(operation(alice.id, id)!)
    }
    await syncContactGroup(carol.id, id)
    const state = session(carol.id, id)
    await post(id, craft(carol.identity, state, 'group_remove', createGroupRemoveBody([bob.identity.keyID])))
    await post(id, craft(carol.identity, state, 'group_add', createGroupAddBody(carol.identity, [bob.identity.publicKey])))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/later admission|original admission/)
    const result = await releaseContactGroupRetry(alice.id, id)
    expect(result).toMatchObject({ released: true, reason: journal === 'pinned' ? 'incarnation_changed' : 'legacy_same_epoch_admission', needsRekey: true, removed: false })
    expect(posts()).toEqual([])
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
    expect(archive(alice.id, id)[0].controls).toEqual(original.controls)
    // The received membership change still needs its rotation; sends stay blocked.
    await expect(sendContactGroupMessage(alice.id, id, 'blocked')).rejects.toThrow(/rotation/i)
    await changeContactGroup(alice.id, id, 'rekey')
    expect(session(alice.id, id).epoch).toBe(3)
    expect(store.findConversation(alice.id, id)!.participants).toContain(hex(bob.identity.keyID))
  })

  it('releases when the target is already absent without claiming its own removal', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageUnposted(alice, id, bob)
    await syncContactGroup(carol.id, id)
    await post(id, craft(carol.identity, session(carol.id, id), 'group_remove', createGroupRemoveBody([bob.identity.keyID])))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    const result = await releaseContactGroupRetry(alice.id, id)
    expect(result).toMatchObject({ released: true, reason: 'target_absent', needsRekey: true })
    expect(posts()).toEqual([])
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(false)
    expect(store.findConversation(alice.id, id)!.participants).not.toContain(hex(bob.identity.keyID))
  })

  it('releases a repair journal whose accepted origin proof was invalidated by a challenged replacement', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    const original = await stageUnposted(alice, id, bob, 60)
    await post(id, envelopeOf(original.controls[0]))
    await syncContactGroup(alice.id, id); await syncContactGroup(carol.id, id)
    const source = structuredClone(session(carol.id, id))
    vi.spyOn(Date, 'now').mockReturnValue((envelopeOf(original.controls[1]).expiry_ts + 1) * 1000)
    const base = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    let repairWire = ''
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      repairWire = base64UrlEncode(wire); await base.call(this, cid, wire); throw new Error('Delivery uncertain')
    })
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(base)
    const repair = structuredClone(operation(alice.id, id)!)
    expect(repair.kind).toBe('removal_rekey')
    const competitor = await lowerIdRotation(carol.identity, source, hex(envelopeOf(repairWire).msg_id))
    await post(id, competitor)
    await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).recovery?.reason).toBe('missing_history')
    const canonical = receiveGroupEvent(carol.identity, competitor, source).state
    pinContact(carol.id, 'Alice', hex(alice.identity.publicKey))
    store.updateConversation(carol.id, id, conv => ({ ...conv, group: { ...conv.group!, session: canonical, cursor: heads.get(id)!, pending: [] } }))
    await openContactGroup(alice.id, await changeContactGroup(carol.id, id, 'refresh', hex(alice.identity.keyID), session(alice.id, id).recovery!.challenge))
    expect(session(alice.id, id)).toMatchObject({ recovery: null, epoch: 3 })
    expect(controlAccepted(host(alice.id, id), original.controls[0])).toBe(false)
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/no longer verified/)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    const result = await releaseContactGroupRetry(alice.id, id)
    expect(result).toMatchObject({ released: true, reason: 'superseded', epoch: 3, members: 2 })
    expect(posts()).toEqual([])
    const row = archive(alice.id, id)[0]
    expect(row).toMatchObject({ kind: 'removal_rekey', controls: repair.controls, origin: repair.origin, delivery: 'unknown', releasedReason: 'superseded' })
    expect(row).not.toHaveProperty('expected'); expect(row).not.toHaveProperty('target')
    expect(() => validateBackup(rawBackup())).not.toThrow()
  }, 20_000)

  it.each(['removed', 'needsRekey'] as const)('keeps the received %s barrier after release', async barrier => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), id = await group(alice, [bob, carol])
    await syncContactGroup(bob.id, id)
    const original = await stageUnposted(bob, id, carol)
    if (barrier === 'removed') await changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))
    else {
      await post(id, craft(alice.identity, session(alice.id, id), 'group_add', createGroupAddBody(alice.identity, [generateIdentity().publicKey])))
      expireRemoval(original)
    }
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(bob.id, id)).rejects.toThrow()
    const result = await releaseContactGroupRetry(bob.id, id)
    expect(result).toMatchObject({ released: true, removed: barrier === 'removed', needsRekey: barrier === 'needsRekey' })
    expect(posts()).toEqual([])
    expect(operation(bob.id, id)).toBeNull(); expect(archive(bob.id, id)[0].controls).toEqual(original.controls)
    await expect(sendContactGroupMessage(bob.id, id, 'still barred')).rejects.toThrow(barrier === 'removed' ? /removed/i : /rotation/i)
    await expect(changeContactGroup(bob.id, id, 'remove', hex(carol.identity.keyID))).rejects.toThrow()
    expect(store.findConversation(bob.id, id)!.participants).toContain(hex(carol.identity.keyID))
  })

  it('refuses when the journal changes during its own replay', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageUnposted(alice, id, bob)
    expireRemoval(original)
    const receive = vi.mocked(DropboxClient.prototype.receiveMessages).getMockImplementation()!
    vi.mocked(DropboxClient.prototype.receiveMessages).mockImplementationOnce(async function (this: DropboxClient, ...args) {
      const result = await receive.apply(this, args)
      store.updateConversation(alice.id, id, conv => { conv.group!.operation!.delivered = 1; return conv })
      return result
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(/changed/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)!.delivered).toBe(1); expect(archive(alice.id, id)).toEqual([])
  })

  it.each(['revisions', 'bytes', 'malformed'] as const)('refuses unchanged when the archive cannot retain evidence (%s)', async bound => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const first = await stageUnposted(alice, id, bob)
    const clock = expireRemoval(first)
    await releaseContactGroupRetry(alice.id, id)
    const saved = structuredClone(archive(alice.id, id))
    clock.mockReturnValue(Date.now())
    const second = await stageUnposted(alice, id, bob)
    clock.mockReturnValue((envelopeOf(second.controls[0]).expiry_ts + 1) * 1000)
    store.updateConversation(alice.id, id, conv => {
      if (bound === 'revisions') conv.group!.releasedOperations = Array.from({ length: MAX_GROUP_OPERATION_REVISIONS }, () => structuredClone(saved[0]))
      else if (bound === 'bytes') conv.group!.releasedOperations = [{ ...saved[0], controls: ['A'.repeat(4 * 1024 * 1024)] }]
      else (conv.group!.releasedOperations![0] as { delivery: string }).delivery = 'accepted'
      return conv
    })
    const before = structuredClone(archive(alice.id, id))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(releaseContactGroupRetry(alice.id, id)).rejects.toThrow(bound === 'malformed' ? /Invalid saved release archive/ : /limit/)
    expect(posts()).toEqual([]); expect(operation(alice.id, id)).toEqual(second); expect(archive(alice.id, id)).toEqual(before)
  }, 20_000)

  it('round-trips the archive through encrypted backup, rejects corrupt archives, and accepts backups without one', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await group(alice, [bob])
    const original = await stageUnposted(alice, id, bob)
    expireRemoval(original)
    await releaseContactGroupRetry(alice.id, id)
    const saved = structuredClone(archive(alice.id, id)), data = JSON.parse(rawBackup())
    const encrypted = await exportEncryptedBackup('synthetic release archive backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic release archive backup password'))
    expect(archive(alice.id, id)).toEqual(saved); expect(operation(alice.id, id)).toBeNull()
    const bad = (mutate: (group: any) => void) => { const invalid = structuredClone(data); mutate(invalid.conversations[alice.id][0].group); expect(() => validateBackup(JSON.stringify(invalid))).toThrow() }
    bad(group => { group.releasedOperations[0].releasedReason = 'cancelled' })
    bad(group => { group.releasedOperations[0].delivery = 'accepted' })
    bad(group => { group.releasedOperations[0].expected = group.session })
    bad(group => { group.releasedOperations[0].kind = 'addition' })
    bad(group => { group.releasedOperations[0].controls = [group.releasedOperations[0].controls[0]] })
    bad(group => { group.releasedOperations[0].welcomes = [group.releasedOperations[0].controls[0]] })
    bad(group => { group.releasedOperations[0].target.keyId = hex(alice.identity.keyID) })
    bad(group => { group.releasedOperations[0].origin = { kind: 'remove', controls: group.releasedOperations[0].controls, welcomes: [], delivered: 0, delivery: 'unknown' } })
    bad(group => { group.releasedOperations[0].releasedAt = -1 })
    bad(group => { group.releasedOperations[0].superseded = [{ kind: 'rekey', controls: [group.releasedOperations[0].controls[1]], welcomes: [], delivered: 0, delivery: 'unknown' }] })
    bad(group => { group.releasedOperations = Array.from({ length: MAX_GROUP_OPERATION_REVISIONS + 1 }, () => group.releasedOperations[0]) })
    bad(group => { group.releasedOperations = 'none' })
    const legacy = structuredClone(data); delete legacy.conversations[alice.id][0].group.releasedOperations
    expect(() => validateBackup(JSON.stringify(legacy))).not.toThrow()
    const partial = structuredClone(data); partial.conversations[alice.id][0].group.releasedOperations[0].delivered = 1
    expect(() => validateBackup(JSON.stringify(partial))).not.toThrow()
    // Receive commits keep the archive intact.
    await sendContactGroupMessage(bob.id, id, 'after restore')
    await syncContactGroup(alice.id, id)
    expect(archive(alice.id, id)).toEqual(saved)
    expect(marshalCanonical(archive(alice.id, id)).length).toBeGreaterThan(0)
  })
})
