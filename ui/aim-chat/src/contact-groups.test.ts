import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateIdentity, DropboxClient, createMessage, groupSessionConversation, serializeEnvelope,
  deserializeEnvelope, isGroupWelcomeEnvelope, openGroupWelcome, parseGroupLink, receiveGroupEvent, createGroupSession,
  createGroupLink, keyIDFromPublicKey, base64UrlDecode, base64UrlEncode, prepareGroupWelcomeRefresh, groupSessionFromWelcome,
  prepareGroupSessionAddition, prepareGroupSessionRekey, prepareGroupAdmissionRenewal, createGroupControlMessage, createGroupRemoveBody, assertGroupCanSend } from '@corpollc/qntm'
import type { SubscriptionMessage, Identity, GroupSessionState } from '@corpollc/qntm'
import * as store from './store'
import { validateBackup, rawBackup, exportEncryptedBackup, prepareBackup, restoreBackup } from './backup'
import { createContactGroup, changeContactGroup, pinContact, openContactGroup, syncContactGroup, publicGroupLink, sendContactGroupMessage, hex, bytes, retryContactGroup, isCurrentGroupMessage, controlAccepted } from './contact-groups'

const relay = new Map<string, SubscriptionMessage[]>()
const heads = new Map<string, number>()
let failPost = false
let hideReplay = false
const SEEN_BOUND = 8192
function profile(name: string, identity = generateIdentity()) {
  const p = store.createProfile(name)
  store.saveIdentity(p.id, { privateKey: hex(identity.privateKey), publicKey: hex(identity.publicKey), keyId: hex(identity.keyID) })
  return { id: p.id, identity }
}
async function post(id: string, envelope: ReturnType<typeof createMessage>) {
  await new DropboxClient('http://localhost').postMessage(bytes(id), serializeEnvelope(envelope))
}
async function savedAddition(alice: ReturnType<typeof profile>, bob: ReturnType<typeof profile>, options: { ttl?: number; challenge?: string; competing?: boolean; partial?: boolean } = {}) {
  const id = await createContactGroup(alice.id, 'Pending admission'), record = store.findConversation(alice.id, id)!
  pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
  let original = prepareGroupSessionAddition(alice.identity, record.group!.session, [bob.identity.publicKey], options.ttl,
    options.challenge ? bytes(options.challenge) : undefined, record.group!.cursor)
  if (options.competing) {
    for (let n = 0; original.rekey.msg_id[0] < 128 && n < 128; n++) original = prepareGroupSessionAddition(alice.identity, record.group!.session,
      [bob.identity.publicKey], options.ttl, options.challenge ? bytes(options.challenge) : undefined, record.group!.cursor)
    expect(original.rekey.msg_id[0]).toBeGreaterThanOrEqual(128)
  }
  let expected = record.group!.session
  for (const control of [original.addition, original.rekey]) expected = receiveGroupEvent(alice.identity, control, expected).state
  const operation: store.StoredGroupOperation = { kind: 'addition', controls: [original.addition, original.rekey].map(e => base64UrlEncode(serializeEnvelope(e))),
    welcomes: original.welcomes.map(e => base64UrlEncode(serializeEnvelope(e))), delivered: 0, expected }
  store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
  await post(id, original.addition); await syncContactGroup(alice.id, id)
  if (options.competing) {
    let competing = prepareGroupSessionRekey(alice.identity, session(alice.id, id))
    for (let n = 0; hex(competing.rekey.msg_id) >= hex(original.rekey.msg_id) && n < 512; n++) competing = prepareGroupSessionRekey(alice.identity, session(alice.id, id))
    expect(hex(competing.rekey.msg_id) < hex(original.rekey.msg_id)).toBe(true)
    await post(id, competing.rekey)
  } else if (!options.partial) await post(id, original.rekey)
  await syncContactGroup(alice.id, id)
  return { id, operation, link: publicGroupLink(alice.id, id), source: record.group!.session }
}
function session(profile: string, id: string) { return store.findConversation(profile, id)!.group!.session }
function host(profile: string, id: string) { return store.findConversation(profile, id)!.group! }
function omit(id: string, seq: number) { relay.set(id, relay.get(id)!.filter(row => row.seq !== seq)) }
async function admittedGroup(alice: ReturnType<typeof profile>, bob: ReturnType<typeof profile>, name = 'Control receipts') {
  const id = await createContactGroup(alice.id, name)
  pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
  const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
  await openContactGroup(bob.id, link)
  return { id, link, source: structuredClone(session(alice.id, id)) }
}
async function acceptedPendingRekey(alice: ReturnType<typeof profile>, bob: ReturnType<typeof profile>, highId = true) {
  const { id, source } = await admittedGroup(alice, bob)
  const current = session(alice.id, id)
  let pending = prepareGroupSessionRekey(alice.identity, current)
  for (let n = 0; highId && pending.rekey.msg_id[0] < 128 && n < 128; n++) pending = prepareGroupSessionRekey(alice.identity, current)
  if (highId) expect(pending.rekey.msg_id[0]).toBeGreaterThanOrEqual(128)
  const expected = receiveGroupEvent(alice.identity, pending.rekey, current).state
  const operation: store.StoredGroupOperation = { kind: 'rekey', controls: [base64UrlEncode(serializeEnvelope(pending.rekey))], welcomes: [], delivered: 0, expected }
  store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
  await post(id, pending.rekey); await syncContactGroup(alice.id, id); await syncContactGroup(bob.id, id)
  return { id, source, operation: structuredClone(host(alice.id, id).operation!) }
}
function pressureSeen(profile: string, id: string, keep: string[]) {
  // Synthetic cache pressure to the legal 8192 bound. The kept IDs are not
  // deleted; a following authenticated event still has to drive eviction.
  const data = JSON.parse(rawBackup()), conv = data.conversations[profile].find((row: { id: string }) => row.id === id)
  const seen = conv.group.session.seen, next: Record<string, { digest: string; epoch: number }> = {}
  for (const mid of keep) next[mid] = seen[mid]
  for (let index = 1; Object.keys(next).length < SEEN_BOUND; index++) {
    const dummy = index.toString(16).padStart(32, '0')
    if (!next[dummy]) next[dummy] = { digest: '00'.repeat(32), epoch: 0 }
  }
  conv.group.session.seen = next
  localStorage.setItem('aim-store', JSON.stringify(data))
}
async function evictWithAuthenticatedTraffic(alice: ReturnType<typeof profile>, bob: ReturnType<typeof profile>, id: string, keep: string[]) {
  pressureSeen(alice.id, id, keep)
  for (let index = 0; index < keep.length + 1; index++) {
    await post(id, createMessage(bob.identity, groupSessionConversation(session(bob.id, id)), 'text', new TextEncoder().encode(`cache pressure ${index}`)))
    await syncContactGroup(bob.id, id)
    await syncContactGroup(alice.id, id)
  }
  for (const mid of keep) expect(session(alice.id, id).seen[mid]).toBeUndefined()
  return host(alice.id, id)
}
afterEach(() => vi.unstubAllGlobals())
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto)
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: async (_name: string, action: () => unknown) => action() } })
  localStorage.clear(); relay.clear(); heads.clear(); failPost = false; hideReplay = false
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
    const entries = hideReplay ? [] : (relay.get(hex(id)) ?? []).filter(row => row.seq > from)
    return { entries, messages: entries.map(row => row.envelope), sequence: heads.get(hex(id)) ?? 0 }
  })
})
describe('browser contact group host', () => {
  it.each(['expired', 'changed roster'] as const)('repairs an accepted addition with an %s rotation, then preserves repeated repairs and renewals through restart', async reason => {
    const alice = profile('Alice'), bob = profile('Bob'), challenge = 'ef'.repeat(32)
    const { id, operation, source, link } = await savedAddition(alice, bob, { ttl: 10, challenge, partial: true })
    const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now())
    if (reason === 'expired') clock.mockReturnValue((deserializeEnvelope(base64UrlDecode(operation.controls[1])).expiry_ts + 1) * 1000)
    else {
      const concurrent = prepareGroupSessionAddition(alice.identity, source, [generateIdentity().publicKey])
      await post(id, concurrent.addition); await syncContactGroup(alice.id, id)
    }
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const first = store.findConversation(alice.id, id)!.group!.operation!
    expect(first.kind).toBe('addition_rekey'); expect(first.welcomes).toEqual([])
    expect(first.controls).toHaveLength(1); expect(first.controls[0]).not.toBe(operation.controls[1])
    expect(first.origin?.controls).toEqual(operation.controls); expect(first.origin?.welcomes).toEqual(operation.welcomes)
    expect(first.expected.rekeys).toEqual([]); expect(first.origin).not.toHaveProperty('expected')
    expect(session(alice.id, id).epoch).toBe(0); expect(session(alice.id, id).needsRekey).toBe(true)
    expect(session(alice.id, id).admissions[hex(bob.identity.keyID)].completion).toBeNull()
    const encrypted = await exportEncryptedBackup('synthetic repeated rotation backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic repeated rotation backup password'))
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    expect(vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))).toEqual(first.controls)
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(first)
    clock.mockReturnValue((deserializeEnvelope(base64UrlDecode(first.controls[0])).expiry_ts + 1) * 1000)
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const second = store.findConversation(alice.id, id)!.group!.operation!
    expect(second.controls).not.toEqual(first.controls); expect(second.origin).toEqual(first.origin)
    expect(second.superseded).toEqual([{ kind: 'addition_rekey', controls: first.controls, welcomes: [], delivered: 0, delivery: 'unknown' }])
    const original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    failPost = false
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      if (isGroupWelcomeEnvelope(deserializeEnvelope(wire))) throw new Error('Delivery uncertain')
      return original.call(this, cid, wire)
    })
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const renewed = store.findConversation(alice.id, id)!.group!.operation!
    expect(renewed.kind).toBe('renewal'); expect(renewed.origin).toEqual(first.origin)
    expect(session(alice.id, id).epoch).toBe(1); expect(session(alice.id, id).needsRekey).toBe(false)
    expect(renewed.superseded?.map(entry => entry.controls)).toEqual([first.controls, second.controls])
    expect(renewed.expected.rekeys).toEqual([])
    clock.mockReturnValue((deserializeEnvelope(base64UrlDecode(renewed.welcomes[0])).expiry_ts + 1) * 1000)
    failPost = true; vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(original)
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const latest = store.findConversation(alice.id, id)!.group!.operation!
    expect(latest.superseded).toEqual([...renewed.superseded!, { kind: 'renewal', controls: [], welcomes: renewed.welcomes, delivered: 0, delivery: 'unknown' }])
    expect(latest.origin).toEqual(first.origin)
    expect(hex(openGroupWelcome(bob.identity, base64UrlDecode(latest.welcomes[0]), parseGroupLink(link)).recoveryChallenge!)).toBe(challenge)
    const finalBackup = await exportEncryptedBackup('synthetic final renewal archive password')
    localStorage.clear(); restoreBackup(await prepareBackup(finalBackup, 'synthetic final renewal archive password'))
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(latest)
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))).toEqual(latest.welcomes)
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).epoch).toBe(1); expect(session(bob.id, id).rekeys).toEqual([])
    expect(Object.keys(session(bob.id, id).admissions)).toHaveLength(reason === 'expired' ? 1 : 2)
  })

  it('keeps repair keys uninstalled and withholds welcomes when an ACK lacks authenticated replay', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await savedAddition(alice, bob, { ttl: 10, partial: true })
    vi.spyOn(Date, 'now').mockReturnValue((deserializeEnvelope(base64UrlDecode(operation.controls[1])).expiry_ts + 1) * 1000)
    const before = session(alice.id, id), original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      const seq = await original.call(this, cid, wire); hideReplay = true; return seq
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/not replayed/i)
    const pending = store.findConversation(alice.id, id)!.group!.operation!
    expect(pending.kind).toBe('addition_rekey'); expect(pending.welcomes).toEqual([])
    expect(session(alice.id, id).root).toBe(before.root); expect(session(alice.id, id).epoch).toBe(before.epoch)
    expect(session(alice.id, id).recovery).not.toBeNull()
    expect(vi.mocked(DropboxClient.prototype.postMessage)).toHaveBeenCalledTimes(1)
  })

  it('renews an expired standalone reviewed renewal without inventing an addition origin', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Reviewed renewal retry'); pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid), challenge = '34'.repeat(32)
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'refresh', kid, challenge)).rejects.toThrow('Delivery uncertain')
    const before = store.findConversation(alice.id, id)!.group!.operation!
    vi.spyOn(Date, 'now').mockReturnValue((deserializeEnvelope(base64UrlDecode(before.welcomes[0])).expiry_ts + 1) * 1000)
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const next = store.findConversation(alice.id, id)!.group!.operation!
    expect(next.origin).toBeUndefined(); expect(next.admission).toEqual(before.admission)
    expect(next.superseded).toEqual([{ kind: 'renewal', controls: [], welcomes: before.welcomes, delivered: 0, delivery: 'unknown' }])
    expect(hex(openGroupWelcome(bob.identity, base64UrlDecode(next.welcomes[0]), parseGroupLink(link)).recoveryChallenge!)).toBe(challenge)
    expect(() => validateBackup(rawBackup())).not.toThrow()
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))).toEqual(next.welcomes)
  }, 15_000)

  it.each(['revisions', 'bytes'] as const)('preserves the exact pending operation without POST when recovery evidence reaches its %s bound', async limit => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await savedAddition(alice, bob, { ttl: 10 })
    const clock = vi.spyOn(Date, 'now').mockReturnValue((deserializeEnvelope(base64UrlDecode(operation.welcomes[0])).expiry_ts + 1) * 1000)
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    store.updateConversation(alice.id, id, conv => {
      const op = conv.group!.operation as Extract<store.StoredGroupOperation, { kind: 'renewal' }>
      op.superseded = Array.from({ length: limit === 'revisions' ? 256 : 1 }, () => ({ kind: 'renewal' as const, controls: [],
        welcomes: limit === 'bytes' ? ['A'.repeat(4 * 1024 * 1024)] : [...op.welcomes], delivered: 0, delivery: 'unknown' as const }))
      return conv
    })
    const pending = store.findConversation(alice.id, id)!.group!.operation!
    clock.mockReturnValue((deserializeEnvelope(base64UrlDecode(pending.welcomes[0])).expiry_ts + 1) * 1000)
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/evidence.*limit/i)
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(pending)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
  }, 15_000)

  it('rejects malformed repair and superseded evidence in backups before replacement', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await savedAddition(alice, bob, { ttl: 10, partial: true })
    vi.spyOn(Date, 'now').mockReturnValue((deserializeEnvelope(base64UrlDecode(operation.controls[1])).expiry_ts + 1) * 1000)
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const original = rawBackup(), data = JSON.parse(original), repair = store.findConversation(alice.id, id)!.group!.operation!
    const entry = { kind: 'addition_rekey', controls: repair.controls, welcomes: [], delivered: 0, delivery: 'unknown' }
    const corruptions = [
      (op: any) => { op.controls = [operation.controls[1]] },
      (op: any) => { delete op.origin },
      (op: any) => { op.expected.admissions[hex(bob.identity.keyID)].completion.rekeyDigest = 'ab'.repeat(32) },
      (op: any) => { op.superseded = [{ ...entry, expected: repair.expected }] },
      (op: any) => { op.superseded = [{ ...entry, origin: repair.origin }] },
      (op: any) => { op.superseded = [{ ...entry, delivery: 'confirmed' }] },
      (op: any) => { op.superseded = [{ ...entry, delivered: 1 }] },
      (op: any) => { op.superseded = [{ ...entry, kind: 'addition' }] },
      (op: any) => { op.superseded = [{ ...entry, controls: [], welcomes: repair.origin!.welcomes }] },
      (op: any) => { op.superseded = Array.from({ length: 257 }, () => entry) },
    ]
    for (const corrupt of corruptions) {
      const invalid = structuredClone(data); corrupt(invalid.conversations[alice.id][0].group.operation)
      expect(() => validateBackup(JSON.stringify(invalid))).toThrow()
      expect(rawBackup()).toBe(original)
    }
    const oversized = structuredClone(data)
    const envelope = { ...deserializeEnvelope(base64UrlDecode(repair.controls[0])), ciphertext: new Uint8Array(18_000) }
    oversized.conversations[alice.id][0].group.operation.superseded = Array.from({ length: 180 }, () => ({ ...entry, controls: [base64UrlEncode(serializeEnvelope(envelope))] }))
    expect(() => validateBackup(JSON.stringify(oversized))).toThrow(/byte limit/i)
    expect(rawBackup()).toBe(original)
  })

  it('never publishes an unknown old-source standalone rekey; the verified later rotation fulfils the intent', async () => {
    const alice = profile('Alice'), id = await createContactGroup(alice.id, 'Stale producer'), source = session(alice.id, id)
    const proposals = [prepareGroupSessionRekey(alice.identity, source), prepareGroupSessionRekey(alice.identity, source)]
      .sort((a, b) => hex(a.rekey.msg_id).localeCompare(hex(b.rekey.msg_id)))
    const [pending, accepted] = proposals
    const expected = receiveGroupEvent(alice.identity, pending.rekey, source).state
    const operation: store.StoredGroupOperation = { kind: 'rekey', controls: [base64UrlEncode(serializeEnvelope(pending.rekey))], welcomes: [], delivered: 0, expected }
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    await post(id, accepted.rekey); await syncContactGroup(alice.id, id)
    const current = session(alice.id, id)
    expect(receiveGroupEvent(alice.identity, pending.rekey, current).rewound).toBe(true)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    // Receivers would accept the lower-ID proposal as a late competitor, but a
    // producer that has verified a later epoch never republishes old-source
    // controls; the verified rotation already fulfilled its rotation intent.
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(session(alice.id, id)).toEqual(current)
    expect(store.findConversation(alice.id, id)!.group!.operation).toBeNull()
  })
  it('retries a completed addition after seen eviction without reposting either accepted control', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation, link } = await savedAddition(alice, bob)
    store.updateConversation(alice.id, id, conv => { conv.group!.session.seen = {}; return conv })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    expect(await retryContactGroup(alice.id, id)).toBe(link)
    const calls = vi.mocked(DropboxClient.prototype.postMessage).mock.calls
    expect(calls).toHaveLength(1)
    expect(base64UrlEncode(calls[0][1])).toBe(operation.welcomes[0])
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).recovery).toBeNull()
  })

  it.each(['expired', 'advanced', 'competing'] as const)('reconciles a completed %s addition into one challenge-preserving current renewal and exact backup retry', async reason => {
    const alice = profile('Alice'), bob = profile('Bob'), challenge = 'cd'.repeat(32)
    const { id, operation, link } = await savedAddition(alice, bob, { ttl: reason === 'expired' ? 10 : undefined, challenge, competing: reason === 'competing' })
    if (reason === 'expired') { const future = Date.now() + 11_000; vi.spyOn(Date, 'now').mockReturnValue(future) }
    if (reason === 'advanced') { await post(id, prepareGroupSessionRekey(alice.identity, session(alice.id, id)).rekey); await syncContactGroup(alice.id, id) }
    const expected = session(alice.id, id), rows = relay.get(id)!.length
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const pending = store.findConversation(alice.id, id)!.group!.operation!
    expect(pending.kind).toBe('renewal'); expect(pending.controls).toEqual([])
    expect(pending.expected.root).toBe(expected.root); expect(pending.expected.rekeys).toEqual([])
    expect(pending.origin).toEqual({ kind: 'addition', controls: operation.controls, welcomes: operation.welcomes, delivered: 0,
      recipient: hex(bob.identity.publicKey), admission: { addId: expected.admissions[hex(bob.identity.keyID)].addId, addDigest: expected.admissions[hex(bob.identity.keyID)].addDigest }, recoveryChallenge: challenge, delivery: 'unknown' })
    expect(pending.origin).not.toHaveProperty('expected')
    const opened = openGroupWelcome(bob.identity, base64UrlDecode(pending.welcomes[0]), parseGroupLink(link))
    expect(opened.purpose).toBe('renewal'); expect(hex(opened.recoveryChallenge!)).toBe(challenge)
    expect(opened.admissions).toEqual(expected.admissions)
    const encrypted = await exportEncryptedBackup('synthetic reconciled admission backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic reconciled admission backup password'))
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(pending)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear(); failPost = false
    expect(await retryContactGroup(alice.id, id)).toBe(link)
    expect(vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))).toEqual(pending.welcomes)
    expect(relay.get(id)).toHaveLength(rows + 1)
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).root).toBe(expected.root); expect(session(bob.id, id).rekeys).toEqual([])
  })

  it('reconciles an already staged renewal after repeated expiry and rejects corrupt origin backups', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id } = await savedAddition(alice, bob, { ttl: 10 })
    const future = Date.now() + 11_000; const clock = vi.spyOn(Date, 'now').mockReturnValue(future)
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const before = rawBackup(), data = JSON.parse(before)
    for (const mutate of [
      (origin: any) => { origin.expected = session(alice.id, id) },
      (origin: any) => { origin.origin = {} },
      (origin: any) => { origin.admission.addDigest = '12'.repeat(32) },
      (origin: any) => { origin.recipient = hex(alice.identity.publicKey) },
      (origin: any) => { origin.delivery = 'accepted' },
      (origin: any) => { origin.recoveryChallenge = 'not a challenge' },
    ]) {
      const invalid = structuredClone(data); mutate(invalid.conversations[alice.id][0].group.operation.origin)
      expect(() => validateBackup(JSON.stringify(invalid))).toThrow()
      expect(rawBackup()).toBe(before)
    }
    const pending = store.findConversation(alice.id, id)!.group!.operation
    clock.mockReturnValue(future + 604_801_000)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const replacement = store.findConversation(alice.id, id)!.group!.operation!
    expect(replacement.kind).toBe('renewal'); expect(replacement.origin).toEqual(pending!.origin)
    expect(replacement.superseded).toEqual([{ kind: 'renewal', controls: [], welcomes: pending!.welcomes, delivered: 0, delivery: 'unknown' }])
    expect(replacement.welcomes).not.toEqual(pending!.welcomes)
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage).mock.calls.map(call => base64UrlEncode(call[1]))).toEqual(replacement.welcomes)
  })

  it.each(['removed', 'readmitted', 'recovery', 'pending rotation', 'missing old proof', 'changed challenge'] as const)('preserves a completed saved addition blocked by %s', async reason => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const { id, operation } = await savedAddition(alice, bob, { ttl: 10 })
    if (reason === 'removed' || reason === 'readmitted') {
      const remove = createGroupControlMessage(alice.identity, groupSessionConversation(session(alice.id, id)), 'group_remove', createGroupRemoveBody([bob.identity.keyID]))
      await post(id, remove); await syncContactGroup(alice.id, id)
      await post(id, prepareGroupSessionRekey(alice.identity, session(alice.id, id)).rekey); await syncContactGroup(alice.id, id)
      if (reason === 'readmitted') {
        const addition = prepareGroupSessionAddition(alice.identity, session(alice.id, id), [bob.identity.publicKey])
        for (const control of [addition.addition, addition.rekey]) await post(id, control)
        await syncContactGroup(alice.id, id)
      }
    } else if (reason === 'pending rotation') {
      const addition = prepareGroupSessionAddition(alice.identity, session(alice.id, id), [generateIdentity().publicKey])
      await post(id, addition.addition); await syncContactGroup(alice.id, id)
    } else store.updateConversation(alice.id, id, conv => {
      if (reason === 'missing old proof') conv.group!.operation!.expected.admissions = {}
      else if (reason === 'changed challenge') (conv.group!.operation as Extract<store.StoredGroupOperation, { kind: 'addition' }>).recoveryChallenge = 'ab'.repeat(32)
      else conv.group!.session.recovery = { reason: 'missing_history', afterSequence: conv.group!.cursor, challenge: 'ab'.repeat(32) }
      return conv
    })
    const pending = store.findConversation(alice.id, id)!.group!.operation
    const future = Date.now() + 11_000; vi.spyOn(Date, 'now').mockReturnValue(future)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow()
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(pending)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(operation.kind).toBe('addition')
  })

  it('cleans a fully acknowledged welcome before network, stale expiry and recovery checks', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, link } = await savedAddition(alice, bob)
    store.updateConversation(alice.id, id, conv => {
      conv.group!.operation!.delivered = 1
      conv.group!.session.recovery = { reason: 'missing_history', afterSequence: conv.group!.cursor, challenge: 'ef'.repeat(32) }
      return conv
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    vi.mocked(DropboxClient.prototype.receiveMessages).mockRejectedValueOnce(new Error('offline'))
    const future = Date.now() + 604_801_000; vi.spyOn(Date, 'now').mockReturnValue(future)
    expect(await retryContactGroup(alice.id, id)).toBe(link)
    expect(store.findConversation(alice.id, id)!.group!.operation).toBeNull()
    expect(session(alice.id, id).recovery).not.toBeNull()
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
  })

  it('rechecks original control release after a concurrent removal during the preceding POST', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), id = await createContactGroup(alice.id, 'Concurrent removal')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))).rejects.toThrow('Delivery uncertain')
    const pending = store.findConversation(alice.id, id)!.group!.operation!, before = session(alice.id, id)
    const original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    failPost = false; vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      const receipt = await original.call(this, cid, wire)
      const admitted = receiveGroupEvent(alice.identity, deserializeEnvelope(wire), before).state
      const removal = createGroupControlMessage(alice.identity, groupSessionConversation(admitted), 'group_remove', createGroupRemoveBody([bob.identity.keyID]))
      await original.call(this, cid, serializeEnvelope(removal))
      return receipt
    })
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/no longer.*admission/i)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).toHaveBeenCalledTimes(1)
    expect(session(alice.id, id).admissions[hex(bob.identity.keyID)]).toBeUndefined()
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(pending)
    expect(relay.get(id)).toHaveLength(3)
  })

  it('does not replace or publish an operation changed during receive catch-up', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id } = await savedAddition(alice, bob)
    const original = vi.mocked(DropboxClient.prototype.receiveMessages).getMockImplementation()!
    vi.mocked(DropboxClient.prototype.receiveMessages).mockImplementationOnce(async function (this: DropboxClient, ...args) {
      const result = await original.apply(this, args)
      store.updateConversation(alice.id, id, conv => { (conv.group!.operation as Extract<store.StoredGroupOperation, { kind: 'addition' }>).recoveryChallenge = '12'.repeat(32); return conv })
      return result
    })
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/operation changed/i)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(store.findConversation(alice.id, id)!.group!.operation!.recoveryChallenge).toBe('12'.repeat(32))
  })
  it('keeps genesis pending when the relay acknowledges delivery but withholds replay', async () => {
    const alice = profile('Alice')
    hideReplay = true
    await expect(createContactGroup(alice.id, 'Pending creation')).rejects.toThrow(/not replayed/)
    const record = store.listConversations(alice.id)[0]
    expect(record.group!.operation!.kind).toBe('create')
    expect(record.group!.session.recovery).toBeNull()
    hideReplay = false
    await retryContactGroup(alice.id, record.id)
    expect(store.findConversation(alice.id, record.id)!.group!.operation).toBeNull()
    expect(relay.get(record.id)).toHaveLength(1)
  })
  it('adds contacts before they open, supports reverse opening order and member-initiated addition', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), dave = profile('Dave')
    const id = await createContactGroup(alice.id, 'Contact room')
    await sendContactGroupMessage(alice.id, id, 'before admission')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey)); pinContact(alice.id, 'Carol', hex(carol.identity.publicKey))
    const bobLink = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    const carolLink = await changeContactGroup(alice.id, id, 'add', hex(carol.identity.keyID))
    expect(carolLink).toBe(bobLink)
    await openContactGroup(carol.id, carolLink)
    await openContactGroup(bob.id, bobLink)
    expect(session(bob.id, id).epoch).toBe(2)
    expect(store.getHistory(bob.id, id)).toEqual([])
    await sendContactGroupMessage(bob.id, id, 'late opener reply')
    await syncContactGroup(alice.id, id)
    expect(store.getHistory(alice.id, id).at(-1)?.text).toBe('late opener reply')
    pinContact(bob.id, 'Dave', hex(dave.identity.publicKey))
    const daveLink = await changeContactGroup(bob.id, id, 'add', hex(dave.identity.keyID))
    await openContactGroup(dave.id, daveLink)
    expect(session(dave.id, id).epoch).toBe(3)
    expect(parseGroupLink(daveLink).inviterPublicKey).toEqual(bob.identity.publicKey)
  })
  it('catches a rotation posted before a delayed admission welcome', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    let raced = false
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      if (!raced && (deserializeEnvelope(wire) as { kind?: string }).kind === 'group_welcome') {
        raced = true
        const rekey = prepareGroupSessionRekey(alice.identity, session(alice.id, id))
        await original.call(this, cid, serializeEnvelope(rekey.rekey))
      }
      return original.call(this, cid, wire)
    })
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).epoch).toBe(2)
    await sendContactGroupMessage(bob.id, id, 'caught delayed welcome rotation')
    await syncContactGroup(alice.id, id)
    expect(store.getHistory(alice.id, id).at(-1)?.text).toBe('caught delayed welcome rotation')
  })

  it('opens a current admission renewal after later rotations without retaining pre-admission roots', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Delayed opening')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await changeContactGroup(alice.id, id, 'rekey')
    await changeContactGroup(alice.id, id, 'rekey')
    const current = session(alice.id, id), { addId, addDigest } = current.admissions[hex(bob.identity.keyID)]
    const renewal = prepareGroupAdmissionRenewal(alice.identity, current, bob.identity.publicKey,
      { addId, addDigest }, undefined, undefined, store.findConversation(alice.id, id)!.group!.cursor)
    await post(id, renewal.welcomes[0])
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).epoch).toBe(3)
    expect(session(bob.id, id).root).toBe(current.root)
    expect(session(bob.id, id).admissions).toEqual(current.admissions)
    expect(session(bob.id, id).rekeys).toEqual([])
    await sendContactGroupMessage(bob.id, id, 'renewed admission reply')
    await syncContactGroup(alice.id, id)
    expect(store.getVisibleHistory(alice.id, id).at(-1)?.text).toBe('renewed admission reply')
  })

  it.each(['refresh', 'renewal'] as const)('prefers a current %s over a later replay of the same-epoch addition welcome', async purpose => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Current welcome')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid)
    const originalWelcome = relay.get(id)!.at(-1)!.envelope
    await sendContactGroupMessage(alice.id, id, 'before the current welcome snapshot')
    await syncContactGroup(alice.id, id)
    const current = session(alice.id, id), anchor = store.findConversation(alice.id, id)!.group!.cursor
    const { addId, addDigest } = current.admissions[kid]
    const fresh = purpose === 'refresh'
      ? prepareGroupWelcomeRefresh(alice.identity, current, [bob.identity.publicKey], undefined, undefined, anchor)
      : prepareGroupAdmissionRenewal(alice.identity, current, bob.identity.publicKey, { addId, addDigest }, undefined, undefined, anchor)
    await post(id, fresh.welcomes[0])
    // A relay can replay ciphertext at a later sequence; that does not make
    // the older addition snapshot fresher than the signed current welcome.
    const seq = heads.get(id)! + 1; heads.set(id, seq)
    relay.get(id)!.push({ seq, envelope: originalWelcome })
    await openContactGroup(bob.id, link)
    expect(store.findConversation(bob.id, id)!.group!.bootstrapSequence).toBe(anchor)
    expect(session(bob.id, id).recovery).toBeNull()
  })

  it('orders competing addition welcomes by their own rekey IDs while keeping unresolved replay paused', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Competing welcomes'), source = session(alice.id, id)
    const anchor = store.findConversation(alice.id, id)!.group!.cursor
    const [canonical, later] = [
      prepareGroupSessionAddition(alice.identity, source, [bob.identity.publicKey], undefined, undefined, anchor),
      prepareGroupSessionAddition(alice.identity, source, [bob.identity.publicKey], undefined, undefined, anchor),
    ].sort((a, b) => hex(a.rekey.msg_id).localeCompare(hex(b.rekey.msg_id)))
    expect(hex(canonical.rekey.msg_id) < hex(later.rekey.msg_id)).toBe(true)
    for (const operation of [canonical, later]) {
      for (const envelope of [operation.addition, operation.rekey, ...operation.welcomes]) await post(id, envelope)
    }
    await openContactGroup(bob.id, publicGroupLink(alice.id, id))
    expect(session(bob.id, id).root).toBe(hex(canonical.conversation.keys.root))
    expect(session(bob.id, id).recovery).not.toBeNull()
    await expect(sendContactGroupMessage(bob.id, id, 'unresolved competing welcome')).rejects.toThrow(/history/i)
  })

  it('falls back from a newer refresh to valid readmission renewal and preserves the removal fence', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Renewed readmission')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid)
    await openContactGroup(bob.id, link)
    await changeContactGroup(alice.id, id, 'remove', kid)
    await syncContactGroup(bob.id, id)
    const removedAt = session(bob.id, id).removedAtEpoch
    expect(removedAt).toBe(1)
    await changeContactGroup(alice.id, id, 'add', kid)
    await changeContactGroup(alice.id, id, 'rekey')
    const current = session(alice.id, id), { addId, addDigest } = current.admissions[kid]
    const anchor = store.findConversation(alice.id, id)!.group!.cursor
    await changeContactGroup(alice.id, id, 'refresh', kid)
    const renewal = openGroupWelcome(bob.identity, relay.get(id)!.at(-1)!.envelope, parseGroupLink(link))
    expect(renewal.purpose).toBe('renewal')
    expect(renewal.admissions[kid]).toMatchObject({ addId, addDigest })
    const refresh = prepareGroupWelcomeRefresh(alice.identity, current, [bob.identity.publicKey], undefined, undefined, anchor)
    await post(id, refresh.welcomes[0])
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).epoch).toBe(4)
    expect(session(bob.id, id).removed).toBe(false)
    expect(session(bob.id, id).removedAtEpoch).toBe(removedAt)
    expect(session(bob.id, id).admissions[kid]).toEqual(current.admissions[kid])
    expect(session(bob.id, id).rekeys).toEqual([])
    await changeContactGroup(alice.id, id, 'remove', kid)
    await syncContactGroup(bob.id, id)
    const removed = session(bob.id, id)
    expect(removed.removedAtEpoch).toBe(4)
    await expect(openContactGroup(bob.id, link)).rejects.toThrow()
    expect(session(bob.id, id).removed).toBe(true)
    expect(session(bob.id, id).removedAtEpoch).toBe(4)
  })

  it('keeps founding and unknown admission refreshes generic, without undoing a saved removal', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Legacy admission')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey)); pinContact(bob.id, 'Alice', hex(alice.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid)
    await openContactGroup(bob.id, link)
    const bobLink = await changeContactGroup(bob.id, id, 'refresh', hex(alice.identity.keyID))
    expect(openGroupWelcome(alice.identity, relay.get(id)!.at(-1)!.envelope, parseGroupLink(bobLink)).purpose).toBe('refresh')
    await changeContactGroup(alice.id, id, 'remove', kid)
    await syncContactGroup(bob.id, id)
    const removed = session(bob.id, id)
    await changeContactGroup(alice.id, id, 'add', kid)
    // Older checkpoints can contain a valid roster without admission evidence.
    const record = store.findConversation(alice.id, id)!
    record.group!.session.admissions = {}
    store.updateConversation(alice.id, id, () => record)
    await changeContactGroup(alice.id, id, 'refresh', kid)
    const row = relay.get(id)!.at(-1)!, welcome = openGroupWelcome(bob.identity, row.envelope, parseGroupLink(link))
    expect(welcome.purpose).toBe('refresh')
    expect(() => groupSessionFromWelcome(bob.identity, welcome, row.seq, removed)).toThrow(/remov/i)
    expect(session(bob.id, id)).toEqual(removed)
  })

  it('preserves a renewal recipient, admission, challenge and exact ciphertext through encrypted backup retry', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Saved renewal')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid)
    const challenge = 'ab'.repeat(32), beforeRows = relay.get(id)!.length
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'refresh', kid, challenge)).rejects.toThrow('Delivery uncertain')
    const saved = store.findConversation(alice.id, id)!.group!.operation!
    expect(saved.kind).toBe('renewal'); expect(saved.controls).toEqual([])
    expect(saved.recipient).toBe(hex(bob.identity.publicKey))
    expect(saved.admission).toEqual(saved.expected.admissions[kid])
    const welcome = openGroupWelcome(bob.identity, base64UrlDecode(saved.welcomes[0]), parseGroupLink(link))
    expect(welcome.purpose).toBe('renewal'); expect(hex(welcome.recoveryChallenge!)).toBe(challenge)
    const encrypted = await exportEncryptedBackup('synthetic renewal backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic renewal backup password'))
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(saved)
    failPost = false
    expect(await retryContactGroup(alice.id, id)).toBe(link)
    expect(relay.get(id)).toHaveLength(beforeRows + 1)
    expect(base64UrlEncode(relay.get(id)!.at(-1)!.envelope)).toBe(saved.welcomes[0])
    expect(store.findConversation(alice.id, id)!.group!.operation).toBeNull()
  })

  it('rejects renewal backup proof changes and changed current provenance before retrying', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Renewal guard')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey)); pinContact(alice.id, 'Carol', hex(carol.identity.publicKey))
    await changeContactGroup(alice.id, id, 'add', kid)
    await changeContactGroup(alice.id, id, 'add', hex(carol.identity.keyID))
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'refresh', kid)).rejects.toThrow('Delivery uncertain')
    const original = rawBackup(), data = JSON.parse(original)
    const corruptions = [
      (op: any) => { delete op.recipient },
      (op: any) => { op.recipient = hex(carol.identity.publicKey) },
      (op: any) => { op.admission.addDigest = '12'.repeat(32) },
      (op: any) => { op.admission.completion = null },
      (op: any) => { delete op.expected.admissions[kid] },
      (op: any) => { op.welcomes.push(op.welcomes[0]) },
    ]
    for (const corrupt of corruptions) {
      const invalid = structuredClone(data); corrupt(invalid.conversations[alice.id][0].group.operation)
      expect(() => validateBackup(JSON.stringify(invalid))).toThrow()
      expect(rawBackup()).toBe(original)
    }
    const record = store.findConversation(alice.id, id)!, saved = record.group!.operation
    // Reconciliation cannot renew a different admission of the same recipient.
    record.group!.session.admissions[kid].addDigest = '34'.repeat(32)
    store.updateConversation(alice.id, id, () => record)
    const beforeRows = relay.get(id)!.length
    failPost = false
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/admission/i)
    expect(relay.get(id)).toHaveLength(beforeRows)
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(saved)
  })

  it('restores an older generic refresh journal as an exact generic retry', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), kid = hex(bob.identity.keyID)
    const id = await createContactGroup(alice.id, 'Older refresh')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', kid)
    const record = store.findConversation(alice.id, id)!, expected = record.group!.session
    const refresh = prepareGroupWelcomeRefresh(alice.identity, expected, [bob.identity.publicKey], undefined, undefined, record.group!.cursor)
    record.group!.operation = { kind: 'refresh', controls: [], welcomes: refresh.welcomes.map(w => base64UrlEncode(serializeEnvelope(w))), delivered: 0, expected }
    store.updateConversation(alice.id, id, () => record)
    const before = rawBackup()
    localStorage.clear(); restoreBackup(await prepareBackup(before))
    await retryContactGroup(alice.id, id)
    expect(base64UrlEncode(relay.get(id)!.at(-1)!.envelope)).toBe(record.group!.operation.welcomes[0])
    expect(openGroupWelcome(bob.identity, relay.get(id)!.at(-1)!.envelope, parseGroupLink(link)).purpose).toBe('refresh')
  })

  it.each(['expired', 'changed keys'] as const)('replaces an older %s generic refresh without upgrading its purpose, retaining repeated exact evidence and challenge', async reason => {
    const alice = profile('Alice'), bob = profile('Bob'), challenge = 'c7'.repeat(32)
    const id = await createContactGroup(alice.id, 'Generic recovery')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    const record = store.findConversation(alice.id, id)!, expected = record.group!.session
    const refresh = prepareGroupWelcomeRefresh(alice.identity, expected, [bob.identity.publicKey], 10, bytes(challenge), record.group!.cursor)
    const operation: store.StoredGroupOperation = { kind: 'refresh', controls: [], welcomes: refresh.welcomes.map(w => base64UrlEncode(serializeEnvelope(w))), delivered: 0, expected }
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    const now = vi.spyOn(Date, 'now').mockReturnValue(Date.now())
    if (reason === 'expired') now.mockReturnValue((refresh.welcomes[0].expiry_ts + 1) * 1000)
    else { await post(id, prepareGroupSessionRekey(alice.identity, session(alice.id, id)).rekey); await syncContactGroup(alice.id, id) }
    const posted = relay.get(id)!.length, anchor = heads.get(id)!
    failPost = true
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const first = store.findConversation(alice.id, id)!.group!.operation!
    expect(first.kind).toBe('refresh'); expect(first.recipient).toBe(hex(bob.identity.publicKey)); expect(first.recoveryChallenge).toBe(challenge)
    expect(first.expected.rekeys).toEqual([]); expect(first.origin).toBeUndefined(); expect(first.admission).toBeUndefined()
    expect(first.superseded).toEqual([{ kind: 'refresh', controls: [], welcomes: operation.welcomes, delivered: 0, delivery: 'unknown' }])
    const opened = openGroupWelcome(bob.identity, base64UrlDecode(first.welcomes[0]), parseGroupLink(link))
    expect(opened.purpose).toBe('refresh'); expect(hex(opened.recoveryChallenge!)).toBe(challenge); expect(opened.replayFromSequence).toBe(anchor)
    // Even now-known admission evidence cannot turn generic recovery into readmission.
    expect(() => groupSessionFromWelcome(bob.identity, opened, posted + 1, {
      ...createGroupSession(bob.identity, opened.conversation, opened.state, { admissions: opened.admissions }), removed: true, removedAtEpoch: 0,
    })).toThrow(/remov/i)
    const encrypted = await exportEncryptedBackup('generic recovery password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'generic recovery password'))
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(first)
    now.mockReturnValue((deserializeEnvelope(base64UrlDecode(first.welcomes[0])).expiry_ts + 1) * 1000)
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow('Delivery uncertain')
    const second = store.findConversation(alice.id, id)!.group!.operation!
    expect(second.superseded).toEqual([...first.superseded!, { kind: 'refresh', controls: [], welcomes: first.welcomes, delivered: 0, delivery: 'unknown' }])
    expect(second.recoveryChallenge).toBe(challenge)
    failPost = false; await retryContactGroup(alice.id, id)
    expect(relay.get(id)!.length).toBe(posted + 1)
    expect(base64UrlEncode(relay.get(id)!.at(-1)!.envelope)).toBe(second.welcomes[0])
  }, 15_000)

  it('records explicit full recipient and challenge on a founding-member generic refresh', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), challenge = 'e3'.repeat(32)
    const id = await createContactGroup(alice.id, 'Founder')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link); pinContact(bob.id, 'Alice', hex(alice.identity.publicKey))
    failPost = true
    await expect(changeContactGroup(bob.id, id, 'refresh', hex(alice.identity.keyID), challenge)).rejects.toThrow('Delivery uncertain')
    const op = store.findConversation(bob.id, id)!.group!.operation!
    expect(op.kind).toBe('refresh'); expect(op.recipient).toBe(hex(alice.identity.publicKey)); expect(op.recoveryChallenge).toBe(challenge)
    expect(validateBackup(rawBackup())).toBeTruthy()
    failPost = false; await retryContactGroup(bob.id, id)
    expect(base64UrlEncode(relay.get(id)!.at(-1)!.envelope)).toBe(op.welcomes[0])
  })

  it.each(['recipient', 'sender', 'recovery', 'rotation'] as const)('preserves a stale generic refresh without POST when blocked by %s', async reason => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Blocked refresh')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    const record = store.findConversation(alice.id, id)!, refresh = prepareGroupWelcomeRefresh(alice.identity, record.group!.session, [bob.identity.publicKey], 10)
    const operation: store.StoredGroupOperation = { kind: 'refresh', controls: [], welcomes: refresh.welcomes.map(w => base64UrlEncode(serializeEnvelope(w))), delivered: 0, expected: record.group!.session }
    if (reason === 'recipient') {
      const remove = createGroupControlMessage(alice.identity, groupSessionConversation(record.group!.session), 'group_remove', createGroupRemoveBody([bob.identity.keyID]))
      await post(id, remove); await syncContactGroup(alice.id, id)
      if (reason === 'recipient') { await post(id, prepareGroupSessionRekey(alice.identity, session(alice.id, id)).rekey); await syncContactGroup(alice.id, id) }
    } else store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, session: { ...conv.group!.session,
      ...(reason === 'sender' ? { removed: true, removedAtEpoch: conv.group!.session.epoch } : reason === 'recovery' ? { recovery: { reason: 'missing_history', challenge: 'a1'.repeat(32), afterSequence: conv.group!.cursor } } : { needsRekey: true }) } } }))
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    vi.spyOn(Date, 'now').mockReturnValue((refresh.welcomes[0].expiry_ts + 1) * 1000)
    const count = relay.get(id)!.length
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow()
    expect(relay.get(id)!.length).toBe(count); expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(operation)
  })

  it.each(['recipient', 'challenge', 'root', 'header', 'signature', 'purpose', 'nested evidence', 'evidence kind'] as const)('rejects generic refresh %s corruption on restore and retry', async reason => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Invalid refresh')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey)); await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    const record = store.findConversation(alice.id, id)!, refresh = prepareGroupWelcomeRefresh(alice.identity, record.group!.session, [bob.identity.publicKey], 10)
    const operation: store.StoredGroupOperation = { kind: 'refresh', controls: [], welcomes: refresh.welcomes.map(w => base64UrlEncode(serializeEnvelope(w))), delivered: 0, expected: record.group!.session, recipient: hex(bob.identity.publicKey), recoveryChallenge: null }
    if (reason === 'recipient') operation.recipient = hex(alice.identity.publicKey)
    if (reason === 'challenge') operation.recoveryChallenge = 'aa'.repeat(32)
    if (reason === 'root') operation.expected = { ...operation.expected, root: 'bb'.repeat(32) }
    if (reason === 'header') { const e = deserializeEnvelope(base64UrlDecode(operation.welcomes[0])); e.expiry_ts++; operation.welcomes[0] = base64UrlEncode(serializeEnvelope(e)) }
    if (reason === 'signature') { const e = deserializeEnvelope(base64UrlDecode(operation.welcomes[0])); e.ciphertext[40] ^= 1; operation.welcomes[0] = base64UrlEncode(serializeEnvelope(e)) }
    if (reason === 'purpose') operation.welcomes = prepareGroupAdmissionRenewal(alice.identity, record.group!.session, bob.identity.publicKey, { addId: record.group!.session.admissions[hex(bob.identity.keyID)].addId, addDigest: record.group!.session.admissions[hex(bob.identity.keyID)].addDigest }).welcomes.map(w => base64UrlEncode(serializeEnvelope(w)))
    if (reason === 'nested evidence' || reason === 'evidence kind') operation.superseded = [{ kind: reason === 'evidence kind' ? 'renewal' : 'refresh', controls: [], welcomes: operation.welcomes, delivered: 0, delivery: 'unknown', ...(reason === 'nested evidence' ? { expected: operation.expected } : {}) }]
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    expect(() => validateBackup(rawBackup())).toThrow()
    if (!reason.includes('evidence')) {
      const count = relay.get(id)!.length
      await expect(retryContactGroup(alice.id, id)).rejects.toThrow()
      expect(relay.get(id)!.length).toBe(count); expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(operation)
    }
  })

  it('detects an omitted rotation between the signed anchor and delayed welcome', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const original = vi.mocked(DropboxClient.prototype.postMessage).getMockImplementation()!
    let raced = false
    vi.mocked(DropboxClient.prototype.postMessage).mockImplementation(async function (this: DropboxClient, cid, wire) {
      if (!raced && (deserializeEnvelope(wire) as { kind?: string }).kind === 'group_welcome') {
        raced = true
        const rekey = prepareGroupSessionRekey(alice.identity, session(alice.id, id))
        const seq = await original.call(this, cid, serializeEnvelope(rekey.rekey))
        omit(id, seq)
      }
      return original.call(this, cid, wire)
    })
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).recovery?.reason).toBe('missing_history')
    await expect(sendContactGroupMessage(bob.id, id, 'must not send stale keys')).rejects.toThrow(/history/i)
  })

  it.each(['before welcome', 'after opening', 'expired before welcome', 'accepted before race'])('blocks a lower-ID pre-admission rekey %s and accepts challenged same-epoch recovery', async timing => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Competing room'), source = session(alice.id, id)
    let addition = prepareGroupSessionAddition(alice.identity, source, [bob.identity.publicKey], undefined, undefined, heads.get(id)!)
    for (let n = 0; addition.rekey.msg_id[0] < 128 && n < 128; n++) addition = prepareGroupSessionAddition(alice.identity, source, [bob.identity.publicKey], undefined, undefined, heads.get(id)!)
    expect(addition.rekey.msg_id[0]).toBeGreaterThanOrEqual(128)
    const afterAdd = receiveGroupEvent(alice.identity, addition.addition, source).state
    const competingTtl = timing === 'expired before welcome' ? 1 : undefined
    let competing = prepareGroupSessionRekey(alice.identity, afterAdd, competingTtl)
    for (let n = 0; hex(competing.rekey.msg_id) >= hex(addition.rekey.msg_id) && n < 128; n++) competing = prepareGroupSessionRekey(alice.identity, afterAdd, competingTtl)
    expect(hex(competing.rekey.msg_id) < hex(addition.rekey.msg_id)).toBe(true)
    let canonical = source
    for (const control of [addition.addition, addition.rekey]) {
      await post(id, control)
      canonical = receiveGroupEvent(alice.identity, control, canonical).state
    }
    const link = publicGroupLink(alice.id, id)
    if (timing === 'after opening' || timing === 'accepted before race') {
      await new DropboxClient('http://localhost').postMessage(bytes(id), serializeEnvelope(addition.welcomes[0]))
      await openContactGroup(bob.id, link)
      expect(session(bob.id, id).recovery).toBeNull()
    }
    const losingText = createMessage(alice.identity, groupSessionConversation(canonical), 'text', new TextEncoder().encode('readable losing-branch text must stay hidden'))
    await post(id, losingText)
    let oldDelivery: store.StoredMessage | undefined
    if (timing === 'accepted before race') {
      oldDelivery = (await syncContactGroup(bob.id, id))[0]
      expect(oldDelivery.text).toBe('readable losing-branch text must stay hidden')
      expect(isCurrentGroupMessage(bob.id, id, oldDelivery)).toBe(true)
    }
    await post(id, competing.rekey)
    canonical = receiveGroupEvent(alice.identity, competing.rekey, canonical).state
    const winningRoot = canonical.root
    await post(id, createMessage(alice.identity, groupSessionConversation(canonical), 'text', new TextEncoder().encode('must not dispatch before recovery')))
    if (timing !== 'after opening' && timing !== 'accepted before race') {
      await new DropboxClient('http://localhost').postMessage(bytes(id), serializeEnvelope(addition.welcomes[0]))
      if (competingTtl) vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 3000)
      await openContactGroup(bob.id, link)
    } else await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).root).not.toBe(winningRoot)
    expect(session(bob.id, id).rekeys).toEqual([])
    expect(session(bob.id, id).recovery?.reason).toBe('missing_history')
    expect(store.getHistory(bob.id, id)).toHaveLength(oldDelivery ? 1 : 0)
    if (oldDelivery) expect(isCurrentGroupMessage(bob.id, id, oldDelivery)).toBe(false)
    await expect(sendContactGroupMessage(bob.id, id, 'stale branch')).rejects.toThrow(/history/i)
    const saved = rawBackup(); localStorage.clear(); localStorage.setItem('aim-store', saved)
    const challenge = session(bob.id, id).recovery!.challenge
    const captured = await new DropboxClient('http://localhost').receiveMessages(bytes(id), 1)
    for (const row of captured.entries) {
      const envelope = deserializeEnvelope(row.envelope)
      if (isGroupWelcomeEnvelope(envelope)) continue
      try { canonical = receiveGroupEvent(alice.identity, envelope, canonical).state }
      catch (error) { if (hex(envelope.msg_id) !== hex(losingText.msg_id)) throw error }
    }
    const refresh = prepareGroupWelcomeRefresh(alice.identity, canonical, [bob.identity.publicKey], undefined, bytes(challenge), captured.sequence)
    await new DropboxClient('http://localhost').postMessage(bytes(id), serializeEnvelope(refresh.welcomes[0]))
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).recovery).toBeNull()
    expect(session(bob.id, id).root).toBe(winningRoot)
    expect(session(bob.id, id).epoch).toBe(1)
    expect(session(bob.id, id).rekeys).toEqual([])
    if (oldDelivery) {
      expect(store.getVisibleHistory(bob.id, id).map(message => message.text)).not.toContain(oldDelivery.text)
      vi.spyOn(crypto, 'getRandomValues').mockImplementationOnce(value => { (value as Uint8Array).set(losingText.msg_id); return value })
      const fresh = createMessage(alice.identity, groupSessionConversation(canonical), 'text', new TextEncoder().encode('fresh winning plaintext with reused ID'))
      expect(hex(fresh.msg_id)).toBe(hex(losingText.msg_id))
      const seq = heads.get(id)! + 1; heads.set(id, seq)
      relay.get(id)!.push({ seq, envelope: serializeEnvelope(fresh) })
      const delivered = await syncContactGroup(bob.id, id)
      expect(delivered.map(message => message.text)).toEqual(['fresh winning plaintext with reused ID'])
      expect(isCurrentGroupMessage(bob.id, id, oldDelivery)).toBe(false)
      expect(isCurrentGroupMessage(bob.id, id, delivered[0])).toBe(true)
      expect(store.getVisibleHistory(bob.id, id).filter(message => message.id === oldDelivery!.id).map(message => message.text)).toEqual(['fresh winning plaintext with reused ID'])
      const archive = store.getHistory(bob.id, id)
      const reused = archive.filter(message => message.id === oldDelivery!.id)
      expect(reused).toHaveLength(2)
      expect(reused[0].groupBinding?.valid).toBe(false)
      expect(reused[0].groupBinding?.digest).not.toBe(reused[1].groupBinding?.digest)
      const encrypted = await exportEncryptedBackup('synthetic archive password')
      localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic archive password'))
      expect(store.getHistory(bob.id, id)).toEqual(archive)
      expect(store.getVisibleHistory(bob.id, id).filter(message => message.id === oldDelivery!.id).map(message => message.text)).toEqual(['fresh winning plaintext with reused ID'])
    }
    const reply = await sendContactGroupMessage(bob.id, id, 'canonical reply')
    const wire = relay.get(id)!.find(row => hex(deserializeEnvelope(row.envelope).msg_id) === reply.id)!
    const received = receiveGroupEvent(alice.identity, deserializeEnvelope(wire.envelope), canonical)
    expect(!received.duplicate && new TextDecoder().decode(received.message.inner.body)).toBe('canonical reply')
  })

  it('keeps durable message validity after synthetic cache pressure plus an authenticated eviction event', async () => {
    const alice = profile('Alice'), id = await createContactGroup(alice.id, 'Replay cache')
    const original = createMessage(alice.identity, groupSessionConversation(session(alice.id, id)), 'text', new TextEncoder().encode('durable accepted message'))
    await post(id, original)
    const accepted = (await syncContactGroup(alice.id, id))[0]
    const data = JSON.parse(rawBackup()), checkpoint = data.conversations[alice.id][0].group.session
    const entry = checkpoint.seen[accepted.id]
    checkpoint.seen = { [accepted.id]: entry }
    for (let index = 1; index < 8192; index++) checkpoint.seen[index.toString(16).padStart(32, '0')] = { digest: '00'.repeat(32), epoch: 0 }
    localStorage.setItem('aim-store', JSON.stringify(data))
    await post(id, createMessage(alice.identity, groupSessionConversation(session(alice.id, id)), 'text', new TextEncoder().encode('trigger actual eviction')))
    await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).seen[accepted.id]).toBeUndefined()
    expect(isCurrentGroupMessage(alice.id, id, accepted)).toBe(true)
    expect(store.getVisibleHistory(alice.id, id).map(message => message.text)).toContain('durable accepted message')
    const seq = heads.get(id)! + 1; heads.set(id, seq)
    relay.get(id)!.push({ seq, envelope: serializeEnvelope(original) })
    expect(await syncContactGroup(alice.id, id)).toEqual([])
    expect(store.getVisibleHistory(alice.id, id)).toHaveLength(2)
    expect(isCurrentGroupMessage(alice.id, id, accepted)).toBe(true)
  })

  it('pauses on an expired authenticated removal without applying its expired authority', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    const remove = createGroupControlMessage(alice.identity, groupSessionConversation(session(alice.id, id)), 'group_remove', createGroupRemoveBody([bob.identity.keyID]), 1)
    await post(id, remove)
    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + 3000)
    await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).removed).toBe(false)
    expect(session(bob.id, id).recovery?.reason).toBe('expired_control')
    await expect(sendContactGroupMessage(bob.id, id, 'blocked')).rejects.toThrow(/history/i)
  })

  it('keeps removal across JSON restart and blocks refresh until explicit readmission', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    const oldWelcome = relay.get(id)!.at(-1)!
    await changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))
    await syncContactGroup(bob.id, id)
    const saved = rawBackup(); localStorage.clear(); localStorage.setItem('aim-store', saved)
    expect(session(bob.id, id).removed).toBe(true)
    await expect(sendContactGroupMessage(bob.id, id, 'forbidden')).rejects.toThrow(/removed/i)
    await expect(changeContactGroup(alice.id, id, 'refresh', hex(bob.identity.keyID))).rejects.toThrow(/not a current member/i)
    await expect(openContactGroup(bob.id, link)).rejects.toThrow(/removal|removed/i)
    await sendContactGroupMessage(alice.id, id, 'during exclusion')
    await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    await sendContactGroupMessage(bob.id, id, 'readmitted')
    expect(store.getHistory(bob.id, id).map(m => m.text)).not.toContain('during exclusion')
    expect(oldWelcome.envelope).toBeInstanceOf(Uint8Array)
  })
  it('requires a fresh challenge-bound welcome after a missing row, including old-welcome reposts', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    const stale = relay.get(id)!.at(-1)!.envelope
    await sendContactGroupMessage(alice.id, id, 'expired text')
    omit(id, heads.get(id)!)
    await syncContactGroup(bob.id, id)
    const challenge = session(bob.id, id).recovery!.challenge
    expect(challenge).toMatch(/^[a-f0-9]{64}$/)
    await expect(sendContactGroupMessage(bob.id, id, 'blocked')).rejects.toThrow(/history/i)
    // Relay replay at a larger sequence cannot fake freshness.
    relay.get(id)!.push({ seq: heads.get(id)! + 1, envelope: stale }); heads.set(id, heads.get(id)! + 1)
    await expect(openContactGroup(bob.id, link)).rejects.toThrow(/challenge/i)
    await changeContactGroup(alice.id, id, 'refresh', hex(bob.identity.keyID), challenge)
    await openContactGroup(bob.id, link)
    expect(session(bob.id, id).recovery).toBeNull()
    await sendContactGroupMessage(bob.id, id, 'recovered')
  })
  it('persists exact pending operations on uncertain delivery and resumes after restart', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Room')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    failPost = true
    await expect(changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))).rejects.toThrow('Delivery uncertain')
    const before = store.findConversation(alice.id, id)!.group!.operation!
    expect(before.controls).toHaveLength(2)
    expect(before.expected.admissions[hex(bob.identity.keyID)].completion).not.toBeNull()
    expect(before.expected.rekeys[0].admissions[hex(bob.identity.keyID)].completion).toBeNull()
    await expect(sendContactGroupMessage(alice.id, id, 'blocked')).rejects.toThrow(/saved group operation/)
    const encrypted = await exportEncryptedBackup('synthetic browser recovery password')
    localStorage.clear()
    const review = await prepareBackup(encrypted, 'synthetic browser recovery password')
    expect(review.incoming.contactPins).toHaveLength(1)
    expect(review.incoming.contactGroups).toHaveLength(1)
    restoreBackup(review)
    expect(store.findConversation(alice.id, id)!.group!.operation).toEqual(before)
    failPost = false
    const link = await retryContactGroup(alice.id, id)
    expect(relay.get(id)!.map(row => base64UrlEncode(row.envelope))).toContain(before.controls[0])
    expect(store.findConversation(alice.id, id)!.group!.operation).toBeNull()
    await openContactGroup(bob.id, link)
  })
  it('preserves admission provenance, source checkpoints and a removal fence through encrypted backup restore', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol')
    const id = await createContactGroup(alice.id, 'Admission archive')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey)); pinContact(alice.id, 'Carol', hex(carol.identity.publicKey))
    const link = await changeContactGroup(alice.id, id, 'add', hex(bob.identity.keyID))
    await openContactGroup(bob.id, link)
    await changeContactGroup(alice.id, id, 'add', hex(carol.identity.keyID))
    await syncContactGroup(bob.id, id)
    const admitted = session(bob.id, id)
    expect(admitted.admissions[hex(bob.identity.keyID)].completion).not.toBeNull()
    expect(admitted.admissions[hex(carol.identity.keyID)].completion).not.toBeNull()
    expect(admitted.rekeys[0].admissions[hex(carol.identity.keyID)].completion).toBeNull()
    await changeContactGroup(alice.id, id, 'remove', hex(bob.identity.keyID))
    await syncContactGroup(bob.id, id)
    const removed = session(bob.id, id)
    expect(removed.removedAtEpoch).toBe(admitted.epoch)
    expect(removed.admissions[hex(bob.identity.keyID)]).toBeUndefined()
    expect(removed.admissions[hex(carol.identity.keyID)]).toEqual(admitted.admissions[hex(carol.identity.keyID)])
    const before = store.findConversation(bob.id, id)!.group!
    const encrypted = await exportEncryptedBackup('synthetic admission archive password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic admission archive password'))
    expect(store.findConversation(bob.id, id)!.group).toEqual(before)
    await expect(openContactGroup(bob.id, link)).rejects.toThrow()
    await expect(sendContactGroupMessage(bob.id, id, 'removed after restore')).rejects.toThrow(/removed/i)
  })
  it('rejects malformed and wrong-epoch admission evidence in backups without replacing local state', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    const id = await createContactGroup(alice.id, 'Validate admissions'), kid = hex(bob.identity.keyID)
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    await changeContactGroup(alice.id, id, 'add', kid)
    const original = rawBackup(), data = JSON.parse(original)
    const checkpoint = (value: typeof data): GroupSessionState => value.conversations[alice.id][0].group.session
    expect(checkpoint(data).admissions[kid].completion).not.toBeNull()
    expect(checkpoint(data).rekeys[0].admissions[kid].completion).toBeNull()
    const corruptions = [
      (state: GroupSessionState) => { state.admissions[kid].addDigest = 'not a digest' },
      (state: GroupSessionState) => { state.admissions[kid].sourceEpoch = state.epoch },
      (state: GroupSessionState) => { state.admissions['00'.repeat(16)] = state.admissions[kid] },
      (state: GroupSessionState) => { state.rekeys[0].admissions = structuredClone(state.admissions) },
      (state: GroupSessionState) => { state.removedAtEpoch = -1 },
      (state: GroupSessionState) => { state.admissions[kid].completion = null; state.admissions[kid].sourceEpoch = state.epoch; state.needsRekey = false },
    ]
    for (const corrupt of corruptions) {
      const invalid = structuredClone(data); corrupt(checkpoint(invalid))
      expect(() => validateBackup(JSON.stringify(invalid))).toThrow()
      expect(rawBackup()).toBe(original)
    }
  })
  it('validates encrypted-backup content, full contact pins and saved checkpoint identity', async () => {
    const alice = profile('Alice'), bob = profile('Bob')
    pinContact(alice.id, 'Bob', hex(bob.identity.publicKey))
    const id = await createContactGroup(alice.id, 'Room')
    expect(validateBackup(rawBackup()).contactPins![alice.id][hex(bob.identity.keyID)]).toBe(hex(bob.identity.publicKey))
    const data = JSON.parse(rawBackup())
    data.conversations[alice.id][0].group.session.identityKid = hex(bob.identity.keyID)
    expect(() => validateBackup(JSON.stringify(data))).toThrow()
    expect(() => pinContact(alice.id, 'Bob', hex(alice.identity.publicKey))).toThrow(/another identity/)
    expect(store.findConversation(alice.id, id)!.group!.session.identityKid).toBe(hex(alice.identity.keyID))
  })

  it.each([false, true] as const)('retries a completed rekey after synthetic cache pressure plus an authenticated eviction%s without a duplicate POST', async laterRotation => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await acceptedPendingRekey(alice, bob)
    const wire = operation.controls[0], mid = hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)
    await evictWithAuthenticatedTraffic(alice, bob, id, [mid])
    expect(controlAccepted(host(alice.id, id), wire)).toBe(true)
    if (laterRotation) {
      await post(id, prepareGroupSessionRekey(bob.identity, session(bob.id, id)).rekey)
      await syncContactGroup(alice.id, id); await syncContactGroup(bob.id, id)
    }
    const encrypted = await exportEncryptedBackup('synthetic control receipt backup password')
    localStorage.clear(); restoreBackup(await prepareBackup(encrypted, 'synthetic control receipt backup password'))
    expect(controlAccepted(host(alice.id, id), wire)).toBe(true)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(alice.id, id).operation).toBeNull()
    expect(session(alice.id, id).epoch).toBe(laterRotation ? 3 : 2)
    if (laterRotation) expect(session(alice.id, id).root).not.toBe(operation.expected.root)
    else expect(session(alice.id, id).root).toBe(operation.expected.root)
  }, 30_000)

  it('retries a completed remove after synthetic cache pressure plus authenticated eviction without publishing obsolete controls', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), carol = profile('Carol')
    const { id } = await admittedGroup(alice, bob, 'Remove receipts')
    pinContact(alice.id, 'Carol', hex(carol.identity.publicKey))
    const carolLink = await changeContactGroup(alice.id, id, 'add', hex(carol.identity.keyID))
    await openContactGroup(carol.id, carolLink)
    const current = session(alice.id, id)
    const remove = createGroupControlMessage(alice.identity, groupSessionConversation(current), 'group_remove', createGroupRemoveBody([bob.identity.keyID]))
    const afterRemove = receiveGroupEvent(alice.identity, remove, current).state
    const rotation = prepareGroupSessionRekey(alice.identity, afterRemove)
    const expected = receiveGroupEvent(alice.identity, rotation.rekey, afterRemove).state
    const operation: store.StoredGroupOperation = { kind: 'remove', controls: [remove, rotation.rekey].map(envelope => base64UrlEncode(serializeEnvelope(envelope))), welcomes: [], delivered: 0, expected }
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    await post(id, remove); await post(id, rotation.rekey)
    await syncContactGroup(alice.id, id); await syncContactGroup(carol.id, id)
    const mids = operation.controls.map(wire => hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id))
    await evictWithAuthenticatedTraffic(alice, carol, id, mids)
    for (const wire of operation.controls) expect(controlAccepted(host(alice.id, id), wire)).toBe(true)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(alice.id, id).operation).toBeNull()
    expect(session(alice.id, id).admissions[hex(bob.identity.keyID)]).toBeUndefined()
  }, 30_000)

  it('lets an invalidated same-source rekey override its leftover seen marker', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, source, operation } = await acceptedPendingRekey(alice, bob)
    const wire = operation.controls[0], mid = hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)
    let competing = prepareGroupSessionRekey(alice.identity, source)
    for (let n = 0; hex(competing.rekey.msg_id) >= mid && n < 512; n++) competing = prepareGroupSessionRekey(alice.identity, source)
    expect(hex(competing.rekey.msg_id) < mid).toBe(true)
    await post(id, competing.rekey); await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).seen[mid]).toBeDefined()
    expect(controlAccepted(host(alice.id, id), wire)).toBe(false)
    expect(host(alice.id, id).controlReceipts?.some(row => row.id === mid && row.valid === false)).toBe(true)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow(/history|epoch/i)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(alice.id, id).operation).toEqual(operation)
  })

  it('does not finish retry from a losing descendant control receipt', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, source } = await acceptedPendingRekey(alice, bob)
    await retryContactGroup(alice.id, id)
    expect(host(alice.id, id).operation).toBeNull()
    const parent = session(alice.id, id)
    let descendant = prepareGroupSessionRekey(alice.identity, parent)
    for (let n = 0; descendant.rekey.msg_id[0] < 128 && n < 128; n++) descendant = prepareGroupSessionRekey(alice.identity, parent)
    const expected = receiveGroupEvent(alice.identity, descendant.rekey, parent).state
    const operation: store.StoredGroupOperation = { kind: 'rekey', controls: [base64UrlEncode(serializeEnvelope(descendant.rekey))], welcomes: [], delivered: 0, expected }
    store.updateConversation(alice.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    await post(id, descendant.rekey); await syncContactGroup(alice.id, id)
    const wire = operation.controls[0], mid = hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)
    expect(controlAccepted(host(alice.id, id), wire)).toBe(true)
    let competing = prepareGroupSessionRekey(alice.identity, source)
    for (let n = 0; competing.rekey.msg_id[0] >= 128 && n < 512; n++) competing = prepareGroupSessionRekey(alice.identity, source)
    expect(competing.rekey.msg_id[0]).toBeLessThan(128)
    await post(id, competing.rekey); await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).seen[mid]).toBeUndefined()
    const receipt = host(alice.id, id).controlReceipts?.find(row => row.id === mid)
    expect(receipt?.valid).toBe(false)
    expect(receipt?.sequence).toBeGreaterThan(0)
    expect(receipt?.epoch).toBe(deserializeEnvelope(base64UrlDecode(wire)).conv_epoch)
    expect(controlAccepted(host(alice.id, id), wire)).toBe(false)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    await expect(retryContactGroup(alice.id, id)).rejects.toThrow()
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(alice.id, id).operation).toEqual(operation)
  })

  it('invalidates prior control proof on challenged welcome replacement', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, link, source } = await admittedGroup(alice, bob, 'Challenged receipts')
    const current = session(bob.id, id)
    const pending = prepareGroupSessionRekey(bob.identity, current)
    const expected = receiveGroupEvent(bob.identity, pending.rekey, current).state
    const operation: store.StoredGroupOperation = { kind: 'rekey', controls: [base64UrlEncode(serializeEnvelope(pending.rekey))], welcomes: [], delivered: 0, expected }
    store.updateConversation(bob.id, id, conv => ({ ...conv, group: { ...conv.group!, operation } }))
    await post(id, pending.rekey); await syncContactGroup(bob.id, id)
    const wire = operation.controls[0], mid = hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)
    expect(controlAccepted(host(bob.id, id), wire)).toBe(true)
    const frame = source.rekeys[0]
    const oldSource = { ...source, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot, rekeys: [], seen: {},
      admissions: structuredClone(frame.admissions), needsRekey: true }
    let unverifiable = prepareGroupSessionRekey(alice.identity, oldSource)
    for (let n = 0; hex(unverifiable.rekey.msg_id) <= frame.messageId && n < 512; n++) unverifiable = prepareGroupSessionRekey(alice.identity, oldSource)
    expect(hex(unverifiable.rekey.msg_id) > frame.messageId).toBe(true)
    await post(id, unverifiable.rekey); await syncContactGroup(bob.id, id)
    expect(session(bob.id, id).recovery).not.toBeNull()
    await changeContactGroup(alice.id, id, 'refresh', hex(bob.identity.keyID), session(bob.id, id).recovery!.challenge)
    await openContactGroup(bob.id, link)
    expect(host(bob.id, id).operation).toEqual(operation)
    expect(host(bob.id, id).controlReceipts?.some(row => row.id === mid && row.valid === false)).toBe(true)
    expect(controlAccepted(host(bob.id, id), wire)).toBe(false)
    expect(session(bob.id, id).epoch).toBeGreaterThan(deserializeEnvelope(base64UrlDecode(wire)).conv_epoch)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    // The replaced checkpoint attests a later epoch: the rotation intent is
    // fulfilled without claiming the invalidated control's own delivery.
    await retryContactGroup(bob.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(bob.id, id).operation).toBeNull()
  })

  it.each(['missing', 'wrong_digest', 'wrong_epoch', 'future_sequence', 'invalidated'] as const)(
    'does not invent delivery from %s control-receipt evidence after synthetic cache pressure plus authenticated eviction', async evidence => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await acceptedPendingRekey(alice, bob)
    const wire = operation.controls[0], mid = hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)
    await evictWithAuthenticatedTraffic(alice, bob, id, [mid])
    const record = store.findConversation(alice.id, id)!
    const receipts = [...(record.group!.controlReceipts ?? [])]
    const row = receipts.find(item => item.id === mid)!
    if (evidence === 'missing') record.group!.controlReceipts = receipts.filter(item => item.id !== mid)
    else if (evidence === 'wrong_digest') row.digest = '00'.repeat(32)
    else if (evidence === 'wrong_epoch') row.epoch += 1
    else if (evidence === 'future_sequence') row.sequence = record.group!.cursor + 1
    else row.valid = false
    store.updateConversation(alice.id, id, () => record)
    expect(controlAccepted(host(alice.id, id), wire)).toBe(false)
    vi.mocked(DropboxClient.prototype.postMessage).mockClear()
    // No delivery is invented and the exact bytes never enter an obsolete
    // epoch; the verified later epoch alone fulfils a standalone rotation intent.
    const before = session(alice.id, id)
    await retryContactGroup(alice.id, id)
    expect(vi.mocked(DropboxClient.prototype.postMessage)).not.toHaveBeenCalled()
    expect(host(alice.id, id).operation).toBeNull()
    expect(session(alice.id, id)).toEqual(before)
  }, 30_000)

  it('rejects malformed control receipts and accepts unknown legacy backups without them', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id } = await acceptedPendingRekey(alice, bob)
    const original = rawBackup(), data = JSON.parse(original), receipts = data.conversations[alice.id][0].group.controlReceipts
    expect(Array.isArray(receipts) && receipts.length).toBeTruthy()
    const corruptions = [
      (group: any) => { group.controlReceipts = [{ ...receipts[0], extra: true }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], digest: 'ab'.repeat(16) }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], sequence: 0 }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], sequence: group.cursor + 1 }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], valid: 'yes' }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], bodyType: 'text' }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0], epoch: -1 }] },
      (group: any) => { group.controlReceipts = [receipts[0], { ...receipts[0] }] },
      (group: any) => { group.controlReceipts = [{ ...receipts[0] }, { ...receipts[0], valid: false }] },
    ]
    for (const corrupt of corruptions) {
      const invalid = structuredClone(data); corrupt(invalid.conversations[alice.id][0].group)
      expect(() => validateBackup(JSON.stringify(invalid))).toThrow()
      expect(rawBackup()).toBe(original)
    }
    const legacy = structuredClone(data); delete legacy.conversations[alice.id][0].group.controlReceipts
    expect(() => validateBackup(JSON.stringify(legacy))).not.toThrow()
    localStorage.setItem('aim-store', JSON.stringify(legacy))
    const wire = host(alice.id, id).operation!.controls[0]
    pressureSeen(alice.id, id, [hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)])
    await post(id, createMessage(bob.identity, groupSessionConversation(session(bob.id, id)), 'text', new TextEncoder().encode('legacy eviction')))
    await syncContactGroup(bob.id, id); await syncContactGroup(alice.id, id)
    expect(session(alice.id, id).seen[hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id)]).toBeUndefined()
    expect(controlAccepted(host(alice.id, id), wire)).toBe(false)
  }, 20_000)

  it('lets later invalidation outrank an earlier valid duplicate receipt identity', async () => {
    const alice = profile('Alice'), bob = profile('Bob'), { id, operation } = await acceptedPendingRekey(alice, bob)
    const wire = operation.controls[0]
    const original = host(alice.id, id).controlReceipts!.find(row => row.id === hex(deserializeEnvelope(base64UrlDecode(wire)).msg_id))!
    expect(controlAccepted(host(alice.id, id), wire)).toBe(true)
    store.updateConversation(alice.id, id, conv => {
      conv.group!.controlReceipts = [{ ...original, valid: true }, { ...original, valid: false }]
      return conv
    })
    expect(controlAccepted(host(alice.id, id), wire)).toBe(false)
    const data = JSON.parse(rawBackup())
    expect(() => validateBackup(JSON.stringify(data))).toThrow(/duplicate control receipt/i)
  })
})
