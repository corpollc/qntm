import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateIdentity, DropboxClient, createMessage, groupSessionConversation, serializeEnvelope,
  deserializeEnvelope, isGroupWelcomeEnvelope, openGroupWelcome, parseGroupLink, receiveGroupEvent, createGroupSession,
  createGroupLink, keyIDFromPublicKey, base64UrlDecode, base64UrlEncode, prepareGroupWelcomeRefresh,
  prepareGroupSessionAddition, prepareGroupSessionRekey, prepareGroupAdmissionRenewal, createGroupControlMessage, createGroupRemoveBody, assertGroupCanSend } from '@corpollc/qntm'
import type { SubscriptionMessage, Identity, GroupSessionState } from '@corpollc/qntm'
import * as store from './store'
import { validateBackup, rawBackup, exportEncryptedBackup, prepareBackup, restoreBackup } from './backup'
import { createContactGroup, changeContactGroup, pinContact, openContactGroup, syncContactGroup, publicGroupLink, sendContactGroupMessage, hex, bytes, retryContactGroup, isCurrentGroupMessage } from './contact-groups'

const relay = new Map<string, SubscriptionMessage[]>()
const heads = new Map<string, number>()
let failPost = false
let hideReplay = false
function profile(name: string, identity = generateIdentity()) {
  const p = store.createProfile(name)
  store.saveIdentity(p.id, { privateKey: hex(identity.privateKey), publicKey: hex(identity.publicKey), keyId: hex(identity.keyID) })
  return { id: p.id, identity }
}
async function post(id: string, envelope: ReturnType<typeof createMessage>) {
  await new DropboxClient('http://localhost').postMessage(bytes(id), serializeEnvelope(envelope))
}
function session(profile: string, id: string) { return store.findConversation(profile, id)!.group!.session }
function omit(id: string, seq: number) { relay.set(id, relay.get(id)!.filter(row => row.seq !== seq)) }
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
    const renewal = prepareGroupAdmissionRenewal(alice.identity, current, bob.identity.publicKey, { addId, addDigest }, undefined, undefined, anchor)
    await post(id, renewal.welcomes[0])
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

  it('keeps durable message validity after real replay-cache eviction and does not dispatch its replay twice', async () => {
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
})
