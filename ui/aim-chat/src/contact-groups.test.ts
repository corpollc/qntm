import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateIdentity, DropboxClient, createMessage, groupSessionConversation, serializeEnvelope,
  deserializeEnvelope, openGroupWelcome, parseGroupLink, receiveGroupEvent, createGroupSession,
  createGroupLink, keyIDFromPublicKey, base64UrlDecode, base64UrlEncode, prepareGroupWelcomeRefresh,
  prepareGroupSessionAddition, prepareGroupSessionRekey, createGroupControlMessage, createGroupRemoveBody, assertGroupCanSend } from '@corpollc/qntm'
import type { SubscriptionMessage, Identity, GroupSessionState } from '@corpollc/qntm'
import * as store from './store'
import { validateBackup, rawBackup, exportEncryptedBackup, prepareBackup, restoreBackup } from './backup'
import { createContactGroup, changeContactGroup, pinContact, openContactGroup, syncContactGroup, publicGroupLink, sendContactGroupMessage, hex, bytes, retryContactGroup } from './contact-groups'

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
