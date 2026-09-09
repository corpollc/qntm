import { webcrypto } from 'node:crypto'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import * as store from './store'
import { MAX_BACKUP_BYTES, exportEncryptedBackup, importBackup, prepareBackup, rawBackup, restoreBackup, validateBackup } from './backup'

let profile: string, conversation: string
beforeEach(() => {
  const values = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
    clear: () => values.clear(),
  })
  vi.stubGlobal('crypto', webcrypto)
  profile = api.createProfile('Original').profile.id
  api.generateIdentity(profile)
  conversation = api.createInvite(profile, 'Saved chat').conversationId
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); localStorage.clear() })
const snapshot = () => JSON.parse(rawBackup())

describe('bounded backup validation and atomic replacement', () => {
  it('accepts a legacy backup without the later guidance field', () => {
    const data = snapshot(); delete data.guidanceContacts
    expect(validateBackup(JSON.stringify(data)).guidanceContacts).toEqual({})
  })
  it.each([
    ['array root', (d: any) => []],
    ['missing fields', (d: any) => ({})],
    ['unknown schema', (d: any) => ({ ...d, version: 999 })],
    ['bad identity pair', (d: any) => { d.identities[profile].privateKey = '00'.repeat(64); return d }],
    ['bad key', (d: any) => { d.conversations[profile][0].keys.aeadKey = 'zz'.repeat(32); return d }],
    ['negative cursor', (d: any) => { d.cursors[profile] = { [conversation]: -1 }; return d }],
    ['unknown active profile', (d: any) => ({ ...d, activeProfileId: 'missing' })],
    ['bad relay', (d: any) => ({ ...d, dropboxUrl: 'javascript:alert(1)' })],
    ['credential URL', (d: any) => ({ ...d, dropboxUrl: 'https://user:secret@example.test' })],
    ['bad gateway key', (d: any) => { d.conversations[profile][0].gateway = { publicKey: 'bad', keyId: 'bad' }; return d }],
    ['null conversation', (d: any) => { d.conversations[profile] = [null]; return d }],
    ['invalid guidance', (d: any) => { d.guidanceContacts[profile] = [{ id: 'x', category: 'legal' }]; return d }],
    ['unknown profile bucket', (d: any) => { d.history.missing = {}; return d }],
    ['prototype bucket', (d: any) => { d.contacts = JSON.parse('{"__proto__":{}}'); return d }],
  ])('rejects %s without changing storage', (_name, alter) => {
    const before = rawBackup()
    expect(() => importBackup(JSON.stringify(alter(snapshot())))).toThrow(/Invalid backup/)
    expect(rawBackup()).toBe(before)
  })
  it('bounds bytes and reports syntax errors without echoing file contents', () => {
    expect(() => validateBackup(' '.repeat(MAX_BACKUP_BYTES + 1))).toThrow(/10 MiB/)
    expect(() => validateBackup('{"secret":"do not print me')).toThrow('Invalid backup: JSON syntax.')
  })
  it('previews identities and all destinations without exposing keys or writing data', async () => {
    const data = snapshot()
    data.profiles[0].name = 'Restored'
    data.dropboxUrl = 'https://replacement.test'
    data.guidanceContacts[profile] = [{ id: 'c', name: 'Counsel', category: 'legal', kind: 'human', conversationId: conversation, recipientKeyId: 'ab'.repeat(16), relayUrl: 'https://guidance.test' }]
    const before = rawBackup()
    const review = await prepareBackup(JSON.stringify(data))
    expect(rawBackup()).toBe(before)
    expect(review.incoming.relayUrl).toBe('https://replacement.test')
    expect(review.incoming.guidance[0].recipientKeyId).toBe('ab'.repeat(16))
    expect(JSON.stringify(review)).not.toContain(data.identities[profile].privateKey)
    expect(JSON.stringify(review)).not.toContain(data.conversations[profile][0].keys.aeadKey)
    restoreBackup(review)
    expect(api.listProfiles().profiles[0].name).toBe('Restored')
    expect(() => restoreBackup(review)).toThrow(/Review/)
  })
  it('refuses stale or fabricated reviews', async () => {
    const review = await prepareBackup(rawBackup())
    store.renameProfile(profile, 'Changed while reviewing')
    expect(() => restoreBackup(review)).toThrow(/Local data changed/)
    expect(() => restoreBackup({ ...review })).toThrow(/Review/)
    expect(api.listProfiles().profiles[0].name).toBe('Changed while reviewing')
  })
  it('leaves storage unchanged if quota rejects the replacement', async () => {
    const review = await prepareBackup(rawBackup()), before = rawBackup()
    vi.spyOn(localStorage, 'setItem').mockImplementation(() => { throw new DOMException('Full', 'QuotaExceededError') })
    expect(() => restoreBackup(review)).toThrow('Full')
    expect(rawBackup()).toBe(before)
  })
})

describe('password-encrypted downloads', () => {
  const password = 'a long unique backup password'
  it('round-trips with randomized encryption and no plaintext identity or key fields', async () => {
    const first = await exportEncryptedBackup(password), second = await exportEncryptedBackup(password)
    expect(first).not.toBe(second)
    expect(first).not.toContain('Original')
    expect(first).not.toContain(snapshot().identities[profile].privateKey)
    const review = await prepareBackup(first, password)
    expect(review.encrypted).toBe(true)
    expect(review.incoming.profiles[0].name).toBe('Original')
    restoreBackup(review)
    expect(api.listConversations(profile).conversations).toHaveLength(1)
  })
  it('fails closed on a wrong password, tampering, or unbounded KDF settings', async () => {
    const encrypted = await exportEncryptedBackup(password), before = rawBackup()
    await expect(prepareBackup(encrypted, 'a wrong password')).rejects.toThrow(/incorrect password or damaged file/)
    const data = JSON.parse(encrypted)
    data.ciphertext = (data.ciphertext[0] === 'A' ? 'B' : 'A') + data.ciphertext.slice(1)
    await expect(prepareBackup(JSON.stringify(data), password)).rejects.toThrow(/incorrect password or damaged file/)
    data.iterations = 2 ** 53
    await expect(prepareBackup(JSON.stringify(data), password)).rejects.toThrow(/unsupported encryption format/)
    expect(rawBackup()).toBe(before)
  })
})
