import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import * as store from './store'
import * as qntm from './qntm'
import { pinGuidanceContact, prepareGuidance, sendGuidance } from './guidance'

describe('local guidance', () => {
  let profileId: string
  let conversationId: string
  let contactId: string
  const recipientKeyId = 'ab'.repeat(16)
  beforeEach(() => {
    const data = new Map<string, string>()
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => data.set(key, value),
      removeItem: (key: string) => data.delete(key),
      clear: () => data.clear(),
    })
    profileId = api.createProfile('Operator').profile.id
    conversationId = api.createInvite(profileId, 'Guidance room').conversationId
    store.updateConversation(profileId, conversationId, c => ({ ...c, participants: [...c.participants, recipientKeyId] }))
    contactId = pinGuidanceContact(profileId, { category: 'legal', name: 'Local counsel', kind: 'human', conversationId, recipientKeyId }).id
  })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('keeps pins local to each profile and includes them in backup and deletion', () => {
    expect(store.listGuidanceContacts('another-profile')).toEqual([])
    const backup = api.exportBackup()
    localStorage.clear()
    api.importBackup(backup)
    expect(store.listGuidanceContacts(profileId)[0].id).toBe(contactId)
    store.deleteProfile(profileId)
    expect(store.listGuidanceContacts(profileId)).toEqual([])
  })

  it('prepares without network calls or automatically attaching history or keys', () => {
    const network = vi.spyOn(qntm, 'sendMessageToConversation')
    store.addHistoryMessage(profileId, conversationId, { id: 'secret', conversationId, direction: 'incoming', sender: 'Other', senderKey: recipientKeyId, bodyType: 'text', text: 'Private transcript', createdAt: new Date().toISOString() })
    const draft = prepareGuidance(profileId, contactId, 'Question', 'Summary')
    expect(draft.audience).toContain(recipientKeyId)
    expect(draft.text).toContain('Summary')
    expect(JSON.stringify(draft)).not.toContain('Private transcript')
    expect(JSON.stringify(draft)).not.toContain(store.findConversation(profileId, conversationId)!.keys.root)
    expect(network).not.toHaveBeenCalled()
  })

  it('sends exactly the reviewed message to the pinned conversation', async () => {
    const network = vi.spyOn(qntm, 'sendMessageToConversation').mockResolvedValue({ id: 'sent' } as never)
    const draft = prepareGuidance(profileId, contactId, 'Question')
    await sendGuidance(draft, 'Operator')
    expect(network).toHaveBeenCalledExactlyOnceWith(profileId, 'Operator', conversationId, draft.text)
  })

  it.each(['member', 'epoch', 'gateway', 'relay', 'contact', 'removed', 'identity', 'message'])('blocks a changed %s before sending', async change => {
    const network = vi.spyOn(qntm, 'sendMessageToConversation')
    const draft = prepareGuidance(profileId, contactId, 'Question')
    if (change === 'member') store.updateConversation(profileId, conversationId, c => ({ ...c, participants: [...c.participants, 'ff'.repeat(16)] }))
    if (change === 'epoch') store.updateConversation(profileId, conversationId, c => ({ ...c, currentEpoch: c.currentEpoch + 1 }))
    if (change === 'gateway') store.updateConversation(profileId, conversationId, c => ({ ...c, gateway: { publicKey: 'other', keyId: 'other' } }))
    if (change === 'relay') store.setDropboxUrl('https://other.example.test')
    if (change === 'contact') store.saveGuidanceContact(profileId, { ...draft.contact, name: 'Different contact' })
    if (change === 'removed') store.removeGuidanceContact(profileId, contactId)
    if (change === 'identity') api.generateIdentity(profileId)
    if (change === 'message') draft.text = 'Unexpected content'
    await expect(sendGuidance(draft, 'Operator')).rejects.toThrow()
    expect(network).not.toHaveBeenCalled()
  })

  it('rejects self, unknown keys, short keys, and blank questions', () => {
    for (const key of [store.getIdentity(profileId)!.keyId, 'cc'.repeat(16), recipientKeyId.slice(0, 8)]) {
      expect(() => pinGuidanceContact(profileId, { category: 'ethical', name: 'Contact', kind: 'agent', conversationId, recipientKeyId: key })).toThrow()
    }
    expect(() => prepareGuidance(profileId, contactId, ' ')).toThrow()
  })
})
