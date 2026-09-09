import { generateIdentity, createInvite, createConversation, deriveConversationKeys } from '@corpollc/qntm'
import type { StoreData } from '../../../src/store'

/** Synthetic local history for display tests; authentication is covered by wire journeys. */
export function gatewayResultFixture(relayUrl: string): StoreData {
  const identity = generateIdentity(), invite = createInvite(identity, 'group')
  const conversation = createConversation(invite, deriveConversationKeys(invite))
  const hex = (value: Uint8Array) => Buffer.from(value).toString('hex')
  const profileId = 'response-demo', conversationId = hex(conversation.id), createdAt = new Date().toISOString()
  return {
    activeProfileId: profileId, profiles: [{ id: profileId, name: 'Response review' }],
    identities: { [profileId]: { privateKey: hex(identity.privateKey), publicKey: hex(identity.publicKey), keyId: hex(identity.keyID) } },
    conversations: { [profileId]: [{ id: conversationId, name: 'Gateway response review', type: 'group', createdAt, currentEpoch: 0,
      participants: [hex(identity.keyID)], participantPublicKeys: [hex(identity.publicKey)],
      keys: { root: hex(conversation.keys.root), aeadKey: hex(conversation.keys.aeadKey), nonceKey: hex(conversation.keys.nonceKey) } }] },
    history: { [profileId]: { [conversationId]: [{ id: 'ab'.repeat(16), conversationId, direction: 'incoming', sender: 'Test gateway', senderKey: hex(identity.keyID),
      bodyType: 'gate.result', createdAt, text: JSON.stringify({ type: 'gate.result', request_id: 'long-response', status_code: 200, content_type: 'application/json',
        body: JSON.stringify({ records: Array.from({ length: 100 }, (_, i) => ({ id: i + 1, status: 'verified sample' })),
          title: 'Complete response visible', markup: '<img src=x onerror="window.responseExecuted=true">' }) }) }] } },
    contacts: {}, guidanceContacts: {}, cursors: {}, dropboxUrl: relayUrl,
  }
}
