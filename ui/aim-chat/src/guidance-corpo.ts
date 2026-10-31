import { CORPO_GUIDANCE_PROVIDERS, createGuidanceIntake, DropboxClient, serializeEnvelope, inviteToToken } from '@corpollc/qntm'
import type { GuidanceProvider } from '@corpollc/qntm'
import * as store from './store'

const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
const unhex = (value: string) => Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16))

export const CORPO_CONTACTS = CORPO_GUIDANCE_PROVIDERS.map(p => ({
  id: p.id, category: p.category, name: 'Corpo', kind: 'organization' as const,
  conversationId: p.conversation_id, recipientKeyId: p.recipient_key_id, relayUrl: p.relay_url,
}))

export async function sendCorpoGuidance(profileId: string, profileName: string, provider: GuidanceProvider, question: string, context: string, text: string) {
  const stored = store.getIdentity(profileId)
  if (!stored) throw new Error('Create a profile with an identity first.')
  if (store.getDropboxUrl() !== provider.relay_url) throw new Error('Select the published Corpo relay before requesting guidance.')
  const identity = { privateKey: unhex(stored.privateKey), publicKey: unhex(stored.publicKey), keyID: unhex(stored.keyId) }
  const request = createGuidanceIntake(identity, provider, question, context)
  const reply = request.replyConversation
  // Retain reply keys before posting, even if the delivery result is uncertain.
  store.addConversation(profileId, {
    id: request.requestId, name: `Corpo guidance · ${provider.category}`, type: 'direct',
    keys: { root: hex(reply.keys.root), aeadKey: hex(reply.keys.aeadKey), nonceKey: hex(reply.keys.nonceKey) },
    participants: reply.participants.map(hex), participantPublicKeys: [stored.publicKey, provider.recipient_public_key],
    createdAt: new Date().toISOString(), currentEpoch: 0, inviteToken: inviteToToken(request.replyInvite),
  })
  const relay = new DropboxClient(provider.relay_url)
  await relay.postMessage(request.envelope.conv_id, serializeEnvelope(request.envelope))
  const message: store.StoredMessage = {
    id: hex(request.envelope.msg_id), conversationId: request.requestId, direction: 'outgoing', sender: profileName,
    senderKey: stored.keyId, bodyType: 'text', text, createdAt: new Date(request.envelope.created_ts * 1000).toISOString(),
  }
  store.addHistoryMessage(profileId, request.requestId, message)
  return message
}
