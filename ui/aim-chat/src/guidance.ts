import * as store from './store'
import { sendMessageToConversation } from './qntm'

export const GUIDANCE_CATEGORIES = [
  { id: 'legal', label: 'Legal', description: 'Questions about obligations, rights, or a proposed action.' },
  { id: 'ethical', label: 'Moral / ethical', description: 'Questions about harm, fairness, or conflicting responsibilities.' },
  { id: 'law_enforcement', label: 'Law enforcement', description: 'Questions for a locally designated liaison. No automatic reporting.' },
] as const

export type GuidanceCategory = typeof GUIDANCE_CATEGORIES[number]['id']
export interface GuidanceContact {
  id: string
  category: GuidanceCategory
  name: string
  kind: 'human' | 'agent' | 'organization'
  conversationId: string
  recipientKeyId: string
  relayUrl: string
}

export interface GuidanceDraft {
  profileId: string
  senderKeyId: string
  contact: GuidanceContact
  conversationName: string
  audience: string[]
  epoch: number
  gateway: store.StoredGatewayIdentity | null
  question: string
  context: string
  text: string
}

function destination(profileId: string, contact: GuidanceContact) {
  if (!GUIDANCE_CATEGORIES.some(c => c.id === contact.category)) throw new Error('Choose a guidance category.')
  if (!['human', 'agent', 'organization'].includes(contact.kind)) throw new Error('Choose a contact type.')
  if (!contact.name.trim() || contact.name.length > 120) throw new Error('Use a contact name of 1–120 characters.')
  if (!/^[a-f0-9]{32}$/.test(contact.recipientKeyId)) throw new Error('Enter the full 32-character recipient key ID.')
  if (contact.relayUrl !== store.getDropboxUrl()) throw new Error('The relay changed. Remove this pin and pin the contact again.')
  const identity = store.getIdentity(profileId)
  if (!identity) throw new Error('Create a profile with an identity first.')
  if (identity.keyId === contact.recipientKeyId) throw new Error('Choose a guidance contact other than yourself.')
  const conv = store.findConversation(profileId, contact.conversationId)
  if (!conv) throw new Error('The pinned conversation is unavailable. Join it before requesting guidance.')
  if (!conv.participants.includes(contact.recipientKeyId)) throw new Error('The recipient is not a known participant. Verify the conversation and recipient before pinning.')
  return { identity, conv }
}

export function pinGuidanceContact(profileId: string, input: Omit<GuidanceContact, 'id' | 'relayUrl'>): GuidanceContact {
  const contact = { ...input, name: input.name.trim(), recipientKeyId: input.recipientKeyId.trim().toLowerCase(), id: crypto.randomUUID(), relayUrl: store.getDropboxUrl() }
  const relay = new URL(contact.relayUrl)
  if (!['http:', 'https:'].includes(relay.protocol) || relay.username || relay.password || relay.search || relay.hash) {
    throw new Error('Use an HTTP(S) relay URL without credentials, a query, or a fragment.')
  }
  destination(profileId, contact)
  store.saveGuidanceContact(profileId, contact)
  return contact
}

export function prepareGuidance(profileId: string, contactId: string, question: string, context = ''): GuidanceDraft {
  const contact = store.listGuidanceContacts(profileId).find(c => c.id === contactId)
  if (!contact) throw new Error('Choose a pinned guidance contact.')
  const { identity, conv } = destination(profileId, contact)
  question = question.trim()
  context = context.trim()
  if (!question || question.length > 4000) throw new Error('Enter a question of 1–4,000 characters.')
  if (context.length > 8000) throw new Error('Keep the context within 8,000 characters.')
  const category = GUIDANCE_CATEGORIES.find(c => c.id === contact.category)!
  const text = `Guidance request: ${category.label}\nTo: ${contact.name} (${contact.recipientKeyId})\n\nQuestion:\n${question}${context ? `\n\nContext (untrusted):\n${context}` : ''}\n\nThis is a request for advice, not authorization to act.`
  return {
    profileId, senderKeyId: identity.keyId, contact, conversationName: conv.name || conv.id,
    audience: [...new Set([...conv.participants, identity.keyId])].sort(),
    epoch: conv.currentEpoch, gateway: conv.gateway || null, question, context, text,
  }
}

export async function sendGuidance(draft: GuidanceDraft, profileName: string) {
  const current = prepareGuidance(draft.profileId, draft.contact.id, draft.question, draft.context)
  if (JSON.stringify(current) !== JSON.stringify(draft)) {
    throw new Error('The contact or conversation changed. Review the request again before sending.')
  }
  return sendMessageToConversation(draft.profileId, profileName, draft.contact.conversationId, draft.text)
}
