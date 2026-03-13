/**
 * API layer — direct function calls to store + qntm.
 * No HTTP server needed. Everything runs in-browser.
 */

import * as store from './store'
import * as qntm from './qntm'
import type { ChatMessage, ContactAlias, Conversation, GateRecipe, IdentityInfo, Profile } from './types'
import starterCatalog from '../../../gate/recipes/starter.json'

function formatConversation(conv: store.StoredConversation): Conversation {
  return {
    id: conv.id,
    name: conv.name || `${conv.type || 'chat'}-${conv.id.slice(0, 8)}`,
    type: conv.type || 'direct',
    participants: conv.participants || [],
    createdAt: conv.createdAt || null,
  }
}

function resolveMessage(profileId: string, msg: store.StoredMessage): ChatMessage {
  const senderKey = msg.senderKey || msg.sender
  const alias = msg.direction === 'incoming'
    ? store.resolveContactAlias(profileId, senderKey)
    : ''
  return { ...msg, senderKey, sender: alias || msg.sender }
}

export const api = {
  listProfiles(): { activeProfileId: string; profiles: Profile[] } {
    return store.listProfiles()
  },

  createProfile(name: string): { profile: Profile } {
    const profile = store.createProfile(name)
    return { profile }
  },

  selectProfile(profileId: string): { activeProfileId: string } {
    store.selectProfile(profileId)
    return { activeProfileId: profileId }
  },

  getIdentity(profileId: string): IdentityInfo {
    return qntm.getIdentityInfo(profileId)
  },

  generateIdentity(profileId: string): { output: string; identity: IdentityInfo } {
    const identity = qntm.generateIdentityForProfile(profileId)
    return { output: 'Identity generated', identity }
  },

  listConversations(profileId: string): { conversations: Conversation[] } {
    return { conversations: store.listConversations(profileId).map(formatConversation) }
  },

  listContacts(profileId: string): { contacts: ContactAlias[] } {
    return { contacts: store.listContacts(profileId) }
  },

  setContact(profileId: string, key: string, name: string): { contacts: ContactAlias[] } {
    store.setContact(profileId, key, name)
    return { contacts: store.listContacts(profileId) }
  },

  createInvite(profileId: string, name: string): { inviteToken: string; conversationId: string; conversations: Conversation[] } {
    return qntm.createInviteForProfile(profileId, name)
  },

  acceptInvite(profileId: string, token: string, name: string): { conversationId: string; conversations: Conversation[] } {
    return qntm.acceptInviteForProfile(profileId, token, name)
  },

  getHistory(profileId: string, conversationId: string): { messages: ChatMessage[] } {
    const raw = store.getHistory(profileId, conversationId)
    return { messages: raw.map(msg => resolveMessage(profileId, msg)) }
  },

  async sendMessage(profileId: string, profileName: string, conversationId: string, text: string): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.sendMessageToConversation(profileId, profileName, conversationId, text)
    return { message }
  },

  async receiveMessages(profileId: string, profileName: string, conversationId: string): Promise<{ messages: ChatMessage[]; warning?: string }> {
    return qntm.receiveMessages(profileId, profileName, conversationId)
  },

  async gateApprove(profileId: string, profileName: string, conversationId: string, requestId: string): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.gateApproveRequest(profileId, profileName, conversationId, requestId)
    return { message }
  },

  gateRecipes(): { recipes: GateRecipe[] } {
    const recipes = Object.values((starterCatalog as { recipes: Record<string, GateRecipe> }).recipes || {})
    return { recipes }
  },

  async gatePromote(profileId: string, profileName: string, conversationId: string, orgId: string, threshold: number): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.gatePromoteRequest(profileId, profileName, conversationId, orgId, threshold)
    return { message }
  },

  async gateRun(
    profileId: string, profileName: string, conversationId: string,
    recipeName: string, orgId: string, gateUrl: string, args?: Record<string, string>
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const allRecipes = (starterCatalog as { recipes: Record<string, GateRecipe> }).recipes || {}
    const recipe = allRecipes[recipeName]
    if (!recipe) throw new Error(`Recipe "${recipeName}" not found`)
    const message = await qntm.gateRunRequest(
      profileId, profileName, conversationId, recipe, recipeName, orgId, gateUrl, args || {}
    )
    return { message }
  },

  async gateSecret(
    profileId: string, profileName: string, conversationId: string,
    service: string, value: string, headerName?: string, headerTemplate?: string,
    gatewayPublicKey?: string
  ): Promise<{ output: string; message: ChatMessage; warning?: string }> {
    const message = await qntm.gateSecretRequest(
      profileId, profileName, conversationId,
      service, value, headerName || 'Authorization', headerTemplate || 'Bearer {value}',
      gatewayPublicKey
    )
    return { output: `Secret provisioned for service ${service}`, message }
  },

  getSettings(): { dropboxUrl: string; defaultDropboxUrl: string } {
    return { dropboxUrl: store.getDropboxUrl(), defaultDropboxUrl: store.DEFAULT_DROPBOX_URL }
  },

  updateSettings(settings: { dropboxUrl: string }): { dropboxUrl: string; defaultDropboxUrl: string } {
    store.setDropboxUrl(settings.dropboxUrl)
    return { dropboxUrl: store.getDropboxUrl(), defaultDropboxUrl: store.DEFAULT_DROPBOX_URL }
  },

  // Backup / Restore
  exportBackup(): string {
    return qntm.exportBackup()
  },

  importBackup(json: string): void {
    qntm.importBackup(json)
  },
}
