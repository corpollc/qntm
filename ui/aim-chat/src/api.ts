/**
 * API layer — direct function calls to store + qntm.
 * No HTTP server needed. Everything runs in-browser.
 */

import type { DropboxSubscription } from '@corpollc/qntm'
import * as store from './store'
import * as qntm from './qntm'
import type { ConversationSubscriptionHandlers } from './qntm'
import type { ChatMessage, ContactAlias, Conversation, GateRecipe, IdentityInfo, Profile } from './types'
import starterCatalog from '../../../gate/recipes/starter.json'

function formatConversation(conv: store.StoredConversation): Conversation {
  return {
    id: conv.id,
    name: conv.name || `${conv.type || 'chat'}-${conv.id.slice(0, 8)}`,
    type: conv.type || 'direct',
    participants: conv.participants || [],
    createdAt: conv.createdAt || null,
    inviteToken: conv.inviteToken || undefined,
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

  createProfile(name: string): { profile: Profile; identity: IdentityInfo } {
    const profile = store.createProfile(name)
    const identity = qntm.generateIdentityForProfile(profile.id)
    return { profile, identity }
  },

  selectProfile(profileId: string): { activeProfileId: string } {
    store.selectProfile(profileId)
    return { activeProfileId: profileId }
  },

  renameProfile(profileId: string, newName: string): { profile: Profile } {
    const profile = store.renameProfile(profileId, newName)
    return { profile }
  },

  deleteProfile(profileId: string): void {
    store.deleteProfile(profileId)
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

  renameConversation(profileId: string, conversationId: string, newName: string): { conversations: Conversation[] } {
    store.updateConversation(profileId, conversationId, (conv) => ({ ...conv, name: newName.trim() || conv.name }))
    return { conversations: store.listConversations(profileId).map(formatConversation) }
  },

  deleteConversation(profileId: string, conversationId: string): { conversations: Conversation[] } {
    store.deleteConversation(profileId, conversationId)
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

  subscribeConversation(
    profileId: string,
    profileName: string,
    conversationId: string,
    handlers: ConversationSubscriptionHandlers,
  ): DropboxSubscription {
    return qntm.subscribeToConversation(profileId, profileName, conversationId, handlers)
  },

  async gateApprove(profileId: string, profileName: string, conversationId: string, requestId: string): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.gateApproveRequest(profileId, profileName, conversationId, requestId)
    return { message }
  },

  async gateDisapprove(profileId: string, profileName: string, conversationId: string, requestId: string): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.gateDisapproveRequest(profileId, profileName, conversationId, requestId)
    return { message }
  },

  gateRecipes(): { recipes: GateRecipe[] } {
    const recipes = Object.values((starterCatalog as { recipes: Record<string, GateRecipe> }).recipes || {})
    return { recipes }
  },

  async gatePromote(
    profileId: string,
    profileName: string,
    conversationId: string,
    gateServerUrl: string,
    threshold: number,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const bootstrap = await qntm.bootstrapGatewayForConversation(profileId, conversationId, gateServerUrl)
    const message = await qntm.gatePromoteRequest(
      profileId,
      profileName,
      conversationId,
      bootstrap.gatewayKid,
      threshold,
    )
    return { message }
  },

  async gateRun(
    profileId: string, profileName: string, conversationId: string,
    recipeName: string, gateUrl: string, args?: Record<string, string>, minimumApprovals = 1,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const allRecipes = (starterCatalog as { recipes: Record<string, GateRecipe> }).recipes || {}
    const recipe = allRecipes[recipeName]
    if (!recipe) throw new Error(`Recipe "${recipeName}" not found`)
    const message = await qntm.gateRunRequest(
      profileId, profileName, conversationId, recipe, recipeName, gateUrl, args || {}, minimumApprovals
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

  async govProposeFloorChange(
    profileId: string,
    profileName: string,
    conversationId: string,
    proposedFloor: number,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.govProposeFloorChange(profileId, profileName, conversationId, proposedFloor)
    return { message }
  },

  async govProposeMemberAdd(
    profileId: string,
    profileName: string,
    conversationId: string,
    memberPublicKey: string,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.govProposeMemberAdd(profileId, profileName, conversationId, memberPublicKey)
    return { message }
  },

  async govProposeMemberRemove(
    profileId: string,
    profileName: string,
    conversationId: string,
    memberKeyId: string,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.govProposeMemberRemove(profileId, profileName, conversationId, memberKeyId)
    return { message }
  },

  async govApprove(
    profileId: string,
    profileName: string,
    conversationId: string,
    proposalId: string,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.govApproveProposal(profileId, profileName, conversationId, proposalId)
    return { message }
  },

  async govDisapprove(
    profileId: string,
    profileName: string,
    conversationId: string,
    proposalId: string,
  ): Promise<{ message: ChatMessage; warning?: string }> {
    const message = await qntm.govDisapproveProposal(profileId, profileName, conversationId, proposalId)
    return { message }
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
