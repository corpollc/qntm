import type { ChatMessage, ContactAlias, Conversation, IdentityInfo, Profile } from './types'

interface ApiError {
  error?: string
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
    ...init,
  })

  const payload = (await response.json().catch(() => ({}))) as T & ApiError

  if (!response.ok) {
    const message = (payload as ApiError).error || `${response.status} ${response.statusText}`
    throw new Error(message)
  }

  return payload
}

export const api = {
  listProfiles: () =>
    request<{ activeProfileId: string; profiles: Profile[] }>('/api/profiles'),

  createProfile: (name: string) =>
    request<{ profile: Profile }>('/api/profiles', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  selectProfile: (profileId: string) =>
    request<{ activeProfileId: string }>(`/api/profiles/${profileId}/select`, {
      method: 'POST',
    }),

  getIdentity: (profileId: string) =>
    request<IdentityInfo>(`/api/profiles/${profileId}/identity`),

  generateIdentity: (profileId: string) =>
    request<{ output: string; identity: IdentityInfo }>(`/api/profiles/${profileId}/identity/generate`, {
      method: 'POST',
    }),

  listConversations: (profileId: string) =>
    request<{ conversations: Conversation[] }>(`/api/profiles/${profileId}/conversations`),

  listContacts: (profileId: string) =>
    request<{ contacts: ContactAlias[] }>(`/api/profiles/${profileId}/contacts`),

  setContact: (profileId: string, key: string, name: string) =>
    request<{ contacts: ContactAlias[] }>(`/api/profiles/${profileId}/contacts`, {
      method: 'POST',
      body: JSON.stringify({ key, name }),
    }),

  createInvite: (profileId: string, name: string) =>
    request<{ inviteToken: string; conversationId: string; conversations: Conversation[] }>(
      `/api/profiles/${profileId}/invite/create`,
      {
        method: 'POST',
        body: JSON.stringify({ name, selfJoin: true }),
      },
    ),

  acceptInvite: (profileId: string, token: string, name: string) =>
    request<{ conversationId: string; conversations: Conversation[] }>(
      `/api/profiles/${profileId}/invite/accept`,
      {
        method: 'POST',
        body: JSON.stringify({ token, name }),
      },
    ),

  getHistory: (profileId: string, conversationId: string) =>
    request<{ messages: ChatMessage[] }>(
      `/api/profiles/${profileId}/history?conversationId=${encodeURIComponent(conversationId)}`,
    ),

  sendMessage: (profileId: string, conversationId: string, text: string) =>
    request<{ message: ChatMessage; warning?: string }>(`/api/profiles/${profileId}/messages/send`, {
      method: 'POST',
      body: JSON.stringify({ conversationId, text }),
    }),

  receiveMessages: (profileId: string, conversationId: string) =>
    request<{ messages: ChatMessage[]; warning?: string }>(`/api/profiles/${profileId}/messages/receive`, {
      method: 'POST',
      body: JSON.stringify({ conversationId }),
    }),
}
