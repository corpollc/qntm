import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import type { ChatMessage, ContactAlias, Conversation, IdentityInfo, Profile } from './types'

const POLL_INTERVAL_MS = 3000

const EMPTY_IDENTITY: IdentityInfo = {
  exists: false,
  keyId: '',
  publicKey: '',
}

function shortId(value: string): string {
  if (!value) {
    return ''
  }

  if (value.length <= 14) {
    return value
  }

  return `${value.slice(0, 8)}...${value.slice(-4)}`
}

function formatTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function App() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [activeProfileId, setActiveProfileId] = useState('')
  const [identity, setIdentity] = useState<IdentityInfo>(EMPTY_IDENTITY)
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [selectedConversationId, setSelectedConversationId] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [contacts, setContacts] = useState<ContactAlias[]>([])
  const [contactDrafts, setContactDrafts] = useState<Record<string, string>>({})

  const [newProfileName, setNewProfileName] = useState('')
  const [inviteName, setInviteName] = useState('')
  const [inviteToken, setInviteToken] = useState('')
  const [createdInviteToken, setCreatedInviteToken] = useState('')
  const [composer, setComposer] = useState('')

  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [isWorking, setIsWorking] = useState(false)

  const pollingRef = useRef(false)
  const messageTailRef = useRef<HTMLDivElement | null>(null)

  const activeProfile = useMemo(
    () => profiles.find((profile) => profile.id === activeProfileId) || null,
    [profiles, activeProfileId],
  )

  const selectedConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === selectedConversationId) || null,
    [conversations, selectedConversationId],
  )

  const contactNameByKey = useMemo(() => {
    const mapping: Record<string, string> = {}
    for (const contact of contacts) {
      mapping[contact.key] = contact.name
    }
    return mapping
  }, [contacts])

  const visibleContactKeys = useMemo(() => {
    const seen = new Set<string>()
    const keys: string[] = []

    for (const message of messages) {
      if (message.direction !== 'incoming' || !message.senderKey) {
        continue
      }
      if (seen.has(message.senderKey)) {
        continue
      }

      seen.add(message.senderKey)
      keys.push(message.senderKey)
    }

    keys.sort((left, right) => left.localeCompare(right))
    return keys
  }, [messages])

  useEffect(() => {
    void initializeProfiles()
  }, [])

  useEffect(() => {
    if (!activeProfileId) {
      setIdentity(EMPTY_IDENTITY)
      setConversations([])
      setSelectedConversationId('')
      setContacts([])
      setContactDrafts({})
      return
    }

    setContactDrafts({})
    void refreshActiveProfileData(activeProfileId)
  }, [activeProfileId])

  useEffect(() => {
    if (!activeProfileId || !selectedConversationId) {
      setMessages([])
      return
    }

    void refreshHistory(activeProfileId, selectedConversationId)
  }, [activeProfileId, selectedConversationId])

  useEffect(() => {
    messageTailRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    void receiveMessages(false)

    const timer = window.setInterval(() => {
      void receiveMessages(false)
    }, POLL_INTERVAL_MS)

    return () => {
      window.clearInterval(timer)
    }
  }, [activeProfileId, selectedConversationId])

  async function initializeProfiles() {
    try {
      const response = await api.listProfiles()
      let nextProfiles = response.profiles
      let nextActiveId = response.activeProfileId

      if (nextProfiles.length === 0) {
        const created = await api.createProfile('Agent 1')
        nextProfiles = [created.profile]
        nextActiveId = created.profile.id
        await api.selectProfile(nextActiveId)
      }

      if (!nextActiveId && nextProfiles.length > 0) {
        nextActiveId = nextProfiles[0].id
        await api.selectProfile(nextActiveId)
      }

      setProfiles(nextProfiles)
      setActiveProfileId(nextActiveId)
      setStatus('Ready')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load profiles')
    }
  }

  async function refreshActiveProfileData(profileId: string) {
    try {
      const [identityResponse, conversationsResponse, contactsResponse] = await Promise.all([
        api.getIdentity(profileId),
        api.listConversations(profileId),
        api.listContacts(profileId),
      ])

      setIdentity(identityResponse)
      setConversations(conversationsResponse.conversations)
      setContacts(contactsResponse.contacts)
      setContactDrafts((previous) => {
        const next = { ...previous }
        for (const contact of contactsResponse.contacts) {
          next[contact.key] = contact.name
        }
        return next
      })

      setSelectedConversationId((previous) => {
        if (
          previous &&
          conversationsResponse.conversations.some((conversation) => conversation.id === previous)
        ) {
          return previous
        }

        return conversationsResponse.conversations[0]?.id || ''
      })

      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh profile data')
    }
  }

  async function refreshHistory(profileId: string, conversationId: string) {
    try {
      const response = await api.getHistory(profileId, conversationId)
      setMessages(response.messages)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load message history')
    }
  }

  function onContactDraftChange(key: string, value: string) {
    setContactDrafts((previous) => ({
      ...previous,
      [key]: value,
    }))
  }

  async function onSaveContact(key: string) {
    if (!activeProfileId) {
      return
    }

    setIsWorking(true)
    try {
      const name = (contactDrafts[key] || '').trim()
      const response = await api.setContact(activeProfileId, key, name)
      setContacts(response.contacts)
      setStatus(name ? `Saved contact ${name}` : `Removed contact alias for ${shortId(key)}`)

      if (selectedConversationId) {
        await refreshHistory(activeProfileId, selectedConversationId)
      }

      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save contact')
    } finally {
      setIsWorking(false)
    }
  }

  async function receiveMessages(manual: boolean) {
    if (pollingRef.current) {
      return
    }

    if (!activeProfileId || !selectedConversationId) {
      return
    }

    pollingRef.current = true
    try {
      const response = await api.receiveMessages(activeProfileId, selectedConversationId)
      const relayWarning = response.warning?.trim() || ''

      if (response.messages.length > 0) {
        await refreshHistory(activeProfileId, selectedConversationId)
        const baseStatus = `Received ${response.messages.length} new message(s)`
        setStatus(relayWarning ? `${baseStatus} · ${relayWarning}` : baseStatus)
      } else if (manual) {
        const baseStatus = 'No new messages'
        setStatus(relayWarning ? `${baseStatus} · ${relayWarning}` : baseStatus)
      } else if (relayWarning) {
        setStatus(relayWarning)
      }

      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to receive messages')
    } finally {
      pollingRef.current = false
    }
  }

  async function onCreateProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const trimmedName = newProfileName.trim()
    if (!trimmedName) {
      return
    }

    setIsWorking(true)
    try {
      const created = await api.createProfile(trimmedName)
      await api.selectProfile(created.profile.id)
      await initializeProfiles()

      setNewProfileName('')
      setStatus(`Created profile ${created.profile.name}`)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create profile')
    } finally {
      setIsWorking(false)
    }
  }

  async function onSelectProfile(profileId: string) {
    if (!profileId || profileId === activeProfileId) {
      return
    }

    try {
      await api.selectProfile(profileId)
      setActiveProfileId(profileId)
      setStatus(`Switched profile to ${profiles.find((profile) => profile.id === profileId)?.name || profileId}`)
      setCreatedInviteToken('')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch profile')
    }
  }

  async function onGenerateIdentity() {
    if (!activeProfileId) {
      return
    }

    setIsWorking(true)
    try {
      const response = await api.generateIdentity(activeProfileId)
      setIdentity(response.identity)
      setStatus('Identity generated')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate identity')
    } finally {
      setIsWorking(false)
    }
  }

  async function onCreateInvite() {
    if (!activeProfileId) {
      return
    }

    setIsWorking(true)
    try {
      const name = inviteName.trim() || `${activeProfile?.name || 'Chat'} Room`
      const response = await api.createInvite(activeProfileId, name)

      setCreatedInviteToken(response.inviteToken)
      setConversations(response.conversations)

      if (response.conversationId) {
        setSelectedConversationId(response.conversationId)
      }

      setStatus('Invite created. Token copied below.')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create invite')
    } finally {
      setIsWorking(false)
    }
  }

  async function onAcceptInvite() {
    if (!activeProfileId) {
      return
    }

    const token = inviteToken.trim()
    if (!token) {
      return
    }

    setIsWorking(true)
    try {
      const name = inviteName.trim() || `${activeProfile?.name || 'Chat'} Link`
      const response = await api.acceptInvite(activeProfileId, token, name)
      setConversations(response.conversations)

      if (response.conversationId) {
        setSelectedConversationId(response.conversationId)
      }

      setInviteToken('')
      setStatus('Invite accepted')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to accept invite')
    } finally {
      setIsWorking(false)
    }
  }

  async function onSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!activeProfileId || !selectedConversationId) {
      return
    }

    const text = composer.trim()
    if (!text) {
      return
    }

    setIsWorking(true)
    try {
      const response = await api.sendMessage(activeProfileId, selectedConversationId, text)
      setMessages((previous) => [...previous, response.message])
      setComposer('')
      const relayWarning = response.warning?.trim() || ''
      setStatus(relayWarning ? `Message sent · ${relayWarning}` : 'Message sent')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message')
    } finally {
      setIsWorking(false)
    }
  }

  return (
    <div className="aim-desktop">
      <div className="aim-window">
        <header className="title-bar">
          <span className="title-text">qntm Instant Messenger</span>
          <span className="title-detail">Classic mode</span>
        </header>

        <div className="aim-body">
          <aside className="sidebar">
            <section className="panel">
              <h2>Identities</h2>

              <label className="label" htmlFor="profile-select">
                Active profile
              </label>
              <select
                id="profile-select"
                className="input"
                value={activeProfileId}
                onChange={(event) => void onSelectProfile(event.target.value)}
              >
                {profiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.name}
                  </option>
                ))}
              </select>

              <form className="row" onSubmit={onCreateProfile}>
                <input
                  className="input"
                  placeholder="New identity"
                  value={newProfileName}
                  onChange={(event) => setNewProfileName(event.target.value)}
                />
                <button className="button" type="submit" disabled={isWorking}>
                  Add
                </button>
              </form>

              <button className="button full" type="button" onClick={() => void onGenerateIdentity()} disabled={isWorking || !activeProfileId}>
                Generate keypair
              </button>

              <div className="meta">
                <div>
                  <strong>Status:</strong> {identity.exists ? 'Ready' : 'No keypair yet'}
                </div>
                <div>
                  <strong>KID:</strong> {identity.keyId ? shortId(identity.keyId) : '-'}
                </div>
              </div>
            </section>

            <section className="panel">
              <h2>Invites</h2>
              <input
                className="input"
                placeholder="Conversation label"
                value={inviteName}
                onChange={(event) => setInviteName(event.target.value)}
              />

              <div className="row">
                <button className="button full" type="button" onClick={() => void onCreateInvite()} disabled={isWorking || !identity.exists}>
                  Create + self-join
                </button>
              </div>

              {createdInviteToken && (
                <textarea className="token-box" value={createdInviteToken} readOnly />
              )}

              <input
                className="input"
                placeholder="Paste invite token"
                value={inviteToken}
                onChange={(event) => setInviteToken(event.target.value)}
              />
              <button className="button full" type="button" onClick={() => void onAcceptInvite()} disabled={isWorking || !identity.exists}>
                Accept invite
              </button>
            </section>

            <section className="panel grow">
              <h2>Conversations</h2>
              <ul className="conversation-list">
                {conversations.length === 0 && <li className="empty">No conversations</li>}
                {conversations.map((conversation) => (
                  <li key={conversation.id}>
                    <button
                      className={`conversation ${conversation.id === selectedConversationId ? 'selected' : ''}`}
                      type="button"
                      onClick={() => setSelectedConversationId(conversation.id)}
                    >
                      <span className="conversation-name">{conversation.name}</span>
                      <span className="conversation-id">{shortId(conversation.id)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>

            <section className="panel">
              <h2>Contacts</h2>
              <div className="contact-list">
                {visibleContactKeys.length === 0 && (
                  <div className="empty">No incoming senders yet</div>
                )}
                {visibleContactKeys.map((key) => (
                  <div className="contact-row" key={key}>
                    <div className="contact-key">{shortId(key)}</div>
                    <input
                      className="input"
                      placeholder="Display name"
                      value={contactDrafts[key] ?? contactNameByKey[key] ?? ''}
                      onChange={(event) => onContactDraftChange(key, event.target.value)}
                    />
                    <button
                      className="button"
                      type="button"
                      disabled={isWorking}
                      onClick={() => void onSaveContact(key)}
                    >
                      Save
                    </button>
                  </div>
                ))}
              </div>
            </section>
          </aside>

          <main className="chat-pane">
            <div className="chat-header">
              <div>
                <strong>{selectedConversation?.name || 'No conversation selected'}</strong>
              </div>
              <div className="chat-subheader">
                {selectedConversation ? shortId(selectedConversation.id) : 'Create or accept an invite'}
              </div>
            </div>

            <div className="chat-log">
              {messages.length === 0 && <div className="empty">No messages yet.</div>}
              {messages.map((message) => (
                <article key={message.id} className={`message ${message.direction}`}>
                  <div className="message-top">
                    <span className="sender">{message.sender}</span>
                    <span className="time">{formatTime(message.createdAt)}</span>
                  </div>
                  <div className="message-body">{message.text}</div>
                  <div className="message-type">{message.bodyType}</div>
                </article>
              ))}
              <div ref={messageTailRef} />
            </div>

            <form className="composer" onSubmit={onSendMessage}>
              <input
                className="input grow"
                placeholder={selectedConversation ? 'Type a message' : 'Select a conversation first'}
                value={composer}
                onChange={(event) => setComposer(event.target.value)}
                disabled={!selectedConversation || isWorking}
              />
              <button className="button" type="submit" disabled={!selectedConversation || isWorking}>
                Send
              </button>
              <button
                className="button"
                type="button"
                disabled={!selectedConversation || isWorking}
                onClick={() => void receiveMessages(true)}
              >
                Check mail
              </button>
            </form>

            <footer className="status-bar">
              <span>
                Profile: <strong>{activeProfile?.name || '-'}</strong>
              </span>
              <span>{status || 'Idle'}</span>
            </footer>

            {error && <div className="error-banner">{error}</div>}
          </main>
        </div>
      </div>
    </div>
  )
}
