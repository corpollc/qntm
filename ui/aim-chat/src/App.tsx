import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import type { ChatMessage, ContactAlias, Conversation, GateRecipe, IdentityInfo, Profile } from './types'
import { shortId } from './utils'
import { SettingsPage } from './components/SettingsPage'
import { Sidebar } from './components/Sidebar'
import type { SidebarHandle } from './components/Sidebar'
import { ChatPane } from './components/ChatPane'
import { GatePanel } from './components/GatePanel'
import { ShortcutsHelp } from './components/ShortcutsHelp'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useToast } from './hooks/useToast'
import { ToastContainer } from './components/ToastContainer'

const POLL_INTERVAL_MS = 3000

const EMPTY_IDENTITY: IdentityInfo = {
  exists: false,
  keyId: '',
  publicKey: '',
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

  const [gateRecipes, setGateRecipes] = useState<GateRecipe[]>([])
  const [selectedRecipe, setSelectedRecipe] = useState('')
  const [gateOrgId, setGateOrgId] = useState('')
  const [gateServerUrl, setGateServerUrl] = useState('http://localhost:8080')
  const [gateArgs, setGateArgs] = useState<Record<string, string>>({})
  const [gatePromoteThreshold, setGatePromoteThreshold] = useState(2)

  const [secretService, setSecretService] = useState('')
  const [secretValue, setSecretValue] = useState('')
  const [secretHeaderName, setSecretHeaderName] = useState('Authorization')
  const [secretHeaderTemplate, setSecretHeaderTemplate] = useState('Bearer {value}')

  const [showSettings, setShowSettings] = useState(false)
  const [showGatePanel, setShowGatePanel] = useState(false)
  const [hiddenConversations, setHiddenConversations] = useState<Set<string>>(() => {
    try {
      const saved = window.localStorage.getItem('aim-hidden-conversations')
      return saved ? new Set(JSON.parse(saved)) : new Set()
    } catch { return new Set() }
  })
  const [showHidden, setShowHidden] = useState(false)
  const [dropboxUrl, setDropboxUrl] = useState('')
  const [defaultDropboxUrl, setDefaultDropboxUrl] = useState('')
  const [dropboxDraft, setDropboxDraft] = useState('')

  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({})

  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [isWorking, setIsWorking] = useState(false)
  const [isLoadingMessages, setIsLoadingMessages] = useState(false)

  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false)

  const { toasts, addToast, removeToast } = useToast()

  const pollingRef = useRef(false)
  const messageTailRef = useRef<HTMLDivElement | null>(null)
  const sidebarRef = useRef<SidebarHandle>(null)

  const activeProfile = useMemo(
    () => profiles.find((profile) => profile.id === activeProfileId) || null,
    [profiles, activeProfileId],
  )

  const selectedConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === selectedConversationId) || null,
    [conversations, selectedConversationId],
  )

  const activeRecipe = useMemo(
    () => gateRecipes.find((r) => r.name === selectedRecipe) || null,
    [gateRecipes, selectedRecipe],
  )

  const resolvedGateUrl = useMemo(() => {
    if (!activeRecipe) return ''
    let url = activeRecipe.target_url
    url = url.replace(/\{(\w+)\}/g, (match, key) => gateArgs[key] || match)
    // Append query params
    const qp = activeRecipe.query_params || []
    const queryParts: string[] = []
    for (const param of qp) {
      const val = gateArgs[param.name] || param.default || ''
      if (val) queryParts.push(`${encodeURIComponent(param.name)}=${encodeURIComponent(val)}`)
    }
    if (queryParts.length > 0) url += (url.includes('?') ? '&' : '?') + queryParts.join('&')
    return url
  }, [activeRecipe, gateArgs])

  // Derive gate status from message history
  const gateStatus = useMemo(() => {
    let promoted = false
    let orgId = ''
    let threshold = 0
    let signerCount = 0
    for (const msg of messages) {
      if (msg.bodyType === 'gate.promote') {
        try {
          const body = JSON.parse(msg.text)
          promoted = true
          orgId = body.org_id || ''
          signerCount = body.signers?.length || 0
          if (body.rules?.[0]?.m) threshold = body.rules[0].m
        } catch { /* ignore */ }
      }
    }
    return { promoted, orgId, threshold, signerCount }
  }, [messages])

  const selectConversation = useCallback((convId: string) => {
    setSelectedConversationId(convId)
    setUnreadCounts((prev) => {
      if (!prev[convId]) return prev
      const next = { ...prev }
      delete next[convId]
      return next
    })
  }, [])

  const toggleHideConversation = useCallback((convId: string) => {
    setHiddenConversations(prev => {
      const next = new Set(prev)
      if (next.has(convId)) next.delete(convId)
      else next.add(convId)
      window.localStorage.setItem('aim-hidden-conversations', JSON.stringify([...next]))
      return next
    })
  }, [])

  const visibleConversations = useMemo(() => {
    if (showHidden) return conversations
    return conversations.filter(c => !hiddenConversations.has(c.id))
  }, [conversations, hiddenConversations, showHidden])

  const hiddenCount = useMemo(
    () => conversations.filter(c => hiddenConversations.has(c.id)).length,
    [conversations, hiddenConversations],
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

  const shortcutActions = useMemo(() => ({
    focusConversationFilter() {
      if (showSettings) setShowSettings(false)
      sidebarRef.current?.focusConversationFilter()
    },
    toggleSettings() {
      setShowSettings((prev) => !prev)
    },
    closeOverlay() {
      if (showShortcutsHelp) { setShowShortcutsHelp(false); return }
      if (showGatePanel) { setShowGatePanel(false); return }
      if (showSettings) { setShowSettings(false); return }
    },
    focusNewConversation() {
      if (showSettings) setShowSettings(false)
      sidebarRef.current?.focusNewConversation()
    },
    switchConversation(index: number) {
      const conv = visibleConversations[index]
      if (conv) selectConversation(conv.id)
    },
    toggleShortcutsHelp() {
      setShowShortcutsHelp((prev) => !prev)
    },
  }), [showSettings, showShortcutsHelp, showGatePanel, visibleConversations, selectConversation])

  useKeyboardShortcuts(shortcutActions)

  useEffect(() => {
    void initializeProfiles()
    void loadSettings()
    void loadGateRecipes()
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

    void refreshHistory(activeProfileId, selectedConversationId, true)
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

  // Poll non-selected conversations for unread message counts
  const bgPollingRef = useRef(false)
  useEffect(() => {
    if (!activeProfileId || conversations.length === 0) {
      return
    }

    async function pollOtherConversations() {
      if (bgPollingRef.current) return
      bgPollingRef.current = true
      try {
        for (const conv of conversations) {
          if (conv.id === selectedConversationId) continue
          try {
            const response = await api.receiveMessages(activeProfileId, activeProfile?.name || '', conv.id)
            if (response.messages.length > 0) {
              setUnreadCounts((prev) => ({
                ...prev,
                [conv.id]: (prev[conv.id] || 0) + response.messages.length,
              }))
            }
          } catch {
            // Ignore errors for background polling of individual conversations
          }
        }
      } finally {
        bgPollingRef.current = false
      }
    }

    void pollOtherConversations()
    const timer = window.setInterval(() => {
      void pollOtherConversations()
    }, POLL_INTERVAL_MS)

    return () => {
      window.clearInterval(timer)
    }
  }, [activeProfileId, conversations, selectedConversationId])

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
      addToast('Ready', 'info')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load profiles'
      setError(msg)
      addToast(msg, 'error')
    }
  }

  async function loadSettings() {
    try {
      const response = await api.getSettings()
      setDropboxUrl(response.dropboxUrl)
      setDefaultDropboxUrl(response.defaultDropboxUrl)
      setDropboxDraft(response.dropboxUrl)
    } catch {
      // Settings not critical for startup
    }
  }

  async function onSaveSettings() {
    setIsWorking(true)
    try {
      const response = await api.updateSettings({ dropboxUrl: dropboxDraft.trim() })
      setDropboxUrl(response.dropboxUrl)
      setDropboxDraft(response.dropboxUrl)
      setStatus('Settings saved')
      addToast('Settings saved', 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save settings'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
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
      const msg = err instanceof Error ? err.message : 'Failed to refresh profile data'
      setError(msg)
      addToast(msg, 'error')
    }
  }

  async function refreshHistory(profileId: string, conversationId: string, initial = false) {
    if (initial) setIsLoadingMessages(true)
    try {
      const response = await api.getHistory(profileId, conversationId)
      setMessages(response.messages)
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load message history'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      if (initial) setIsLoadingMessages(false)
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
      const statusMsg = name ? `Saved contact ${name}` : `Removed contact alias for ${shortId(key)}`
      setStatus(statusMsg)
      addToast(statusMsg, 'success')

      if (selectedConversationId) {
        await refreshHistory(activeProfileId, selectedConversationId)
      }

      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save contact'
      setError(msg)
      addToast(msg, 'error')
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
      const response = await api.receiveMessages(activeProfileId, activeProfile?.name || '', selectedConversationId)
      const relayWarning = response.warning?.trim() || ''

      if (response.messages.length > 0) {
        await refreshHistory(activeProfileId, selectedConversationId)
        const baseStatus = `Received ${response.messages.length} new message(s)`
        const fullStatus = relayWarning ? `${baseStatus} · ${relayWarning}` : baseStatus
        setStatus(fullStatus)
        addToast(fullStatus, 'info')
      } else if (manual) {
        const baseStatus = 'No new messages'
        const fullStatus = relayWarning ? `${baseStatus} · ${relayWarning}` : baseStatus
        setStatus(fullStatus)
        addToast(fullStatus, 'info')
      } else if (relayWarning) {
        setStatus(relayWarning)
        addToast(relayWarning, 'info')
      }

      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to receive messages'
      setError(msg)
      addToast(msg, 'error')
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
      addToast(`Created profile ${created.profile.name}`, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create profile'
      setError(msg)
      addToast(msg, 'error')
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
      const switchMsg = `Switched profile to ${profiles.find((profile) => profile.id === profileId)?.name || profileId}`
      setStatus(switchMsg)
      addToast(switchMsg, 'success')
      setCreatedInviteToken('')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to switch profile'
      setError(msg)
      addToast(msg, 'error')
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
      setStatus('Keypair generated')
      addToast('Keypair generated', 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to generate keypair'
      setError(msg)
      addToast(msg, 'error')
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
      const name = inviteName.trim() || `${activeProfile?.name || 'Conversation'} Room`
      const response = await api.createInvite(activeProfileId, name)

      setCreatedInviteToken(response.inviteToken)
      setConversations(response.conversations)

      if (response.conversationId) {
        setSelectedConversationId(response.conversationId)
      }

      setStatus('Invite created. Token copied below.')
      addToast('Invite created. Token copied below.', 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create invite'
      setError(msg)
      addToast(msg, 'error')
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
      const name = inviteName.trim() || `${activeProfile?.name || 'Conversation'} Link`
      const response = await api.acceptInvite(activeProfileId, token, name)
      setConversations(response.conversations)

      if (response.conversationId) {
        setSelectedConversationId(response.conversationId)
      }

      setInviteToken('')
      setStatus('Invite accepted')
      addToast('Invite accepted', 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to accept invite'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  function loadGateRecipes() {
    try {
      const response = api.gateRecipes()
      setGateRecipes(response.recipes)
    } catch {
      // Gate recipes not critical
    }
  }

  function onRecipeChange(recipeName: string) {
    setSelectedRecipe(recipeName)
    setGateArgs({})
  }

  function onGateArgChange(key: string, value: string) {
    setGateArgs((prev) => ({ ...prev, [key]: value }))
  }

  async function onGateRun() {
    if (!activeProfileId || !selectedConversationId || !selectedRecipe) {
      setError('Select an API template')
      addToast('Select an API template', 'error')
      return
    }

    const orgId = gateOrgId.trim() || gateStatus.orgId || selectedConversationId

    setIsWorking(true)
    try {
      const response = await api.gateRun(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        selectedRecipe,
        orgId,
        gateServerUrl.trim(),
        Object.keys(gateArgs).length > 0 ? gateArgs : undefined,
      )
      setMessages((previous) => [...previous, response.message])
      setStatus(`API request submitted: ${selectedRecipe}`)
      addToast(`API request submitted: ${selectedRecipe}`, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to submit API request'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGatePromote() {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    // Use conversation ID as org ID — the conversation IS the org
    const orgId = gateOrgId.trim() || selectedConversationId

    setIsWorking(true)
    try {
      const response = await api.gatePromote(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        orgId,
        gatePromoteThreshold,
      )
      setMessages((previous) => [...previous, response.message])
      setStatus(`API Gateway enabled: ${gatePromoteThreshold} approvals required`)
      addToast(`API Gateway enabled: ${gatePromoteThreshold} approvals required`, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to enable API Gateway'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGateSecret() {
    if (!activeProfileId || !selectedConversationId || !secretService.trim() || !secretValue) {
      setError('Enter a service name and API key')
      addToast('Enter a service name and API key', 'error')
      return
    }

    setIsWorking(true)
    try {
      const response = await api.gateSecret(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        secretService.trim(),
        secretValue,
        secretHeaderName.trim() || undefined,
        secretHeaderTemplate.trim() || undefined,
      )
      setMessages((previous) => [...previous, response.message])
      const secretMsg = response.output || `API key added for ${secretService.trim()}`
      setStatus(secretMsg)
      addToast(secretMsg, 'success')
      setSecretValue('')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to add API key'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  const onGateApprove = useCallback(async (requestId: string, conversationId: string) => {
    if (!activeProfileId) return

    setIsWorking(true)
    try {
      await api.gateApprove(activeProfileId, activeProfile?.name || '', conversationId, requestId)
      setStatus(`Request approved: ${requestId.slice(0, 8)}...`)
      addToast(`Request approved: ${requestId.slice(0, 8)}...`, 'success')
      setError('')
      // Refresh to show the new approval message
      await refreshHistory(activeProfileId, conversationId)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to approve request'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }, [activeProfileId])

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
      const response = await api.sendMessage(activeProfileId, activeProfile?.name || '', selectedConversationId, text)
      setMessages((previous) => [...previous, response.message])
      setComposer('')
      const relayWarning = response.warning?.trim() || ''
      const sentMsg = relayWarning ? `Message sent · ${relayWarning}` : 'Message sent'
      setStatus(sentMsg)
      addToast(sentMsg, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to send message'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  return (
    <div className="aim-desktop">
      <a className="sr-only skip-link" href="#chat-pane">
        Skip to main content
      </a>
      <div className="aim-window">
        <header className="title-bar">
          <span className="title-text">qntm Messenger</span>
          <span className="title-detail">
            <button
              className="settings-toggle"
              type="button"
              onClick={() => setShowSettings(!showSettings)}
              aria-label={showSettings ? 'Close settings' : 'Open settings'}
            >
              {showSettings ? 'Back to conversations' : 'Settings'}
            </button>
          </span>
        </header>

        <div className="aim-body">
          {showSettings ? (
            <SettingsPage
              dropboxUrl={dropboxUrl}
              defaultDropboxUrl={defaultDropboxUrl}
              dropboxDraft={dropboxDraft}
              setDropboxDraft={setDropboxDraft}
              isWorking={isWorking}
              onSaveSettings={onSaveSettings}
              error={error}
              setStatus={setStatus}
              setError={setError}
            />
          ) : (
          <>
          <Sidebar
            profiles={profiles}
            activeProfileId={activeProfileId}
            identity={identity}
            newProfileName={newProfileName}
            setNewProfileName={setNewProfileName}
            inviteName={inviteName}
            setInviteName={setInviteName}
            inviteToken={inviteToken}
            setInviteToken={setInviteToken}
            createdInviteToken={createdInviteToken}
            visibleConversations={visibleConversations}
            selectedConversationId={selectedConversationId}
            setSelectedConversationId={selectConversation}
            hiddenConversations={hiddenConversations}
            unreadCounts={unreadCounts}
            hiddenCount={hiddenCount}
            showHidden={showHidden}
            setShowHidden={setShowHidden}
            toggleHideConversation={toggleHideConversation}
            visibleContactKeys={visibleContactKeys}
            contactDrafts={contactDrafts}
            contactNameByKey={contactNameByKey}
            isWorking={isWorking}
            onSelectProfile={onSelectProfile}
            onCreateProfile={onCreateProfile}
            onGenerateIdentity={onGenerateIdentity}
            onCreateInvite={onCreateInvite}
            onAcceptInvite={onAcceptInvite}
            onContactDraftChange={onContactDraftChange}
            onSaveContact={onSaveContact}
            setStatus={setStatus}
          />

          <ChatPane
            selectedConversation={selectedConversation}
            messages={messages}
            composer={composer}
            setComposer={setComposer}
            isWorking={isWorking}
            isLoadingMessages={isLoadingMessages}
            showGatePanel={showGatePanel}
            setShowGatePanel={setShowGatePanel}
            activeProfile={activeProfile}
            status={status}
            messageTailRef={messageTailRef}
            onSendMessage={onSendMessage}
            onCheckMessages={() => void receiveMessages(true)}
            onGateApprove={onGateApprove}
            identityExists={identity.exists}
            conversationCount={conversations.length}
            onGenerateIdentity={onGenerateIdentity}
            onOpenInvites={() => {}}
          />

          {showGatePanel && selectedConversation && (
            <GatePanel
              gateStatus={gateStatus}
              gateRecipes={gateRecipes}
              selectedRecipe={selectedRecipe}
              activeRecipe={activeRecipe}
              gateServerUrl={gateServerUrl}
              setGateServerUrl={setGateServerUrl}
              gateArgs={gateArgs}
              gateOrgId={gateOrgId}
              gatePromoteThreshold={gatePromoteThreshold}
              setGatePromoteThreshold={setGatePromoteThreshold}
              resolvedGateUrl={resolvedGateUrl}
              secretService={secretService}
              setSecretService={setSecretService}
              secretValue={secretValue}
              setSecretValue={setSecretValue}
              secretHeaderName={secretHeaderName}
              setSecretHeaderName={setSecretHeaderName}
              secretHeaderTemplate={secretHeaderTemplate}
              setSecretHeaderTemplate={setSecretHeaderTemplate}
              isWorking={isWorking}
              onRecipeChange={onRecipeChange}
              onGateArgChange={onGateArgChange}
              onGateRun={onGateRun}
              onGatePromote={onGatePromote}
              onGateSecret={onGateSecret}
            />
          )}
          </>
          )}
        </div>
        <ToastContainer toasts={toasts} removeToast={removeToast} />
      </div>
    </div>
  )
}
