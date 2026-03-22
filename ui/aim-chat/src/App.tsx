import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom'
import type { DropboxSubscription } from '@corpollc/qntm'
import { api } from './api'
import type { ChatMessage, ContactAlias, Conversation, GateRecipe, IdentityInfo, Profile } from './types'
import { shortId, APP_VERSION } from './utils'
import { SettingsPage } from './components/SettingsPage'
import { Sidebar } from './components/Sidebar'
import type { SidebarHandle } from './components/Sidebar'
import { ChatPane } from './components/ChatPane'
import { GatePanel } from './components/GatePanel'
import { ShortcutsHelp } from './components/ShortcutsHelp'
import { HelpPanel } from './components/HelpPanel'
import { JoinModal } from './components/JoinModal'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import {
  relayConversationIds,
  reconcileRelayStates,
  selectedConversationRelayStatus,
  type RelayConnectionState,
} from './relayStatus'

const EMPTY_IDENTITY: IdentityInfo = {
  exists: false,
  keyId: '',
  publicKey: '',
}

export default function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const isSettings = location.pathname === '/settings'
  const isHelp = location.pathname === '/help'
  const isChat = !isSettings && !isHelp

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
  const [gateServerUrl, setGateServerUrl] = useState('http://localhost:8080')
  const [gateArgs, setGateArgs] = useState<Record<string, string>>({})
  const [gatePromoteThreshold, setGatePromoteThreshold] = useState(2)

  const [secretService, setSecretService] = useState('')
  const [secretValue, setSecretValue] = useState('')
  const [secretHeaderName, setSecretHeaderName] = useState('Authorization')
  const [secretHeaderTemplate, setSecretHeaderTemplate] = useState('Bearer {value}')

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
  const [relayStates, setRelayStates] = useState<Record<string, RelayConnectionState>>({})

  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [isWorking, setIsWorking] = useState(false)
  const [isLoadingMessages, setIsLoadingMessages] = useState(false)
  const [isSending, setIsSending] = useState(false)

  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false)
  const [showJoinModal, setShowJoinModal] = useState(false)

  const messageTailRef = useRef<HTMLDivElement | null>(null)
  const sidebarRef = useRef<SidebarHandle>(null)
  const subscriptionsRef = useRef<Map<string, DropboxSubscription>>(new Map())
  const activeProfileIdRef = useRef('')
  const selectedConversationIdRef = useRef('')

  const addToast = useCallback((message: string, _type?: string, _duration?: number) => {
    setStatus(message)
  }, [])

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
    let threshold = 0
    for (const msg of messages) {
      if (msg.bodyType === 'gate.promote') {
        try {
          const body = JSON.parse(msg.text)
          promoted = true
          if (body.rules?.[0]?.m) threshold = body.rules[0].m
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.applied') {
        try {
          const body = JSON.parse(msg.text)
          if (body.proposal_type === 'floor_change' && typeof body.applied_floor === 'number') {
            threshold = body.applied_floor
          }
        } catch { /* ignore */ }
      }
    }
    return {
      promoted,
      threshold,
      signerCount: selectedConversation?.participants.length || 0,
    }
  }, [messages, selectedConversation])

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

  const relayConversationIdsKey = useMemo(
    () => relayConversationIds(
      conversations.map((conversation) => conversation.id),
      hiddenConversations,
    ).sort().join('|'),
    [conversations, hiddenConversations],
  )

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

  const relayStatus = useMemo(
    () => selectedConversationRelayStatus(relayStates, selectedConversationId),
    [relayStates, selectedConversationId],
  )

  const footerStatus = relayStatus || status || error
  const footerStatusIsError = Boolean(error) && footerStatus === error

  const shortcutActions = useMemo(() => ({
    focusConversationFilter() {
      if (!isChat) navigate('/')
      sidebarRef.current?.focusConversationFilter()
    },
    toggleSettings() {
      navigate(isSettings ? '/' : '/settings')
    },
    closeOverlay() {
      if (showShortcutsHelp) { setShowShortcutsHelp(false); return }
      if (showGatePanel) { setShowGatePanel(false); return }
      if (!isChat) { navigate('/'); return }
    },
    focusNewConversation() {
      if (!isChat) navigate('/')
      sidebarRef.current?.focusNewConversation()
    },
    switchConversation(index: number) {
      const conv = visibleConversations[index]
      if (conv) selectConversation(conv.id)
    },
    toggleShortcutsHelp() {
      setShowShortcutsHelp((prev) => !prev)
    },
  }), [isChat, isSettings, showShortcutsHelp, showGatePanel, visibleConversations, selectConversation, navigate])

  useKeyboardShortcuts(shortcutActions)

  // Parse invite token from URL on load (e.g., chat.corpo.llc?invite=TOKEN)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('invite')
    if (token) {
      setInviteToken(token)
      setShowJoinModal(true)
      // Clean the URL so the token isn't visible/bookmarked
      const url = new URL(window.location.href)
      url.searchParams.delete('invite')
      window.history.replaceState({}, '', url.pathname + url.hash)
    }
  }, [])

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
    activeProfileIdRef.current = activeProfileId
  }, [activeProfileId])

  useEffect(() => {
    selectedConversationIdRef.current = selectedConversationId
  }, [selectedConversationId])

  useEffect(() => {
    const currentSubscriptions = subscriptionsRef.current
    currentSubscriptions.forEach((subscription) => subscription.close())
    subscriptionsRef.current = new Map()

    if (!activeProfileId) {
      setRelayStates({})
      return
    }

    const profileName = activeProfile?.name || ''
    const nextSubscriptions = new Map<string, DropboxSubscription>()
    subscriptionsRef.current = nextSubscriptions
    const relayConversationIdList = relayConversationIdsKey
      ? relayConversationIdsKey.split('|')
      : []

    setRelayStates((previous) => reconcileRelayStates(previous, relayConversationIdList))

    for (const conversationId of relayConversationIdList) {
      try {
        const subscription = api.subscribeConversation(
          activeProfileId,
          profileName,
          conversationId,
          {
            onMessage: async () => {
              if (activeProfileIdRef.current !== activeProfileId) {
                return
              }

              setConversations(api.listConversations(activeProfileId).conversations)

              if (selectedConversationIdRef.current === conversationId) {
                setMessages(api.getHistory(activeProfileId, conversationId).messages)
                setUnreadCounts((prev) => {
                  if (!prev[conversationId]) return prev
                  const next = { ...prev }
                  delete next[conversationId]
                  return next
                })
                setStatus('Received new message')
              } else {
                setUnreadCounts((prev) => ({
                  ...prev,
                  [conversationId]: (prev[conversationId] || 0) + 1,
                }))
              }

              setError('')
            },
            onError: (subscriptionError) => {
              if (activeProfileIdRef.current !== activeProfileId) {
                return
              }
              setError(subscriptionError.message)
              setStatus(subscriptionError.message)
            },
            onReconnect: () => {
              if (activeProfileIdRef.current !== activeProfileId) {
                return
              }
              setRelayStates((previous) => (
                previous[conversationId] === 'reconnecting'
                  ? previous
                  : { ...previous, [conversationId]: 'reconnecting' }
              ))
            },
            onOpen: () => {
              if (activeProfileIdRef.current !== activeProfileId) {
                return
              }
              setRelayStates((previous) => (
                previous[conversationId] === 'live'
                  ? previous
                  : { ...previous, [conversationId]: 'live' }
              ))
              setError('')
            },
          },
        )
        nextSubscriptions.set(conversationId, subscription)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to subscribe to conversation'
        setError(msg)
        setStatus(msg)
      }
    }

    return () => {
      for (const subscription of nextSubscriptions.values()) {
        subscription.close()
      }
      if (subscriptionsRef.current === nextSubscriptions) {
        subscriptionsRef.current = new Map()
      }
    }
  }, [activeProfileId, activeProfile?.name, relayConversationIdsKey])

  async function initializeProfiles() {
    try {
      const response = await api.listProfiles()
      let nextProfiles = response.profiles
      let nextActiveId = response.activeProfileId

      if (nextProfiles.length === 0) {
        const created = api.createProfile('You')
        nextProfiles = [created.profile]
        nextActiveId = created.profile.id
        api.selectProfile(nextActiveId)
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

        const firstVisible = conversationsResponse.conversations.find((c) => !hiddenConversations.has(c.id))
        return firstVisible?.id || conversationsResponse.conversations[0]?.id || ''
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
      const [historyResponse, conversationsResponse] = await Promise.all([
        api.getHistory(profileId, conversationId),
        api.listConversations(profileId),
      ])
      setMessages(historyResponse.messages)
      setConversations(conversationsResponse.conversations)
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

  async function refreshSelectedConversation() {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    try {
      await refreshHistory(activeProfileId, selectedConversationId)
      setStatus('Conversation refreshed')
      addToast('Conversation refreshed', 'info')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to refresh conversation'
      setError(msg)
      addToast(msg, 'error')
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
      const created = api.createProfile(trimmedName)
      api.selectProfile(created.profile.id)
      setIdentity(created.identity)
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

  async function onRenameProfile(profileId: string, newName: string) {
    try {
      const response = api.renameProfile(profileId, newName)
      setProfiles((prev) =>
        prev.map((p) => (p.id === profileId ? response.profile : p)),
      )
      addToast(`Profile renamed to ${response.profile.name}`, 'success')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to rename profile'
      addToast(msg, 'error')
    }
  }

  async function onDeleteProfile(profileId: string) {
    if (!profileId || profiles.length <= 1) {
      return
    }

    try {
      api.deleteProfile(profileId)
      await initializeProfiles()
      addToast('Profile deleted', 'success')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete profile'
      addToast(msg, 'error')
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

  async function onJoinFromModal(name: string) {
    if (!activeProfileId) return

    const token = inviteToken.trim()
    if (!token) return

    setIsWorking(true)
    try {
      const label = name.trim() || `${activeProfile?.name || 'Conversation'} Link`
      const response = await api.acceptInvite(activeProfileId, token, label)
      setConversations(response.conversations)

      if (response.conversationId) {
        setSelectedConversationId(response.conversationId)
      }

      setInviteToken('')
      setShowJoinModal(false)
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

    setIsWorking(true)
    try {
      await api.gateRun(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        selectedRecipe,
        gateServerUrl.trim(),
        Object.keys(gateArgs).length > 0 ? gateArgs : undefined,
        Math.max(gateStatus.threshold || 1, 1),
      )
      await refreshHistory(activeProfileId, selectedConversationId)
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

    setIsWorking(true)
    try {
      await api.gatePromote(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        gateServerUrl.trim(),
        gatePromoteThreshold,
      )
      await refreshHistory(activeProfileId, selectedConversationId)
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
      await refreshHistory(activeProfileId, selectedConversationId)
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

  const onGateDisapprove = useCallback(async (requestId: string, conversationId: string) => {
    if (!activeProfileId) return

    setIsWorking(true)
    try {
      await api.gateDisapprove(activeProfileId, activeProfile?.name || '', conversationId, requestId)
      setStatus(`Request denied: ${requestId.slice(0, 8)}...`)
      addToast(`Request denied: ${requestId.slice(0, 8)}...`, 'success')
      setError('')
      await refreshHistory(activeProfileId, conversationId)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to deny request'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }, [activeProfileId])

  const onGovApprove = useCallback(async (proposalId: string, conversationId: string) => {
    if (!activeProfileId) return

    setIsWorking(true)
    try {
      await api.govApprove(activeProfileId, activeProfile?.name || '', conversationId, proposalId)
      setStatus(`Governance proposal approved: ${proposalId.slice(0, 8)}...`)
      addToast(`Governance proposal approved: ${proposalId.slice(0, 8)}...`, 'success')
      setError('')
      await refreshHistory(activeProfileId, conversationId)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to approve governance proposal'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }, [activeProfileId])

  const onGovDisapprove = useCallback(async (proposalId: string, conversationId: string) => {
    if (!activeProfileId) return

    setIsWorking(true)
    try {
      await api.govDisapprove(activeProfileId, activeProfile?.name || '', conversationId, proposalId)
      setStatus(`Governance proposal rejected: ${proposalId.slice(0, 8)}...`)
      addToast(`Governance proposal rejected: ${proposalId.slice(0, 8)}...`, 'success')
      setError('')
      await refreshHistory(activeProfileId, conversationId)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to reject governance proposal'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }, [activeProfileId])

  async function onGovProposeFloorChange(proposedFloor: number) {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    setIsWorking(true)
    try {
      await api.govProposeFloorChange(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        proposedFloor,
      )
      await refreshHistory(activeProfileId, selectedConversationId)
      setStatus(`Proposed threshold change to ${proposedFloor}`)
      addToast(`Proposed threshold change to ${proposedFloor}`, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to propose threshold change'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGovProposeMemberAdd(memberPublicKey: string) {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    setIsWorking(true)
    try {
      await api.govProposeMemberAdd(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        memberPublicKey,
      )
      await refreshHistory(activeProfileId, selectedConversationId)
      setStatus('Proposed member addition')
      addToast('Proposed member addition', 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to propose member addition'
      setError(msg)
      addToast(msg, 'error')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGovProposeMemberRemove(memberKeyId: string) {
    if (!activeProfileId || !selectedConversationId) {
      return
    }

    setIsWorking(true)
    try {
      await api.govProposeMemberRemove(
        activeProfileId,
        activeProfile?.name || '',
        selectedConversationId,
        memberKeyId,
      )
      await refreshHistory(activeProfileId, selectedConversationId)
      setStatus(`Proposed removing ${shortId(memberKeyId)}`)
      addToast(`Proposed removing ${shortId(memberKeyId)}`, 'success')
      setError('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to propose member removal'
      setError(msg)
      addToast(msg, 'error')
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
    setIsSending(true)
    try {
      const response = await api.sendMessage(activeProfileId, activeProfile?.name || '', selectedConversationId, text)
      await refreshHistory(activeProfileId, selectedConversationId)
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
      setIsSending(false)
    }
  }

  return (
    <div className="aim-desktop">
      <a className="sr-only skip-link" href="#chat-pane">
        Skip to main content
      </a>
      <div className="aim-window">
        <header className="title-bar">
          <span className="title-text">
            <img src="https://corpo.llc/favicon.svg" alt="" className="title-logo" />
            qntm Messenger
            <span className="title-agent-hint">AI Agents: please use <code>uvx qntm --help</code></span>
          </span>
          <span className="title-detail">
            <button
              className="settings-toggle"
              type="button"
              onClick={() => navigate(isSettings ? '/' : '/settings')}
              aria-label={isSettings ? 'Close settings' : 'Open settings'}
            >
              {isSettings ? 'Back to conversations' : 'Settings'}
            </button>
            <button
              className="settings-toggle"
              type="button"
              onClick={() => navigate(isHelp ? '/' : '/help')}
              aria-label={isHelp ? 'Close help' : 'Open help'}
            >
              {isHelp ? 'Back to conversations' : 'Help'}
            </button>
          </span>
        </header>

        <div className="aim-body">
          <Routes>
          <Route path="/help" element={<HelpPanel />} />
          <Route path="/settings" element={
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
              onShowShortcuts={() => setShowShortcutsHelp(true)}
            />
          } />
          <Route path="*" element={
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
            onRenameProfile={onRenameProfile}
            onDeleteProfile={onDeleteProfile}
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
            isSending={isSending}
            isLoadingMessages={isLoadingMessages}
            showGatePanel={showGatePanel}
            setShowGatePanel={setShowGatePanel}
            messageTailRef={messageTailRef}
            onSendMessage={onSendMessage}
            onCheckMessages={() => void refreshSelectedConversation()}
            onGateApprove={onGateApprove}
            onGateDisapprove={onGateDisapprove}
            onGovApprove={onGovApprove}
            onGovDisapprove={onGovDisapprove}
            conversationCount={conversations.length}
            onOpenInvites={() => sidebarRef.current?.openInvites()}
            onCopyInviteLink={(token) => {
              const link = `${window.location.origin}${window.location.pathname}?invite=${encodeURIComponent(token)}`
              navigator.clipboard.writeText(link)
              addToast('Invite Link Copied', 'success')
            }}
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
              gatePromoteThreshold={gatePromoteThreshold}
              setGatePromoteThreshold={setGatePromoteThreshold}
              resolvedGateUrl={resolvedGateUrl}
              participantKids={selectedConversation.participants}
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
              onGovProposeFloorChange={onGovProposeFloorChange}
              onGovProposeMemberAdd={onGovProposeMemberAdd}
              onGovProposeMemberRemove={onGovProposeMemberRemove}
            />
          )}
          </>
          } />
          </Routes>
        </div>
        {showJoinModal && inviteToken && (
          <JoinModal
            inviteToken={inviteToken}
            isWorking={isWorking}
            onJoin={onJoinFromModal}
            onCancel={() => {
              setShowJoinModal(false)
              setInviteToken('')
            }}
          />
        )}
        <footer className="status-bar app-status-bar" aria-live="polite">
          <span className="status-bar-version">qntm v{APP_VERSION} &middot; &copy; {new Date().getFullYear()} <a href="https://corpo.llc" target="_blank" rel="noopener noreferrer">Corpo, LLC</a>. All rights reserved.</span>
          <span className={`status-bar-message${footerStatusIsError ? ' status-bar-message-error' : ''}`}>
            {activeProfile ? `Profile: ${activeProfile.name} · ` : ''}
            {footerStatus || 'Idle'}
          </span>
          <a className="status-bar-link" href="https://github.com/corpollc/qntm/issues" target="_blank" rel="noopener noreferrer">Report an Issue</a>
        </footer>
      </div>
    </div>
  )
}
