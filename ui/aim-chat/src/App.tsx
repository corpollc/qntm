import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import type { ChatMessage, ContactAlias, Conversation, GateRecipe, IdentityInfo, Profile } from './types'

interface GateRequestBody {
  type: string
  recipe_name?: string
  org_id: string
  request_id: string
  verb: string
  target_endpoint: string
  target_service: string
  target_url: string
  expires_at: string
  signer_kid: string
  arguments?: Record<string, string>
  request_body?: unknown
}

interface GateApprovalBody {
  type: string
  request_id: string
  signer_kid: string
}

interface GateExecutedBody {
  type: string
  request_id: string
  execution_status_code: number
}

interface GateResultBody {
  type: string
  request_id: string
  status_code: number
  content_type?: string
  body?: string
}

function parseGateMessage(text: string): GateRequestBody | GateApprovalBody | GateExecutedBody | null {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function GateRequestCard({
  message,
  onApprove,
  isWorking,
}: {
  message: ChatMessage
  onApprove: (requestId: string, conversationId: string) => void
  isWorking: boolean
}) {
  const parsed = parseGateMessage(message.text) as GateRequestBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  const isExpired = new Date(parsed.expires_at) < new Date()
  const hasArgs = parsed.arguments && Object.keys(parsed.arguments).length > 0
  const hasBody = parsed.request_body !== undefined && parsed.request_body !== null

  return (
    <div className="gate-card gate-request">
      <div className="gate-card-header">
        Gate Request{parsed.recipe_name ? `: ${parsed.recipe_name}` : ''}
      </div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div className="gate-verb-line">
          <span className={`gate-verb gate-verb-${parsed.verb.toLowerCase()}`}>{parsed.verb}</span>
          <code className="gate-url-resolved">{parsed.target_url}</code>
        </div>
        <div><strong>Endpoint:</strong> {parsed.target_endpoint}</div>
        <div><strong>Service:</strong> {parsed.target_service}</div>
        <div><strong>Org:</strong> {parsed.org_id}</div>
        <div><strong>Requester:</strong> {shortId(parsed.signer_kid)}</div>
        <div><strong>Expires:</strong> {new Date(parsed.expires_at).toLocaleTimeString()}</div>
        {hasArgs && (
          <div className="gate-args-display">
            <strong>Arguments:</strong>
            {Object.entries(parsed.arguments!).filter(([k]) => k !== '_body').map(([key, value]) => (
              <div key={key} className="gate-arg-item">
                <code>{key}</code>: {value}
              </div>
            ))}
          </div>
        )}
        {hasBody && (
          <div className="gate-body-preview">
            <strong>Request body:</strong>
            <pre className="gate-body-content">
              {typeof parsed.request_body === 'string'
                ? parsed.request_body
                : JSON.stringify(parsed.request_body, null, 2)}
            </pre>
          </div>
        )}
      </div>
      {!isExpired && (
        <button
          className="gate-approve-btn"
          type="button"
          disabled={isWorking}
          onClick={() => onApprove(parsed.request_id, message.conversationId)}
        >
          Approve
        </button>
      )}
      {isExpired && <div className="gate-expired">Expired</div>}
    </div>
  )
}

function GateApprovalCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateApprovalBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-approval">
      <div className="gate-card-header">Gate Approval</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div><strong>Approved by:</strong> {shortId(parsed.signer_kid)}</div>
      </div>
    </div>
  )
}

function GateExecutedCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateExecutedBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-executed">
      <div className="gate-card-header">Gate Executed</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div><strong>HTTP Status:</strong> {parsed.execution_status_code || 'N/A'}</div>
      </div>
    </div>
  )
}

interface GateExpiredBody {
  type: string
  secret_id: string
  service: string
  expired_at: string
  message: string
}

function GateExpiredCard({ message }: { message: ChatMessage }) {
  let parsed: GateExpiredBody | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  const expiredDate = new Date(parsed.expired_at)
  const timeAgo = Math.round((Date.now() - expiredDate.getTime()) / 60000)

  return (
    <div className="gate-card gate-expired" style={{
      borderColor: '#e67e22',
      backgroundColor: 'rgba(230, 126, 34, 0.08)',
      borderLeft: '4px solid #e67e22',
    }}>
      <div className="gate-card-header" style={{ color: '#e67e22' }}>
        Credential Expired
      </div>
      <div className="gate-card-body">
        <div><strong>Service:</strong> {parsed.service}</div>
        <div><strong>Secret:</strong> {shortId(parsed.secret_id)}</div>
        <div><strong>Expired:</strong> {timeAgo > 0 ? `${timeAgo}m ago` : 'just now'} ({expiredDate.toLocaleString()})</div>
        <div style={{ marginTop: '8px', color: '#e67e22', fontWeight: 500 }}>
          {parsed.message}
        </div>
      </div>
    </div>
  )
}

interface GatePromoteBody {
  org_id: string
  signers: Array<{ kid: string; public_key: string }>
  rules: Array<{ service: string; endpoint: string; verb: string; m: number; n: number }>
}

function GatePromoteCard({ message }: { message: ChatMessage }) {
  let parsed: GatePromoteBody | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  const threshold = parsed.rules?.[0]?.m ?? '?'
  const n = parsed.signers?.length ?? '?'

  return (
    <div className="gate-card gate-promote">
      <div className="gate-card-header">Gate Promote</div>
      <div className="gate-card-body">
        <div><strong>Org:</strong> {parsed.org_id}</div>
        <div><strong>Threshold:</strong> {threshold}-of-{n}</div>
        <div><strong>Signers:</strong> {parsed.signers?.length ?? 0}</div>
        {parsed.signers?.map((s) => (
          <div key={s.kid} className="gate-signer-item">
            <code>{shortId(s.kid)}</code>
          </div>
        ))}
        <div><strong>Rules:</strong> {parsed.rules?.length ?? 0}</div>
      </div>
    </div>
  )
}

function GateConfigCard({ message }: { message: ChatMessage }) {
  let parsed: { rules?: Array<{ service: string; endpoint: string; verb: string; m: number; n: number }> } | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-config">
      <div className="gate-card-header">Gate Config Update</div>
      <div className="gate-card-body">
        <div><strong>Rules:</strong> {parsed.rules?.length ?? 0}</div>
        {parsed.rules?.map((r, i) => (
          <div key={i}>
            <code>{r.verb} {r.endpoint}</code> on <code>{r.service}</code>: M={r.m}
          </div>
        ))}
      </div>
    </div>
  )
}

function GateResultCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateResultBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  const isSuccess = parsed.status_code >= 200 && parsed.status_code < 300
  const isJson = parsed.content_type?.includes('json')
  const MAX_BODY_LENGTH = 2000

  let displayBody = parsed.body || ''
  if (isJson && displayBody) {
    try {
      displayBody = JSON.stringify(JSON.parse(displayBody), null, 2)
    } catch {
      // keep raw
    }
  }
  const truncated = displayBody.length > MAX_BODY_LENGTH
  if (truncated) {
    displayBody = displayBody.slice(0, MAX_BODY_LENGTH)
  }

  return (
    <div className={`gate-card gate-result ${isSuccess ? 'gate-result-ok' : 'gate-result-err'}`}>
      <div className="gate-card-header">Gate Result</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div>
          <strong>Status:</strong>{' '}
          <span className={isSuccess ? 'gate-status-ok' : 'gate-status-err'}>
            {parsed.status_code}
          </span>
        </div>
        {parsed.content_type && (
          <div><strong>Content-Type:</strong> {parsed.content_type}</div>
        )}
        {displayBody && (
          <div className="gate-result-body-section">
            <strong>Response:</strong>
            <pre className="gate-result-body">{displayBody}{truncated ? '\n... (truncated)' : ''}</pre>
          </div>
        )}
      </div>
    </div>
  )
}

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
  const [dropboxUrl, setDropboxUrl] = useState('')
  const [defaultDropboxUrl, setDefaultDropboxUrl] = useState('')
  const [dropboxDraft, setDropboxDraft] = useState('')

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
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings')
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

  async function loadGateRecipes() {
    try {
      const response = await api.gateRecipes()
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
    if (!activeProfileId || !selectedConversationId || !selectedRecipe || !gateOrgId.trim()) {
      setError('Select a recipe and enter an org ID')
      return
    }

    setIsWorking(true)
    try {
      const response = await api.gateRun(
        activeProfileId,
        selectedConversationId,
        selectedRecipe,
        gateOrgId.trim(),
        gateServerUrl.trim(),
        Object.keys(gateArgs).length > 0 ? gateArgs : undefined,
      )
      setMessages((previous) => [...previous, response.message])
      setStatus(`Gate request submitted: ${selectedRecipe}`)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit gate request')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGatePromote() {
    if (!activeProfileId || !selectedConversationId || !gateOrgId.trim()) {
      setError('Enter an org ID to promote this conversation')
      return
    }

    setIsWorking(true)
    try {
      const response = await api.gatePromote(
        activeProfileId,
        selectedConversationId,
        gateOrgId.trim(),
        gatePromoteThreshold,
      )
      setMessages((previous) => [...previous, response.message])
      setStatus(`Gate promote sent: org=${gateOrgId.trim()} threshold=${gatePromoteThreshold}`)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to promote conversation')
    } finally {
      setIsWorking(false)
    }
  }

  async function onGateSecret() {
    if (!activeProfileId || !selectedConversationId || !secretService.trim() || !secretValue) {
      setError('Enter a service name and secret value')
      return
    }

    setIsWorking(true)
    try {
      const response = await api.gateSecret(
        activeProfileId,
        selectedConversationId,
        secretService.trim(),
        secretValue,
        secretHeaderName.trim() || undefined,
        secretHeaderTemplate.trim() || undefined,
      )
      setMessages((previous) => [...previous, response.message])
      setStatus(response.output || `Secret provisioned for ${secretService.trim()}`)
      setSecretValue('')
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to provision secret')
    } finally {
      setIsWorking(false)
    }
  }

  const onGateApprove = useCallback(async (requestId: string, conversationId: string) => {
    if (!activeProfileId) return

    setIsWorking(true)
    try {
      await api.gateApprove(activeProfileId, conversationId, requestId)
      setStatus(`Approval sent for ${requestId.slice(0, 8)}...`)
      setError('')
      // Refresh to show the new approval message
      await refreshHistory(activeProfileId, conversationId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve gate request')
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
          <span className="title-detail">
            <button
              className="settings-toggle"
              type="button"
              onClick={() => setShowSettings(!showSettings)}
            >
              {showSettings ? 'Back to chat' : 'Settings'}
            </button>
          </span>
        </header>

        <div className="aim-body">
          {showSettings ? (
            <div className="settings-page">
              <section className="panel">
                <h2>Dropbox Endpoint</h2>
                <p className="settings-description">
                  The dropbox is the relay server that stores and delivers encrypted messages.
                </p>

                <label className="label" htmlFor="dropbox-url">Dropbox URL</label>
                <input
                  id="dropbox-url"
                  className="input"
                  placeholder={defaultDropboxUrl}
                  value={dropboxDraft}
                  onChange={(event) => setDropboxDraft(event.target.value)}
                />

                <div className="row">
                  <button
                    className="button"
                    type="button"
                    disabled={isWorking}
                    onClick={() => void onSaveSettings()}
                  >
                    Save
                  </button>
                  <button
                    className="button"
                    type="button"
                    disabled={isWorking || dropboxDraft === defaultDropboxUrl}
                    onClick={() => {
                      setDropboxDraft(defaultDropboxUrl)
                    }}
                  >
                    Reset to default
                  </button>
                </div>

                <div className="meta">
                  <div><strong>Current:</strong> {dropboxUrl}</div>
                  <div><strong>Default:</strong> {defaultDropboxUrl}</div>
                </div>
              </section>

              {error && <div className="error-banner">{error}</div>}
            </div>
          ) : (
          <>
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
                {identity.publicKey && (
                  <div className="pubkey-row">
                    <strong>Public key:</strong>
                    <code className="pubkey-value">{shortId(identity.publicKey)}</code>
                    <button
                      className="button-small"
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(identity.publicKey)
                        setStatus('Public key copied to clipboard')
                      }}
                    >
                      Copy
                    </button>
                  </div>
                )}
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

            <section className="panel">
              <h2>Gate</h2>

              <label className="label" htmlFor="gate-recipe">Recipe</label>
              <select
                id="gate-recipe"
                className="input"
                value={selectedRecipe}
                onChange={(event) => onRecipeChange(event.target.value)}
              >
                <option value="">Select a recipe...</option>
                {gateRecipes.map((recipe) => (
                  <option key={recipe.name} value={recipe.name}>
                    {recipe.name} — {recipe.verb} {recipe.endpoint}
                  </option>
                ))}
              </select>

              <label className="label" htmlFor="gate-org">Org ID</label>
              <input
                id="gate-org"
                className="input"
                placeholder="e.g. acme"
                value={gateOrgId}
                onChange={(event) => setGateOrgId(event.target.value)}
              />

              <label className="label" htmlFor="gate-url">Gate server</label>
              <input
                id="gate-url"
                className="input"
                placeholder="http://localhost:8080"
                value={gateServerUrl}
                onChange={(event) => setGateServerUrl(event.target.value)}
              />

              {activeRecipe && (
                <div className="gate-args">
                  {(activeRecipe.path_params || []).length > 0 && (
                    <>
                      <div className="gate-args-heading">Path params</div>
                      {activeRecipe.path_params!.map((param) => (
                        <div className="gate-arg-field" key={`path-${param.name}`}>
                          <label className="label" htmlFor={`gate-path-${param.name}`}>
                            {param.name}{param.required ? ' *' : ''}
                          </label>
                          <input
                            id={`gate-path-${param.name}`}
                            className="input"
                            placeholder={param.description || param.name}
                            value={gateArgs[param.name] || ''}
                            onChange={(e) => onGateArgChange(param.name, e.target.value)}
                          />
                        </div>
                      ))}
                    </>
                  )}

                  {(activeRecipe.query_params || []).length > 0 && (
                    <>
                      <div className="gate-args-heading">Query params</div>
                      {activeRecipe.query_params!.map((param) => (
                        <div className="gate-arg-field" key={`query-${param.name}`}>
                          <label className="label" htmlFor={`gate-query-${param.name}`}>
                            {param.name}{param.required ? ' *' : ''}
                          </label>
                          <input
                            id={`gate-query-${param.name}`}
                            className="input"
                            placeholder={param.default || param.description || param.name}
                            value={gateArgs[param.name] || ''}
                            onChange={(e) => onGateArgChange(param.name, e.target.value)}
                          />
                        </div>
                      ))}
                    </>
                  )}

                  {activeRecipe.body_schema?.properties && (
                    <>
                      <div className="gate-args-heading">Body fields</div>
                      {Object.entries(activeRecipe.body_schema.properties as Record<string, { description?: string; type?: string }>).map(([key, prop]) => (
                        <div className="gate-arg-field" key={`body-${key}`}>
                          <label className="label" htmlFor={`gate-body-${key}`}>
                            {key}
                          </label>
                          <input
                            id={`gate-body-${key}`}
                            className="input"
                            placeholder={prop.description || prop.type || key}
                            value={gateArgs[key] || ''}
                            onChange={(e) => onGateArgChange(key, e.target.value)}
                          />
                        </div>
                      ))}
                    </>
                  )}

                  {!activeRecipe.body_schema && activeRecipe.body_example && (
                    <>
                      <div className="gate-args-heading">Request body</div>
                      <textarea
                        className="token-box"
                        placeholder={JSON.stringify(activeRecipe.body_example, null, 2)}
                        value={gateArgs._body || ''}
                        onChange={(e) => onGateArgChange('_body', e.target.value)}
                      />
                    </>
                  )}

                  {resolvedGateUrl && (
                    <div className="gate-url-preview">
                      <span className={`gate-verb gate-verb-${activeRecipe.verb.toLowerCase()}`}>
                        {activeRecipe.verb}
                      </span>{' '}
                      <code>{resolvedGateUrl}</code>
                    </div>
                  )}
                </div>
              )}

              <button
                className="button full"
                type="button"
                disabled={isWorking || !selectedConversation || !selectedRecipe || !gateOrgId.trim()}
                onClick={() => void onGateRun()}
              >
                Submit gate request
              </button>

              <div className="gate-promote-section">
                <div className="gate-args-heading">Promote conversation</div>
                <label className="label" htmlFor="gate-promote-threshold">Threshold</label>
                <input
                  id="gate-promote-threshold"
                  className="input"
                  type="number"
                  min={1}
                  value={gatePromoteThreshold}
                  onChange={(event) => setGatePromoteThreshold(Number(event.target.value) || 1)}
                />
                <button
                  className="button full"
                  type="button"
                  disabled={isWorking || !selectedConversation || !gateOrgId.trim()}
                  onClick={() => void onGatePromote()}
                >
                  Promote to Gate
                </button>
              </div>

              <div className="gate-secret-section">
                <div className="gate-args-heading">Add Secret</div>
                <label className="label" htmlFor="secret-service">Service</label>
                <input
                  id="secret-service"
                  className="input"
                  placeholder="e.g. stripe, github"
                  value={secretService}
                  onChange={(event) => setSecretService(event.target.value)}
                />
                <label className="label" htmlFor="secret-header-name">Header name</label>
                <input
                  id="secret-header-name"
                  className="input"
                  placeholder="Authorization"
                  value={secretHeaderName}
                  onChange={(event) => setSecretHeaderName(event.target.value)}
                />
                <label className="label" htmlFor="secret-header-template">Header template</label>
                <input
                  id="secret-header-template"
                  className="input"
                  placeholder="Bearer {value}"
                  value={secretHeaderTemplate}
                  onChange={(event) => setSecretHeaderTemplate(event.target.value)}
                />
                <label className="label" htmlFor="secret-value">Secret value</label>
                <input
                  id="secret-value"
                  className="input"
                  type="password"
                  placeholder="API key or token"
                  value={secretValue}
                  onChange={(event) => setSecretValue(event.target.value)}
                />
                <button
                  className="button full"
                  type="button"
                  disabled={isWorking || !selectedConversation || !secretService.trim() || !secretValue}
                  onClick={() => void onGateSecret()}
                >
                  Provision secret
                </button>
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
                  {message.bodyType === 'gate.promote' ? (
                    <GatePromoteCard message={message} />
                  ) : message.bodyType === 'gate.config' ? (
                    <GateConfigCard message={message} />
                  ) : message.bodyType === 'gate.request' ? (
                    <GateRequestCard message={message} onApprove={onGateApprove} isWorking={isWorking} />
                  ) : message.bodyType === 'gate.approval' ? (
                    <GateApprovalCard message={message} />
                  ) : message.bodyType === 'gate.executed' ? (
                    <GateExecutedCard message={message} />
                  ) : message.bodyType === 'gate.expired' ? (
                    <GateExpiredCard message={message} />
                  ) : message.bodyType === 'gate.result' ? (
                    <GateResultCard message={message} />
                  ) : (
                    <div className="message-body">{message.text}</div>
                  )}
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
          </>
          )}
        </div>
      </div>
    </div>
  )
}
