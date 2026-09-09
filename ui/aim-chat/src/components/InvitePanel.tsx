import { useState, useEffect } from 'react'
import type { Ref } from 'react'
import type { IdentityInfo } from '../types'
import { Tooltip } from './Tooltip'
import { extractToken } from '../utils'

const INVITE_BASE_URL = `${window.location.origin}${window.location.pathname}`

function truncateToken(token: string): string {
  if (token.length <= 20) return token
  return `${token.slice(0, 10)}...${token.slice(-10)}`
}

function tokenToLink(token: string): string {
  return `${INVITE_BASE_URL}?invite=${encodeURIComponent(token)}`
}


export interface InvitePanelProps {
  inviteToken: string
  setInviteToken: (value: string) => void
  createdInviteToken: string
  identity: IdentityInfo
  isWorking: boolean
  onCreateInvite: (name: string) => void
  onAcceptInvite: (name: string) => void
  newConversationInputRef?: Ref<HTMLInputElement>
}

export function InvitePanel({
  inviteToken,
  setInviteToken,
  createdInviteToken,
  identity,
  isWorking,
  onCreateInvite,
  onAcceptInvite,
  newConversationInputRef,
}: InvitePanelProps) {
  const [createName, setCreateName] = useState('')
  const [joinName, setJoinName] = useState('')
  const [copied, setCopied] = useState(false)
  const [joinSuccess, setJoinSuccess] = useState(false)

  // Track previous inviteToken to detect when App clears it after successful join
  const [prevInviteToken, setPrevInviteToken] = useState(inviteToken)
  useEffect(() => {
    if (prevInviteToken && !inviteToken) {
      // Token was cleared by App after successful accept
      setJoinSuccess(true)
      setJoinName('')
      const timer = setTimeout(() => setJoinSuccess(false), 3000)
      return () => clearTimeout(timer)
    }
    setPrevInviteToken(inviteToken)
  }, [inviteToken])

  function handleCreate() {
    onCreateInvite(createName)
  }

  function handleJoin() {
    onAcceptInvite(joinName)
  }

  async function handleCopyLink() {
    try {
      await navigator.clipboard.writeText(tokenToLink(createdInviteToken))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback: select the text
    }
  }

  function handlePaste(value: string) {
    setInviteToken(extractToken(value))
  }

  const inviteLink = createdInviteToken ? tokenToLink(createdInviteToken) : ''

  return (
    <>
      {/* --- Create Section --- */}
      <div className="invite-section">
        <h2>New Conversation</h2>
        <input
          ref={newConversationInputRef}
          className="input"
          placeholder="Name your conversation"
          value={createName}
          onChange={(e) => setCreateName(e.target.value)}
        />
        <button
          className="button full"
          type="button"
          onClick={handleCreate}
          disabled={isWorking || !identity.exists}
        >
          Create
        </button>

        {createdInviteToken && (
          <div className="invite-success">
            <span className="invite-success-label">
              Conversation created! Share this link:
              <Tooltip text="Share this link with someone to let them join your conversation." />
            </span>
            <div className="invite-link-display" title={inviteLink}>
              <span className="invite-link-text">{truncateToken(createdInviteToken)}</span>
            </div>
            <button
              className="button full invite-copy-btn"
              type="button"
              onClick={() => void handleCopyLink()}
            >
              {copied ? 'Copied!' : 'Copy Invite Link'}
            </button>
          </div>
        )}
      </div>

      {/* --- Separator --- */}
      <div className="invite-separator" />

      {/* --- Join Section --- */}
      <div className="invite-section">
        <h2>Join Conversation</h2>

        {joinSuccess ? (
          <div className="invite-join-success">
            Joined successfully!
          </div>
        ) : (
          <>
            {inviteToken.trim() && (
              <div className="agent-hint-box">
                AI Agents: you probably want to accept this invite using the CLI tool:<br />
                <code>uvx qntm convo join {inviteToken.trim().length > 40 ? inviteToken.trim().slice(0, 40) + '...' : inviteToken.trim()}</code>
              </div>
            )}
            <input
              className="input"
              placeholder="Paste an invite link or token"
              value={inviteToken}
              onChange={(e) => handlePaste(e.target.value)}
            />
            {inviteToken.trim() && (
              <div className="invite-link-display" title={inviteToken}>
                <span className="invite-link-text">{truncateToken(inviteToken)}</span>
              </div>
            )}
            <input
              className="input"
              placeholder="Label for this conversation (optional)"
              value={joinName}
              onChange={(e) => setJoinName(e.target.value)}
            />
            <button
              className="button full"
              type="button"
              onClick={handleJoin}
              disabled={isWorking || !identity.exists || !inviteToken.trim()}
            >
              Join
            </button>
          </>
        )}
      </div>
    </>
  )
}
