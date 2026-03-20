import { useState, useEffect } from 'react'
import type { Ref } from 'react'
import type { IdentityInfo } from '../types'
import { Tooltip } from './Tooltip'

export interface InvitePanelProps {
  inviteName: string
  setInviteName: (value: string) => void
  inviteToken: string
  setInviteToken: (value: string) => void
  createdInviteToken: string
  identity: IdentityInfo
  isWorking: boolean
  onCreateInvite: () => void
  onAcceptInvite: () => void
  newConversationInputRef?: Ref<HTMLInputElement>
}

export function InvitePanel({
  inviteName,
  setInviteName,
  inviteToken,
  setInviteToken,
  createdInviteToken,
  identity,
  isWorking,
  onCreateInvite,
  onAcceptInvite,
  newConversationInputRef,
}: InvitePanelProps) {
  const [createName, setCreateName] = useState(inviteName)
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
    setInviteName(createName)
    // Allow setInviteName to propagate before calling handler
    setTimeout(() => onCreateInvite(), 0)
  }

  function handleJoin() {
    setInviteName(joinName)
    setTimeout(() => onAcceptInvite(), 0)
  }

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(createdInviteToken)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback: select the text
    }
  }

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
            <span className="invite-success-label">Conversation created! Share this invite token: <Tooltip text="Share this token with someone to let them join your conversation." /></span>
            <div className="invite-token-row">
              <textarea
                className="token-box"
                value={createdInviteToken}
                readOnly
              />
              <button
                className="button invite-copy-btn"
                type="button"
                aria-label="Copy to clipboard"
                onClick={() => void handleCopy()}
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
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
              placeholder="Paste an invite token"
              value={inviteToken}
              onChange={(e) => setInviteToken(e.target.value)}
            />
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
