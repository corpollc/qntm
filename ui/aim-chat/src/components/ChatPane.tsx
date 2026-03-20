import { FormEvent, useMemo } from 'react'
import type { ChatMessage, Conversation, Profile } from '../types'
import { formatSmartTime, formatDateLabel, isSameDay, isSameGroup, senderColor, shortId, parseGateMessage } from '../utils'
import type { GateApprovalBody, GatePromoteBody } from '../gate-types'
import {
  GateRequestCard,
  GateApprovalCard,
  GateDisapprovalCard,
  GateExecutedCard,
  GateExpiredCard,
  GatePromoteCard,
  GateConfigCard,
  GateResultCard,
} from './GateCards'
import { GovProposalCard } from './GovernanceCards'
import { SystemEventCard } from './SystemEvents'
import { Composer } from './Composer'
import { WelcomeCard } from './WelcomeCard'

export interface ChatPaneProps {
  selectedConversation: Conversation | null
  messages: ChatMessage[]
  composer: string
  setComposer: (value: string) => void
  isWorking: boolean
  isSending: boolean
  isLoadingMessages: boolean
  showGatePanel: boolean
  setShowGatePanel: (value: boolean) => void
  activeProfile: Profile | null
  status: string
  messageTailRef: React.MutableRefObject<HTMLDivElement | null>
  onSendMessage: (event: FormEvent<HTMLFormElement>) => void
  onCheckMessages: () => void
  onGateApprove: (requestId: string, conversationId: string) => void
  onGateDisapprove?: (requestId: string, conversationId: string) => void
  onGovApprove?: (proposalId: string, conversationId: string) => void
  onGovDisapprove?: (proposalId: string, conversationId: string) => void
  conversationCount: number
  onOpenInvites: () => void
  onCopyInviteLink?: (token: string) => void
}

function MessageBody({ message, onGateApprove, onGateDisapprove, onGovApprove, onGovDisapprove, isWorking, approvalCounts, disapprovalCounts, requiredApprovals, approvedByMe, govApprovalCounts, govDisapprovalCounts, govRequiredApprovals, govApprovedByMe, govDisapprovedByMe, govApplied }: {
  message: ChatMessage
  onGateApprove: (requestId: string, conversationId: string) => void
  onGateDisapprove?: (requestId: string, conversationId: string) => void
  onGovApprove?: (proposalId: string, conversationId: string) => void
  onGovDisapprove?: (proposalId: string, conversationId: string) => void
  isWorking: boolean
  approvalCounts: Record<string, number>
  disapprovalCounts: Record<string, number>
  requiredApprovals: number
  approvedByMe: Set<string>
  govApprovalCounts: Record<string, number>
  govDisapprovalCounts: Record<string, number>
  govRequiredApprovals: Record<string, number>
  govApprovedByMe: Set<string>
  govDisapprovedByMe: Set<string>
  govApplied: Set<string>
}) {
  if (message.bodyType === 'gate.promote') return <GatePromoteCard message={message} />
  if (message.bodyType === 'gate.config') return <GateConfigCard message={message} />
  if (message.bodyType === 'gate.request') {
    const parsed = parseGateMessage(message.text) as import('../gate-types').GateRequestBody | null
    const requestId = parsed?.request_id || ''
    return <GateRequestCard message={message} onApprove={onGateApprove} onDisapprove={onGateDisapprove} isWorking={isWorking} alreadyApproved={approvedByMe.has(requestId)} approvalCount={approvalCounts[requestId] || 0} disapprovalCount={disapprovalCounts[requestId] || 0} requiredApprovals={requiredApprovals} />
  }
  if (message.bodyType === 'gate.approval') {
    const parsed = parseGateMessage(message.text) as GateApprovalBody | null
    const requestId = parsed?.request_id || ''
    return <GateApprovalCard message={message} approvalCount={approvalCounts[requestId] || 0} requiredApprovals={requiredApprovals} />
  }
  if (message.bodyType === 'gate.disapproval') return <GateDisapprovalCard message={message} />
  if (message.bodyType === 'gate.executed') return <GateExecutedCard message={message} />
  if (message.bodyType === 'gate.expired') return <GateExpiredCard message={message} />
  if (message.bodyType === 'gate.invalidated') return <SystemEventCard message={message} />
  if (message.bodyType === 'gate.result') return <GateResultCard message={message} />
  if (message.bodyType === 'group_genesis' || message.bodyType === 'group_add' || message.bodyType === 'group_remove' || message.bodyType === 'group_rekey') {
    return <SystemEventCard message={message} />
  }
  if (message.bodyType === 'gov.propose') {
    const parsed = parseGateMessage(message.text) as { proposal_id?: string } | null
    const proposalId = parsed?.proposal_id || ''
    return (
      <GovProposalCard
        message={message}
        onApprove={onGovApprove}
        onDisapprove={onGovDisapprove}
        isWorking={isWorking}
        alreadyApproved={govApprovedByMe.has(proposalId)}
        alreadyDisapproved={govDisapprovedByMe.has(proposalId)}
        approvalCount={govApprovalCounts[proposalId] || 0}
        disapprovalCount={govDisapprovalCounts[proposalId] || 0}
        requiredApprovals={govRequiredApprovals[proposalId] || 0}
        isApplied={govApplied.has(proposalId)}
      />
    )
  }
  if (message.bodyType === 'gov.approve' || message.bodyType === 'gov.disapprove' || message.bodyType === 'gov.applied' || message.bodyType === 'gov.invalidated') {
    return <SystemEventCard message={message} />
  }
  return <div className="message-body">{message.text}</div>
}

export function ChatPane({
  selectedConversation,
  messages,
  composer,
  setComposer,
  isWorking,
  isSending,
  isLoadingMessages,
  showGatePanel,
  setShowGatePanel,
  activeProfile,
  status,
  messageTailRef,
  onSendMessage,
  onCheckMessages,
  onGateApprove,
  onGateDisapprove,
  onGovApprove,
  onGovDisapprove,
  conversationCount,
  onOpenInvites,
  onCopyInviteLink,
}: ChatPaneProps) {
  const lastOutgoingIndex = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].direction === 'outgoing') return i
    }
    return -1
  })()

  // Count approvals per request_id and track which ones current user approved
  const {
    approvalCounts,
    disapprovalCounts,
    requiredApprovals,
    approvedByMe,
    govApprovalCounts,
    govDisapprovalCounts,
    govRequiredApprovals,
    govApprovedByMe,
    govDisapprovedByMe,
    govApplied,
  } = useMemo(() => {
    const counts: Record<string, number> = {}
    const denyCounts: Record<string, number> = {}
    const myApprovals = new Set<string>()
    const govVotes: Record<string, Record<string, 'approve' | 'disapprove'>> = {}
    const govApprovals: Record<string, number> = {}
    const govDisapprovals: Record<string, number> = {}
    const govRequired: Record<string, number> = {}
    const myGovApprovals = new Set<string>()
    const myGovDisapprovals = new Set<string>()
    const appliedGov = new Set<string>()
    let threshold = 0
    for (const msg of messages) {
      if (msg.bodyType === 'gate.request') {
        const parsed = parseGateMessage(msg.text)
        if (parsed && 'request_id' in parsed) {
          const requestId = parsed.request_id as string
          counts[requestId] = 1 // submission = first approval
          if (msg.direction === 'outgoing') {
            myApprovals.add(requestId)
          }
        }
      } else if (msg.bodyType === 'gate.approval') {
        const parsed = parseGateMessage(msg.text) as GateApprovalBody | null
        if (parsed?.request_id) {
          counts[parsed.request_id] = (counts[parsed.request_id] || 0) + 1
          if (msg.direction === 'outgoing') {
            myApprovals.add(parsed.request_id)
          }
        }
      } else if (msg.bodyType === 'gate.disapproval') {
        const parsed = parseGateMessage(msg.text) as { request_id?: string } | null
        if (parsed?.request_id) {
          denyCounts[parsed.request_id] = (denyCounts[parsed.request_id] || 0) + 1
        }
      } else if (msg.bodyType === 'gate.promote') {
        try {
          const body = JSON.parse(msg.text) as GatePromoteBody
          if (body.rules?.[0]?.m) threshold = body.rules[0].m
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.propose') {
        try {
          const parsed = JSON.parse(msg.text) as {
            proposal_id: string
            signer_kid: string
            required_approvals: number
          }
          govVotes[parsed.proposal_id] = govVotes[parsed.proposal_id] || {}
          govVotes[parsed.proposal_id][parsed.signer_kid] = 'approve'
          govRequired[parsed.proposal_id] = parsed.required_approvals || 1
          if (msg.direction === 'outgoing') {
            myGovApprovals.add(parsed.proposal_id)
            myGovDisapprovals.delete(parsed.proposal_id)
          }
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.approve') {
        try {
          const parsed = JSON.parse(msg.text) as { proposal_id: string; signer_kid: string }
          govVotes[parsed.proposal_id] = govVotes[parsed.proposal_id] || {}
          govVotes[parsed.proposal_id][parsed.signer_kid] = 'approve'
          if (msg.direction === 'outgoing') {
            myGovApprovals.add(parsed.proposal_id)
            myGovDisapprovals.delete(parsed.proposal_id)
          }
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.disapprove') {
        try {
          const parsed = JSON.parse(msg.text) as { proposal_id: string; signer_kid: string }
          govVotes[parsed.proposal_id] = govVotes[parsed.proposal_id] || {}
          govVotes[parsed.proposal_id][parsed.signer_kid] = 'disapprove'
          if (msg.direction === 'outgoing') {
            myGovApprovals.delete(parsed.proposal_id)
            myGovDisapprovals.add(parsed.proposal_id)
          }
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.applied') {
        try {
          const parsed = JSON.parse(msg.text) as { proposal_id: string }
          appliedGov.add(parsed.proposal_id)
        } catch { /* ignore */ }
      }
    }
    for (const [proposalId, votes] of Object.entries(govVotes)) {
      govApprovals[proposalId] = Object.values(votes).filter((vote) => vote === 'approve').length
      govDisapprovals[proposalId] = Object.values(votes).filter((vote) => vote === 'disapprove').length
    }
    return {
      approvalCounts: counts,
      disapprovalCounts: denyCounts,
      requiredApprovals: threshold,
      approvedByMe: myApprovals,
      govApprovalCounts: govApprovals,
      govDisapprovalCounts: govDisapprovals,
      govRequiredApprovals: govRequired,
      govApprovedByMe: myGovApprovals,
      govDisapprovedByMe: myGovDisapprovals,
      govApplied: appliedGov,
    }
  }, [messages])

  const showWelcome = conversationCount === 0 && messages.length === 0
  return (
    <main id="chat-pane" className={`chat-pane ${showGatePanel ? 'with-gate' : ''}`}>
      <div className="chat-header">
        <div className="chat-header-left">
          <div className="chat-header-title">
            <strong>{selectedConversation?.name || 'No conversation selected'}</strong>
            {selectedConversation?.inviteToken && (
              <button
                className="invite-add-btn"
                type="button"
                title="Invite"
                onClick={() => onCopyInviteLink?.(selectedConversation.inviteToken!)}
              >
                +
              </button>
            )}
          </div>
          <div className="chat-subheader">
            {selectedConversation ? shortId(selectedConversation.id) : 'Create or accept an invite'}
          </div>
        </div>
        {selectedConversation && (
          <button
            className={`gate-toggle ${showGatePanel ? 'active' : ''}`}
            type="button"
            onClick={() => setShowGatePanel(!showGatePanel)}
            aria-label={showGatePanel ? 'Close API Gateway panel' : 'Open API Gateway panel'}
            aria-expanded={showGatePanel}
          >
            {showGatePanel ? 'API Gateway \u2715' : 'API Gateway \u25B6'}
          </button>
        )}
      </div>

      <div className="chat-log">
        {showWelcome && (
          <WelcomeCard
            conversationCount={conversationCount}
            isWorking={isWorking}
            onOpenInvites={onOpenInvites}
          />
        )}
        {!showWelcome && messages.length === 0 && isLoadingMessages && (
          <>
            <div className="skeleton skeleton-message" />
            <div className="skeleton skeleton-message" />
            <div className="skeleton skeleton-message" />
            <div className="skeleton skeleton-message" />
          </>
        )}
        {!showWelcome && messages.length === 0 && !isLoadingMessages && <div className="empty">No messages yet. Type a message below to start the conversation.</div>}
        {messages.map((message, index) => {
          const prev = index > 0 ? messages[index - 1] : null
          const showDate = !prev || !isSameDay(prev.createdAt, message.createdAt)
          const isGroupFirst = !prev || showDate || !isSameGroup(prev, message)
          const color = senderColor(message.sender)
          const initial = message.sender.charAt(0).toUpperCase()

          return (
            <div key={message.id}>
              {showDate && (
                <div className="date-separator">
                  <span className="date-separator-label">{formatDateLabel(message.createdAt)}</span>
                </div>
              )}
              <div className={`message-group ${message.direction}`}>
                <article className={`message ${message.direction} ${isGroupFirst ? 'message-group-first' : 'message-group-cont'}`}>
                  {isGroupFirst && (
                    <div className="message-top">
                      <span className="sender">{message.sender}</span>
                      <span className="time">
                        {formatSmartTime(message.createdAt)}
                        {message.direction === 'outgoing' && (
                          isSending && index === lastOutgoingIndex
                            ? <span className="message-status message-status-pending"> sending…</span>
                            : <span className="message-status message-status-sent"> ✓</span>
                        )}
                      </span>
                    </div>
                  )}
                  <MessageBody message={message} onGateApprove={onGateApprove} onGateDisapprove={onGateDisapprove} onGovApprove={onGovApprove} onGovDisapprove={onGovDisapprove} isWorking={isWorking} approvalCounts={approvalCounts} disapprovalCounts={disapprovalCounts} requiredApprovals={requiredApprovals} approvedByMe={approvedByMe} govApprovalCounts={govApprovalCounts} govDisapprovalCounts={govDisapprovalCounts} govRequiredApprovals={govRequiredApprovals} govApprovedByMe={govApprovedByMe} govDisapprovedByMe={govDisapprovedByMe} govApplied={govApplied} />
                </article>
              </div>
            </div>
          )
        })}
        <div ref={messageTailRef} />
      </div>

      <Composer
        selectedConversation={selectedConversation}
        composer={composer}
        setComposer={setComposer}
        isWorking={isWorking}
        onSendMessage={onSendMessage}
        onCheckMessages={onCheckMessages}
      />

      <footer className="status-bar" aria-live="polite">
        <span>
          Profile: <strong>{activeProfile?.name || '-'}</strong>
        </span>
        <span>{status || 'Idle'}</span>
      </footer>

    </main>
  )
}
