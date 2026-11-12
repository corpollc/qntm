import { FormEvent, useMemo } from 'react'
import { base64UrlDecode } from '@corpollc/qntm'
import type { ChatMessage, Conversation } from '../types'
import { formatSmartTime, formatDateLabel, isSameDay, isSameGroup, senderColor, shortId, parseGateMessage } from '../utils'
import { bytesToHex } from '../qntm'
import type { GateApprovalBody, GatePromoteBody, GateRequestBody } from '../gate-types'
import {
  GateRequestCard,
  GateApprovalCard,
  GateDisapprovalCard,
  GateExecutedCard,
  GateExpiredCard,
  GateAcceptanceCard,
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

function decodeSignerKidHex(signerKid: unknown): string | null {
  if (typeof signerKid !== 'string' || !signerKid.trim()) return null
  try {
    const decoded = base64UrlDecode(signerKid.trim())
    if (decoded.length !== 16) return null
    return bytesToHex(decoded).toLowerCase()
  } catch {
    return null
  }
}

function isAuthenticSignerMessage(message: ChatMessage, signerKid: unknown, participantsHex?: Set<string>): signerKid is string {
  const signerHex = decodeSignerKidHex(signerKid)
  if (!signerHex) return false
  if (message.direction === 'incoming' && message.senderKey && message.senderKey.toLowerCase() !== signerHex) {
    return false
  }
  if (participantsHex && participantsHex.size > 0 && !participantsHex.has(signerHex)) {
    return false
  }
  return true
}

function MessageBody({ message, onGateApprove, onGateDisapprove, onGovApprove, onGovDisapprove, isWorking, approvalCounts, disapprovalCounts, requiredApprovalsByRequest, defaultRequiredApprovals, approvedByMe, disapprovedByMe, executedRequests, govApprovalCounts, govDisapprovalCounts, govRequiredApprovals, govApprovedByMe, govDisapprovedByMe, govApplied }: {
  message: ChatMessage
  onGateApprove: (requestId: string, conversationId: string) => void
  onGateDisapprove?: (requestId: string, conversationId: string) => void
  onGovApprove?: (proposalId: string, conversationId: string) => void
  onGovDisapprove?: (proposalId: string, conversationId: string) => void
  isWorking: boolean
  approvalCounts: Record<string, number>
  disapprovalCounts: Record<string, number>
  requiredApprovalsByRequest: Record<string, number>
  defaultRequiredApprovals: number
  approvedByMe: Set<string>
  disapprovedByMe: Set<string>
  executedRequests: Set<string>
  govApprovalCounts: Record<string, number>
  govDisapprovalCounts: Record<string, number>
  govRequiredApprovals: Record<string, number>
  govApprovedByMe: Set<string>
  govDisapprovedByMe: Set<string>
  govApplied: Set<string>
}) {
  if (message.bodyType === 'gate.accept') return <GateAcceptanceCard />
  if (message.bodyType === 'gate.promote') return <GatePromoteCard message={message} />
  if (message.bodyType === 'gate.config') return <GateConfigCard message={message} />
  if (message.bodyType === 'gate.request') {
    const parsed = parseGateMessage(message.text) as GateRequestBody | null
    const requestId = parsed?.request_id || ''
    const reqThreshold = requiredApprovalsByRequest[requestId] || parsed?.required_approvals || defaultRequiredApprovals
    return <GateRequestCard message={message} onApprove={onGateApprove} onDisapprove={onGateDisapprove} isWorking={isWorking} alreadyApproved={approvedByMe.has(requestId)} alreadyDisapproved={disapprovedByMe.has(requestId)} isExecuted={executedRequests.has(requestId)} approvalCount={approvalCounts[requestId] || 0} disapprovalCount={disapprovalCounts[requestId] || 0} requiredApprovals={reqThreshold} />
  }
  if (message.bodyType === 'gate.approval') {
    const parsed = parseGateMessage(message.text) as GateApprovalBody | null
    const requestId = parsed?.request_id || ''
    const reqThreshold = requiredApprovalsByRequest[requestId] || defaultRequiredApprovals
    return <GateApprovalCard message={message} approvalCount={approvalCounts[requestId] || 0} requiredApprovals={reqThreshold} />
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
    const parsed = parseGateMessage(message.text) as { proposal_id?: string; required_approvals?: number } | null
    const proposalId = parsed?.proposal_id || ''
    const propThreshold = govRequiredApprovals[proposalId] || parsed?.required_approvals || defaultRequiredApprovals
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
        requiredApprovals={propThreshold}
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

  // Count unique eligible approvals/disapprovals per request_id and proposal_id
  const {
    approvalCounts,
    disapprovalCounts,
    requiredApprovalsByRequest,
    defaultRequiredApprovals,
    approvedByMe,
    disapprovedByMe,
    executedRequests,
    govApprovalCounts,
    govDisapprovalCounts,
    govRequiredApprovals,
    govApprovedByMe,
    govDisapprovedByMe,
    govApplied,
  } = useMemo(() => {
    const gateVotes: Record<string, Record<string, 'approve' | 'disapprove'>> = {}
    const gateEligible: Record<string, Set<string>> = {}
    const reqRequired: Record<string, number> = {}
    const counts: Record<string, number> = {}
    const denyCounts: Record<string, number> = {}
    const myApprovals = new Set<string>()
    const myDisapprovals = new Set<string>()
    const executed = new Set<string>()
    const govVotes: Record<string, Record<string, 'approve' | 'disapprove'>> = {}
    const govEligible: Record<string, Set<string>> = {}
    const govApprovals: Record<string, number> = {}
    const govDisapprovals: Record<string, number> = {}
    const govRequired: Record<string, number> = {}
    const myGovApprovals = new Set<string>()
    const myGovDisapprovals = new Set<string>()
    const appliedGov = new Set<string>()
    const participantsHex = selectedConversation?.participants?.length
      ? new Set(selectedConversation.participants.map((p) => p.toLowerCase()))
      : undefined
    const activeGatewayHex = selectedConversation?.gateway?.status === 'active'
      ? decodeSignerKidHex(selectedConversation.gateway.keyId)
      : null
    let threshold = selectedConversation?.gateway?.floor ?? 0

    for (const msg of messages) {
      if (msg.bodyType === 'gate.request') {
        const parsed = parseGateMessage(msg.text) as GateRequestBody | null
        if (parsed?.request_id && typeof parsed.signature === 'string' && parsed.signature.length > 0 && isAuthenticSignerMessage(msg, parsed.signer_kid)) {
          const requestId = parsed.request_id
          if (Array.isArray(parsed.eligible_signer_kids) && parsed.eligible_signer_kids.length > 0) {
            if (!parsed.eligible_signer_kids.includes(parsed.signer_kid)) continue
            gateEligible[requestId] = new Set(parsed.eligible_signer_kids)
          }
          if (typeof parsed.required_approvals === 'number' && parsed.required_approvals >= 1) {
            reqRequired[requestId] = parsed.required_approvals
          }
          gateVotes[requestId] = gateVotes[requestId] || {}
          gateVotes[requestId][parsed.signer_kid] = 'approve'
          if (msg.direction === 'outgoing') {
            myApprovals.add(requestId)
            myDisapprovals.delete(requestId)
          }
        }
      } else if (msg.bodyType === 'gate.approval') {
        const parsed = parseGateMessage(msg.text) as GateApprovalBody | null
        if (parsed?.request_id && typeof parsed.signature === 'string' && parsed.signature.length > 0) {
          const eligibleSet = gateEligible[parsed.request_id]
          if (!isAuthenticSignerMessage(msg, parsed.signer_kid, eligibleSet ? undefined : participantsHex)) continue
          if (eligibleSet && !eligibleSet.has(parsed.signer_kid)) continue
          gateVotes[parsed.request_id] = gateVotes[parsed.request_id] || {}
          gateVotes[parsed.request_id][parsed.signer_kid] = 'approve'
          if (msg.direction === 'outgoing') {
            myApprovals.add(parsed.request_id)
            myDisapprovals.delete(parsed.request_id)
          }
        }
      } else if (msg.bodyType === 'gate.disapproval') {
        const parsed = parseGateMessage(msg.text) as { request_id?: string; signer_kid?: string } | null
        if (parsed?.request_id) {
          const eligibleSet = gateEligible[parsed.request_id]
          if (!isAuthenticSignerMessage(msg, parsed.signer_kid, eligibleSet ? undefined : participantsHex)) continue
          if (eligibleSet && !eligibleSet.has(parsed.signer_kid)) continue
          gateVotes[parsed.request_id] = gateVotes[parsed.request_id] || {}
          gateVotes[parsed.request_id][parsed.signer_kid] = 'disapprove'
          if (msg.direction === 'outgoing') {
            myApprovals.delete(parsed.request_id)
            myDisapprovals.add(parsed.request_id)
          }
        }
      } else if (msg.bodyType === 'gate.executed' || msg.bodyType === 'gate.result' || msg.bodyType === 'gate.invalidated') {
        if (!activeGatewayHex) continue
        if (msg.direction === 'incoming' && msg.senderKey && msg.senderKey.toLowerCase() !== activeGatewayHex) continue
        try {
          const parsed = JSON.parse(msg.text) as { request_id?: string }
          if (parsed.request_id) executed.add(parsed.request_id)
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gate.promote') {
        try {
          const body = JSON.parse(msg.text) as GatePromoteBody
          const promotedFloor = body.floor ?? body.rules?.[0]?.m
          if (typeof promotedFloor === 'number' && promotedFloor >= 1) threshold = promotedFloor
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.propose') {
        try {
          const parsed = JSON.parse(msg.text) as {
            proposal_id: string
            signer_kid: string
            signature?: string
            eligible_signer_kids?: string[]
            required_approvals: number
          }
          if (!parsed.proposal_id || typeof parsed.signature !== 'string' || !parsed.signature || !isAuthenticSignerMessage(msg, parsed.signer_kid)) continue
          if (Array.isArray(parsed.eligible_signer_kids) && parsed.eligible_signer_kids.length > 0) {
            if (!parsed.eligible_signer_kids.includes(parsed.signer_kid)) continue
            govEligible[parsed.proposal_id] = new Set(parsed.eligible_signer_kids)
          }
          govVotes[parsed.proposal_id] = govVotes[parsed.proposal_id] || {}
          govVotes[parsed.proposal_id][parsed.signer_kid] = 'approve'
          govRequired[parsed.proposal_id] = Math.max(parsed.required_approvals || 1, 1)
          if (msg.direction === 'outgoing') {
            myGovApprovals.add(parsed.proposal_id)
            myGovDisapprovals.delete(parsed.proposal_id)
          }
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.approve') {
        try {
          const parsed = JSON.parse(msg.text) as { proposal_id: string; signer_kid: string; signature?: string }
          if (!parsed.proposal_id || typeof parsed.signature !== 'string' || !parsed.signature) continue
          const eligibleSet = govEligible[parsed.proposal_id]
          if (!isAuthenticSignerMessage(msg, parsed.signer_kid, eligibleSet ? undefined : participantsHex)) continue
          if (eligibleSet && !eligibleSet.has(parsed.signer_kid)) continue
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
          if (!parsed.proposal_id) continue
          const eligibleSet = govEligible[parsed.proposal_id]
          if (!isAuthenticSignerMessage(msg, parsed.signer_kid, eligibleSet ? undefined : participantsHex)) continue
          if (eligibleSet && !eligibleSet.has(parsed.signer_kid)) continue
          govVotes[parsed.proposal_id] = govVotes[parsed.proposal_id] || {}
          govVotes[parsed.proposal_id][parsed.signer_kid] = 'disapprove'
          if (msg.direction === 'outgoing') {
            myGovApprovals.delete(parsed.proposal_id)
            myGovDisapprovals.add(parsed.proposal_id)
          }
        } catch { /* ignore */ }
      } else if (msg.bodyType === 'gov.applied') {
        if (!activeGatewayHex) continue
        if (msg.direction === 'incoming' && msg.senderKey && msg.senderKey.toLowerCase() !== activeGatewayHex) continue
        try {
          const parsed = JSON.parse(msg.text) as { proposal_id: string; proposal_type?: string; applied_floor?: number }
          if (parsed.proposal_id) appliedGov.add(parsed.proposal_id)
          if (parsed.proposal_type === 'floor_change' && typeof parsed.applied_floor === 'number' && parsed.applied_floor >= 1) {
            threshold = parsed.applied_floor
          }
        } catch { /* ignore */ }
      }
    }

    const fallbackThreshold = Math.max(threshold || selectedConversation?.gateway?.floor || 1, 1)
    const resolvedReqRequired: Record<string, number> = {}
    for (const [requestId, votes] of Object.entries(gateVotes)) {
      counts[requestId] = Object.values(votes).filter((vote) => vote === 'approve').length
      denyCounts[requestId] = Object.values(votes).filter((vote) => vote === 'disapprove').length
      resolvedReqRequired[requestId] = Math.max(reqRequired[requestId] || fallbackThreshold, 1)
    }
    for (const [proposalId, votes] of Object.entries(govVotes)) {
      govApprovals[proposalId] = Object.values(votes).filter((vote) => vote === 'approve').length
      govDisapprovals[proposalId] = Object.values(votes).filter((vote) => vote === 'disapprove').length
    }
    return {
      approvalCounts: counts,
      disapprovalCounts: denyCounts,
      requiredApprovalsByRequest: resolvedReqRequired,
      defaultRequiredApprovals: fallbackThreshold,
      approvedByMe: myApprovals,
      disapprovedByMe: myDisapprovals,
      executedRequests: executed,
      govApprovalCounts: govApprovals,
      govDisapprovalCounts: govDisapprovals,
      govRequiredApprovals: govRequired,
      govApprovedByMe: myGovApprovals,
      govDisapprovedByMe: myGovDisapprovals,
      govApplied: appliedGov,
    }
  }, [messages, selectedConversation])

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
                  <MessageBody message={message} onGateApprove={onGateApprove} onGateDisapprove={onGateDisapprove} onGovApprove={onGovApprove} onGovDisapprove={onGovDisapprove} isWorking={isWorking} approvalCounts={approvalCounts} disapprovalCounts={disapprovalCounts} requiredApprovalsByRequest={requiredApprovalsByRequest} defaultRequiredApprovals={defaultRequiredApprovals} approvedByMe={approvedByMe} disapprovedByMe={disapprovedByMe} executedRequests={executedRequests} govApprovalCounts={govApprovalCounts} govDisapprovalCounts={govDisapprovalCounts} govRequiredApprovals={govRequiredApprovals} govApprovedByMe={govApprovedByMe} govDisapprovedByMe={govDisapprovedByMe} govApplied={govApplied} />
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
    </main>
  )
}
