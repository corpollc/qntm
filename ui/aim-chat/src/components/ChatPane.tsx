import { FormEvent, useMemo } from 'react'
import type { ChatMessage, Conversation, Profile } from '../types'
import { formatSmartTime, formatDateLabel, isSameDay, isSameGroup, senderColor, shortId, parseGateMessage } from '../utils'
import type { GateApprovalBody, GatePromoteBody } from '../gate-types'
import {
  GateRequestCard,
  GateApprovalCard,
  GateExecutedCard,
  GateExpiredCard,
  GatePromoteCard,
  GateConfigCard,
  GateResultCard,
} from './GateCards'
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
  identityExists: boolean
  conversationCount: number
  onGenerateIdentity: () => void
  onOpenInvites: () => void
}

function MessageBody({ message, onGateApprove, isWorking, approvalCounts, requiredApprovals, approvedByMe }: {
  message: ChatMessage
  onGateApprove: (requestId: string, conversationId: string) => void
  isWorking: boolean
  approvalCounts: Record<string, number>
  requiredApprovals: number
  approvedByMe: Set<string>
}) {
  if (message.bodyType === 'gate.promote') return <GatePromoteCard message={message} />
  if (message.bodyType === 'gate.config') return <GateConfigCard message={message} />
  if (message.bodyType === 'gate.request') {
    const parsed = parseGateMessage(message.text) as import('../gate-types').GateRequestBody | null
    const requestId = parsed?.request_id || ''
    return <GateRequestCard message={message} onApprove={onGateApprove} isWorking={isWorking} alreadyApproved={approvedByMe.has(requestId)} approvalCount={approvalCounts[requestId] || 0} requiredApprovals={requiredApprovals} />
  }
  if (message.bodyType === 'gate.approval') {
    const parsed = parseGateMessage(message.text) as GateApprovalBody | null
    const requestId = parsed?.request_id || ''
    return <GateApprovalCard message={message} approvalCount={approvalCounts[requestId] || 0} requiredApprovals={requiredApprovals} />
  }
  if (message.bodyType === 'gate.executed') return <GateExecutedCard message={message} />
  if (message.bodyType === 'gate.expired') return <GateExpiredCard message={message} />
  if (message.bodyType === 'gate.result') return <GateResultCard message={message} />
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
  identityExists,
  conversationCount,
  onGenerateIdentity,
  onOpenInvites,
}: ChatPaneProps) {
  const lastOutgoingIndex = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].direction === 'outgoing') return i
    }
    return -1
  })()

  // Count approvals per request_id and track which ones current user approved
  const { approvalCounts, requiredApprovals, approvedByMe } = useMemo(() => {
    const counts: Record<string, number> = {}
    const myApprovals = new Set<string>()
    let threshold = 0
    for (const msg of messages) {
      if (msg.bodyType === 'gate.request') {
        const parsed = parseGateMessage(msg.text)
        if (parsed && 'request_id' in parsed) {
          const requestId = parsed.request_id as string
          counts[requestId] = 1 // submission = first approval
          // If this is an outgoing message, the current user submitted (and thus approved) it
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
      } else if (msg.bodyType === 'gate.promote') {
        try {
          const body = JSON.parse(msg.text) as GatePromoteBody
          if (body.rules?.[0]?.m) threshold = body.rules[0].m
        } catch { /* ignore */ }
      }
    }
    return { approvalCounts: counts, requiredApprovals: threshold, approvedByMe: myApprovals }
  }, [messages])

  const showWelcome = !identityExists || (conversationCount === 0 && messages.length === 0)
  return (
    <main id="chat-pane" className={`chat-pane ${showGatePanel ? 'with-gate' : ''}`}>
      <div className="chat-header">
        <div className="chat-header-left">
          <div>
            <strong>{selectedConversation?.name || 'No conversation selected'}</strong>
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
            identityExists={identityExists}
            conversationCount={conversationCount}
            isWorking={isWorking}
            onGenerateIdentity={onGenerateIdentity}
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
                            ? <span className="message-status message-status-pending"> sending\u2026</span>
                            : <span className="message-status message-status-sent"> \u2713</span>
                        )}
                      </span>
                    </div>
                  )}
                  <MessageBody message={message} onGateApprove={onGateApprove} isWorking={isWorking} approvalCounts={approvalCounts} requiredApprovals={requiredApprovals} approvedByMe={approvedByMe} />
                  <div className="message-type">{message.bodyType}</div>
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
