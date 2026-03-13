import { FormEvent } from 'react'
import type { ChatMessage, Conversation, Profile } from '../types'
import { formatSmartTime, formatDateLabel, isSameDay, isSameGroup, senderColor, shortId } from '../utils'
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

function MessageBody({ message, onGateApprove, isWorking }: { message: ChatMessage; onGateApprove: (requestId: string, conversationId: string) => void; isWorking: boolean }) {
  if (message.bodyType === 'gate.promote') return <GatePromoteCard message={message} />
  if (message.bodyType === 'gate.config') return <GateConfigCard message={message} />
  if (message.bodyType === 'gate.request') return <GateRequestCard message={message} onApprove={onGateApprove} isWorking={isWorking} />
  if (message.bodyType === 'gate.approval') return <GateApprovalCard message={message} />
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
  const showWelcome = !identityExists || (conversationCount === 0 && messages.length === 0)
  return (
    <main className={`chat-pane ${showGatePanel ? 'with-gate' : ''}`}>
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
        {!showWelcome && messages.length === 0 && !isLoadingMessages && <div className="empty">No messages yet.</div>}
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
                {isGroupFirst && message.direction === 'incoming' && (
                  <span className="sender-avatar" style={{ background: color }}>{initial}</span>
                )}
                <article className={`message ${message.direction} ${isGroupFirst ? 'message-group-first' : 'message-group-cont'}`}>
                  {isGroupFirst && (
                    <div className="message-top">
                      <span className="sender">{message.sender}</span>
                      <span className="time">{formatSmartTime(message.createdAt)}</span>
                    </div>
                  )}
                  <MessageBody message={message} onGateApprove={onGateApprove} isWorking={isWorking} />
                  <div className="message-type">{message.bodyType}</div>
                </article>
                {isGroupFirst && message.direction === 'outgoing' && (
                  <span className="sender-avatar" style={{ background: color }}>{initial}</span>
                )}
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

      <footer className="status-bar">
        <span>
          Profile: <strong>{activeProfile?.name || '-'}</strong>
        </span>
        <span>{status || 'Idle'}</span>
      </footer>

    </main>
  )
}
