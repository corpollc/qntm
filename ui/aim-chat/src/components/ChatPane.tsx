import { FormEvent } from 'react'
import type { ChatMessage, Conversation, Profile } from '../types'
import { formatTime, shortId } from '../utils'
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

export interface ChatPaneProps {
  selectedConversation: Conversation | null
  messages: ChatMessage[]
  composer: string
  setComposer: (value: string) => void
  isWorking: boolean
  showGatePanel: boolean
  setShowGatePanel: (value: boolean) => void
  activeProfile: Profile | null
  status: string
  error: string
  messageTailRef: React.MutableRefObject<HTMLDivElement | null>
  onSendMessage: (event: FormEvent<HTMLFormElement>) => void
  onCheckMessages: () => void
  onGateApprove: (requestId: string, conversationId: string) => void
}

export function ChatPane({
  selectedConversation,
  messages,
  composer,
  setComposer,
  isWorking,
  showGatePanel,
  setShowGatePanel,
  activeProfile,
  status,
  error,
  messageTailRef,
  onSendMessage,
  onCheckMessages,
  onGateApprove,
}: ChatPaneProps) {
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

      {error && <div className="error-banner">{error}</div>}
    </main>
  )
}
