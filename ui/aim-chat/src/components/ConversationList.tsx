import type { Conversation } from '../types'
import { shortId } from '../utils'

export interface ConversationListProps {
  visibleConversations: Conversation[]
  selectedConversationId: string
  setSelectedConversationId: (id: string) => void
  hiddenConversations: Set<string>
  hiddenCount: number
  showHidden: boolean
  setShowHidden: (fn: (prev: boolean) => boolean) => void
  toggleHideConversation: (convId: string) => void
}

export function ConversationList({
  visibleConversations,
  selectedConversationId,
  setSelectedConversationId,
  hiddenConversations,
  hiddenCount,
  showHidden,
  setShowHidden,
  toggleHideConversation,
}: ConversationListProps) {
  return (
    <section className="panel grow">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <h2>Conversations</h2>
        {hiddenCount > 0 && (
          <button
            className="button-small"
            type="button"
            onClick={() => setShowHidden(v => !v)}
            title={showHidden ? 'Hide hidden conversations' : 'Show hidden conversations'}
          >
            {showHidden ? `Hide (${hiddenCount})` : `${hiddenCount} hidden`}
          </button>
        )}
      </div>
      <ul className="conversation-list">
        {visibleConversations.length === 0 && <li className="empty">No conversations yet</li>}
        {visibleConversations.map((conversation) => (
          <li key={conversation.id}>
            <div className={`conversation ${conversation.id === selectedConversationId ? 'selected' : ''}`}>
              <button
                className="conversation-select"
                type="button"
                onClick={() => setSelectedConversationId(conversation.id)}
              >
                <span className="conversation-name">{conversation.name}</span>
                <span className="conversation-id">{shortId(conversation.id)}</span>
              </button>
              <button
                className="conversation-hide"
                type="button"
                onClick={(e) => { e.stopPropagation(); toggleHideConversation(conversation.id) }}
                title={hiddenConversations.has(conversation.id) ? 'Unhide' : 'Hide'}
              >
                {hiddenConversations.has(conversation.id) ? 'Show' : '\u00d7'}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
