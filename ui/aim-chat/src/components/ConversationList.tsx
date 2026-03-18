import type { Ref } from 'react'
import type { Conversation } from '../types'
import { shortId } from '../utils'

export interface ConversationListProps {
  visibleConversations: Conversation[]
  selectedConversationId: string
  setSelectedConversationId: (id: string) => void
  hiddenConversations: Set<string>
  unreadCounts: Record<string, number>
  hiddenCount: number
  showHidden: boolean
  setShowHidden: (fn: (prev: boolean) => boolean) => void
  toggleHideConversation: (convId: string) => void
  conversationFilter: string
  setConversationFilter: (value: string) => void
  filterInputRef?: Ref<HTMLInputElement>
}

export function ConversationList({
  visibleConversations,
  selectedConversationId,
  setSelectedConversationId,
  hiddenConversations,
  unreadCounts,
  toggleHideConversation,
  conversationFilter,
  setConversationFilter,
  filterInputRef,
}: ConversationListProps) {
  return (
    <>
      <input
        ref={filterInputRef}
        className="input conversation-filter"
        placeholder="Filter conversations..."
        aria-label="Filter conversations"
        value={conversationFilter}
        onChange={(e) => setConversationFilter(e.target.value)}
      />
      <ul className="conversation-list" role="listbox" aria-label="Conversations">
        {visibleConversations.length === 0 && <li className="empty" role="presentation">No conversations yet. Create one above or join with an invite token.</li>}
        {visibleConversations.map((conversation) => {
          const unread = unreadCounts[conversation.id] || 0
          const isSelected = conversation.id === selectedConversationId
          return (
          <li key={conversation.id} role="option" aria-selected={isSelected}>
            <div className={`conversation ${isSelected ? 'selected' : ''}`}>
              <button
                className="conversation-select"
                type="button"
                onClick={() => setSelectedConversationId(conversation.id)}
                aria-current={isSelected ? 'true' : undefined}
              >
                <span className={`conversation-name${unread > 0 ? ' has-unread' : ''}`}>{conversation.name}</span>
                <span className="conversation-id">{shortId(conversation.id)}</span>
              </button>
              {unread > 0 && <span className="unread-badge">{unread}</span>}
              <button
                className="conversation-hide"
                type="button"
                onClick={(e) => { e.stopPropagation(); toggleHideConversation(conversation.id) }}
                aria-label={hiddenConversations.has(conversation.id) ? 'Show conversation' : 'Hide conversation'}
                title={hiddenConversations.has(conversation.id) ? 'Unhide' : 'Hide'}
              >
                {hiddenConversations.has(conversation.id) ? 'Show' : '\u00d7'}
              </button>
            </div>
          </li>
          )
        })}
      </ul>
    </>
  )
}
