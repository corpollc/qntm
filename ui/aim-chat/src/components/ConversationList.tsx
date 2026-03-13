import type { RefObject } from 'react'
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
  filterInputRef?: RefObject<HTMLInputElement | null>
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
        value={conversationFilter}
        onChange={(e) => setConversationFilter(e.target.value)}
      />
      <ul className="conversation-list">
        {visibleConversations.length === 0 && <li className="empty">No conversations yet</li>}
        {visibleConversations.map((conversation) => {
          const unread = unreadCounts[conversation.id] || 0
          return (
          <li key={conversation.id}>
            <div className={`conversation ${conversation.id === selectedConversationId ? 'selected' : ''}`}>
              <button
                className="conversation-select"
                type="button"
                onClick={() => setSelectedConversationId(conversation.id)}
              >
                <span className={`conversation-name${unread > 0 ? ' has-unread' : ''}`}>{conversation.name}</span>
                <span className="conversation-id">{shortId(conversation.id)}</span>
              </button>
              {unread > 0 && <span className="unread-badge">{unread}</span>}
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
          )
        })}
      </ul>
    </>
  )
}
