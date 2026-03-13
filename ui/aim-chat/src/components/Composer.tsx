import { FormEvent } from 'react'
import type { Conversation } from '../types'

export interface ComposerProps {
  selectedConversation: Conversation | null
  composer: string
  setComposer: (value: string) => void
  isWorking: boolean
  onSendMessage: (event: FormEvent<HTMLFormElement>) => void
  onCheckMessages: () => void
}

export function Composer({
  selectedConversation,
  composer,
  setComposer,
  isWorking,
  onSendMessage,
  onCheckMessages,
}: ComposerProps) {
  return (
    <form className="composer" onSubmit={onSendMessage}>
      <input
        className="input grow"
        placeholder={selectedConversation ? 'Type a message' : 'Select a conversation first'}
        value={composer}
        onChange={(event) => setComposer(event.target.value)}
        disabled={!selectedConversation || isWorking}
      />
      <button className="button" type="submit" disabled={!selectedConversation || isWorking}>
        Send
      </button>
      <button
        className="button"
        type="button"
        disabled={!selectedConversation || isWorking}
        onClick={onCheckMessages}
      >
        Check for messages
      </button>
    </form>
  )
}
