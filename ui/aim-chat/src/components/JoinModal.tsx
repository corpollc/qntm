import { useState } from 'react'

export interface JoinModalProps {
  inviteToken: string
  isWorking: boolean
  onJoin: (name: string) => void
  onCancel: () => void
}

export function JoinModal({ inviteToken, isWorking, onJoin, onCancel }: JoinModalProps) {
  const [name, setName] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onJoin(name)
  }

  return (
    <div className="join-modal-backdrop" onClick={onCancel}>
      <form
        className="join-modal-card"
        onClick={(e) => e.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <h2 className="join-modal-title">Do you want to join this chat?</h2>
        <p className="join-modal-description">
          Someone shared an invite link with you. Give this conversation a name and join.
        </p>
        <label className="join-modal-label" htmlFor="join-modal-name">
          Name The Chat
        </label>
        <input
          id="join-modal-name"
          className="input"
          placeholder="e.g. Team Chat, Project Alpha"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
        <button
          className="button join-modal-join-btn"
          type="submit"
          disabled={isWorking}
        >
          {isWorking ? 'Joining\u2026' : 'Join'}
        </button>
      </form>
    </div>
  )
}
