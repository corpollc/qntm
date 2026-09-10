import { useState } from 'react'
import { parseGroupLink } from '@corpollc/qntm'
import { hex } from '../contact-groups'

export interface JoinModalProps {
  inviteToken: string
  isWorking: boolean
  onJoin: (name: string) => void
  onCancel: () => void
}

export function JoinModal({ inviteToken, isWorking, onJoin, onCancel }: JoinModalProps) {
  const [name, setName] = useState('')
  const [verified, setVerified] = useState(false)
  let locator
  try { locator = parseGroupLink(inviteToken) } catch { /* legacy invite */ }

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
        <h2 className="join-modal-title">{locator ? 'Open your contact group?' : 'Do you want to join this chat?'}</h2>
        <p className="join-modal-description">
          {locator ? 'Use your existing identity to receive the welcome sent by this contact. Check their full public key and relay before opening.' : 'Someone shared an invite link with you. Give this conversation a name and join.'}
        </p>
        {locator && <div className="contact-groups"><label>Contact public key<code className="contact-full-key">{hex(locator.inviterPublicKey)}</code></label><label>Relay<code className="contact-full-key">{locator.relayUrl}</code></label><label className="contact-verification"><input type="checkbox" checked={verified} onChange={e => setVerified(e.target.checked)} /> I verified this contact and relay</label></div>}
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
          disabled={isWorking || (!!locator && !verified)}
        >
          {isWorking ? 'Opening\u2026' : locator ? 'Open group' : 'Join'}
        </button>
      </form>
    </div>
  )
}
