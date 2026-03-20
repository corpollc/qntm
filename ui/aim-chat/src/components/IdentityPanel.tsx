import { FormEvent, useState } from 'react'
import type { IdentityInfo, Profile } from '../types'
import { shortId } from '../utils'
import { Tooltip } from './Tooltip'
import { ConfirmDialog } from './ConfirmDialog'

export interface IdentityPanelProps {
  profiles: Profile[]
  activeProfileId: string
  identity: IdentityInfo
  newProfileName: string
  setNewProfileName: (value: string) => void
  isWorking: boolean
  onSelectProfile: (profileId: string) => void
  onCreateProfile: (event: FormEvent<HTMLFormElement>) => void
  onRenameProfile: (profileId: string, newName: string) => void
  onGenerateIdentity: () => void
  setStatus: (value: string) => void
}

export function IdentityPanel({
  profiles,
  activeProfileId,
  identity,
  newProfileName,
  setNewProfileName,
  isWorking,
  onSelectProfile,
  onCreateProfile,
  onRenameProfile,
  onGenerateIdentity,
  setStatus,
}: IdentityPanelProps) {
  const [showConfirm, setShowConfirm] = useState(false)
  const activeProfile = profiles.find((p) => p.id === activeProfileId)
  const [editingName, setEditingName] = useState(false)
  const [nameDraft, setNameDraft] = useState('')

  function handleGenerateClick() {
    if (identity.exists) {
      setShowConfirm(true)
    } else {
      void onGenerateIdentity()
    }
  }

  return (
    <>
      <ConfirmDialog
        open={showConfirm}
        title="Replace keypair?"
        message="This will generate a new keypair and replace your current one. Your existing Key ID will no longer be valid. This cannot be undone."
        confirmLabel="Replace keypair"
        danger
        onConfirm={() => {
          setShowConfirm(false)
          void onGenerateIdentity()
        }}
        onCancel={() => setShowConfirm(false)}
      />
      {profiles.length > 1 && (
        <>
          <label className="label" htmlFor="profile-select">
            Active profile
          </label>
          <select
            id="profile-select"
            className="input"
            value={activeProfileId}
            onChange={(event) => void onSelectProfile(event.target.value)}
          >
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </select>
        </>
      )}

      <label className="label">Display name</label>
      {editingName ? (
        <form className="row" onSubmit={(e) => {
          e.preventDefault()
          if (nameDraft.trim() && activeProfileId) {
            onRenameProfile(activeProfileId, nameDraft.trim())
          }
          setEditingName(false)
        }}>
          <input
            className="input"
            value={nameDraft}
            onChange={(e) => setNameDraft(e.target.value)}
            autoFocus
            onBlur={() => setEditingName(false)}
            onKeyDown={(e) => { if (e.key === 'Escape') setEditingName(false) }}
          />
          <button className="button" type="submit">Save</button>
        </form>
      ) : (
        <div className="row">
          <span className="profile-name-display">{activeProfile?.name || '-'}</span>
          <button
            className="button-small"
            type="button"
            onClick={() => {
              setNameDraft(activeProfile?.name || '')
              setEditingName(true)
            }}
          >
            Edit
          </button>
        </div>
      )}

      <form className="row" onSubmit={onCreateProfile}>
        <input
          className="input"
          placeholder="New profile name"
          value={newProfileName}
          onChange={(event) => setNewProfileName(event.target.value)}
        />
        <button className="button" type="submit" disabled={isWorking}>
          Add
        </button>
      </form>

      <button className="button full" type="button" onClick={handleGenerateClick} disabled={isWorking || !activeProfileId}>
        Generate keypair
        <Tooltip text="Creates a new cryptographic key pair for signing and encrypting messages." />
      </button>

      <div className="meta">
        <div>
          <strong>Status:</strong> {identity.exists ? 'Ready' : 'No keypair yet'}
        </div>
        <div>
          <strong>Key ID:</strong>
          <Tooltip text="Your unique identifier on the network. Share your public key to let others verify your messages." />
          {' '}{identity.keyId ? shortId(identity.keyId) : '-'}
        </div>
        {identity.publicKey && (
          <div className="pubkey-row">
            <strong>Public key:</strong>
            <Tooltip text="Your public key can be safely shared. Others use it to encrypt messages only you can read." />
            <code className="pubkey-value">{shortId(identity.publicKey)}</code>
            <button
              className="button-small"
              type="button"
              aria-label="Copy to clipboard"
              onClick={() => {
                navigator.clipboard.writeText(identity.publicKey)
                setStatus('Public key copied to clipboard')
              }}
            >
              Copy
            </button>
          </div>
        )}
      </div>
    </>
  )
}
