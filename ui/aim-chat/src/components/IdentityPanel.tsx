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
  onDeleteProfile: (profileId: string) => void
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
  onDeleteProfile,
  setStatus,
}: IdentityPanelProps) {
  const activeProfile = profiles.find((p) => p.id === activeProfileId)
  const [editingName, setEditingName] = useState(false)
  const [nameDraft, setNameDraft] = useState('')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  return (
    <>
      <ConfirmDialog
        open={showDeleteConfirm}
        title="Delete profile?"
        message={`This will permanently delete "${activeProfile?.name || ''}" and all its conversations, keys, and message history. This cannot be undone.`}
        confirmLabel="Delete profile"
        danger
        onConfirm={() => {
          setShowDeleteConfirm(false)
          void onDeleteProfile(activeProfileId)
        }}
        onCancel={() => setShowDeleteConfirm(false)}
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
            onBlur={() => {
              // Delay so a Save button click can fire submit before unmount
              setTimeout(() => setEditingName(false), 150)
            }}
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
          {profiles.length > 1 && (
            <button
              className="button-small danger"
              type="button"
              onClick={() => setShowDeleteConfirm(true)}
            >
              Delete
            </button>
          )}
        </div>
      )}

      <div className="meta">
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
    </>
  )
}
