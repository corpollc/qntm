import { FormEvent } from 'react'
import type { IdentityInfo, Profile } from '../types'
import { shortId } from '../utils'

export interface IdentityPanelProps {
  profiles: Profile[]
  activeProfileId: string
  identity: IdentityInfo
  newProfileName: string
  setNewProfileName: (value: string) => void
  isWorking: boolean
  onSelectProfile: (profileId: string) => void
  onCreateProfile: (event: FormEvent<HTMLFormElement>) => void
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
  onGenerateIdentity,
  setStatus,
}: IdentityPanelProps) {
  return (
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

      <button className="button full" type="button" onClick={() => void onGenerateIdentity()} disabled={isWorking || !activeProfileId}>
        Generate keypair
      </button>

      <div className="meta">
        <div>
          <strong>Status:</strong> {identity.exists ? 'Ready' : 'No keypair yet'}
        </div>
        <div>
          <strong>Key ID:</strong> {identity.keyId ? shortId(identity.keyId) : '-'}
        </div>
        {identity.publicKey && (
          <div className="pubkey-row">
            <strong>Public key:</strong>
            <code className="pubkey-value">{shortId(identity.publicKey)}</code>
            <button
              className="button-small"
              type="button"
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
