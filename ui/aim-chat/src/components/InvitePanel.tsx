import type { IdentityInfo } from '../types'

export interface InvitePanelProps {
  inviteName: string
  setInviteName: (value: string) => void
  inviteToken: string
  setInviteToken: (value: string) => void
  createdInviteToken: string
  identity: IdentityInfo
  isWorking: boolean
  onCreateInvite: () => void
  onAcceptInvite: () => void
}

export function InvitePanel({
  inviteName,
  setInviteName,
  inviteToken,
  setInviteToken,
  createdInviteToken,
  identity,
  isWorking,
  onCreateInvite,
  onAcceptInvite,
}: InvitePanelProps) {
  return (
    <section className="panel">
      <h2>Invites</h2>
      <input
        className="input"
        placeholder="Conversation label"
        value={inviteName}
        onChange={(event) => setInviteName(event.target.value)}
      />

      <div className="row">
        <button className="button full" type="button" onClick={() => void onCreateInvite()} disabled={isWorking || !identity.exists}>
          New Conversation
        </button>
      </div>

      {createdInviteToken && (
        <textarea className="token-box" value={createdInviteToken} readOnly />
      )}

      <input
        className="input"
        placeholder="Paste invite token"
        value={inviteToken}
        onChange={(event) => setInviteToken(event.target.value)}
      />
      <button className="button full" type="button" onClick={() => void onAcceptInvite()} disabled={isWorking || !identity.exists}>
        Join Conversation
      </button>
    </section>
  )
}
