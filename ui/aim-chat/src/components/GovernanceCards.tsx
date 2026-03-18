import type { ChatMessage } from '../types'
import { shortId } from '../utils'
import { formatGovEvent } from './SystemEvents'

export function GovProposalCard({
  message,
  onApprove,
  onDisapprove,
  isWorking,
  alreadyApproved,
  alreadyDisapproved,
  approvalCount,
  disapprovalCount,
  requiredApprovals,
  isApplied,
}: {
  message: ChatMessage
  onApprove?: (proposalId: string, conversationId: string) => void
  onDisapprove?: (proposalId: string, conversationId: string) => void
  isWorking: boolean
  alreadyApproved?: boolean
  alreadyDisapproved?: boolean
  approvalCount?: number
  disapprovalCount?: number
  requiredApprovals?: number
  isApplied?: boolean
}) {
  let parsed: {
    proposal_id?: string
    expires_at?: string
  } | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed?.proposal_id) return <div className="message-body">{message.text}</div>

  const display = formatGovEvent(message.bodyType, message.text, message.sender)
  const isExpired = parsed.expires_at ? new Date(parsed.expires_at) < new Date() : false
  const thresholdMet = approvalCount != null && requiredApprovals != null && approvalCount >= requiredApprovals

  return (
    <div className="gate-card gate-config">
      <div className="gate-card-header">
        Governance Proposal
        {approvalCount != null && requiredApprovals != null && (
          <span style={{ fontWeight: 400, marginLeft: 8 }}>
            ({approvalCount} of {requiredApprovals} approvals{thresholdMet ? ' - threshold met' : ''})
          </span>
        )}
      </div>
      <div className="gate-card-body">
        <div><strong>Proposal:</strong> {shortId(parsed.proposal_id)}</div>
        {display && <div><strong>Change:</strong> {display.headline}</div>}
        {display?.detail && <div><strong>Detail:</strong> {display.detail}</div>}
        {disapprovalCount != null && disapprovalCount > 0 && (
          <div style={{ color: 'var(--danger, #e74c3c)', fontWeight: 600 }}>
            {disapprovalCount} rejection{disapprovalCount !== 1 ? 's' : ''}
          </div>
        )}
        {isApplied && (
          <div style={{ color: 'var(--success, #2e8b57)', fontWeight: 600 }}>
            Applied
          </div>
        )}
      </div>
      {!isExpired && !isApplied && !thresholdMet && !alreadyApproved && onApprove && (
        <button
          className="gate-approve-btn"
          type="button"
          disabled={isWorking}
          onClick={() => onApprove(parsed.proposal_id!, message.conversationId)}
        >
          Approve
        </button>
      )}
      {!isExpired && !isApplied && !alreadyDisapproved && onDisapprove && (
        <button
          className="gate-deny-btn"
          type="button"
          disabled={isWorking}
          onClick={() => onDisapprove(parsed.proposal_id!, message.conversationId)}
        >
          Reject
        </button>
      )}
      {!isExpired && !isApplied && alreadyApproved && (
        <div style={{ marginTop: 8, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
          You have already approved this proposal.
        </div>
      )}
      {!isExpired && !isApplied && alreadyDisapproved && (
        <div style={{ marginTop: 8, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
          You have already rejected this proposal.
        </div>
      )}
      {isExpired && <div className="gate-expired">Expired</div>}
    </div>
  )
}
