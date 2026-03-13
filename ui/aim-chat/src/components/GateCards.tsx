import type { ChatMessage } from '../types'
import type {
  GateRequestBody,
  GateApprovalBody,
  GateExecutedBody,
  GateExpiredBody,
  GatePromoteBody,
  GateResultBody,
} from '../gate-types'
import { shortId, parseGateMessage } from '../utils'

export function GateRequestCard({
  message,
  onApprove,
  isWorking,
}: {
  message: ChatMessage
  onApprove: (requestId: string, conversationId: string) => void
  isWorking: boolean
}) {
  const parsed = parseGateMessage(message.text) as GateRequestBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  const isExpired = new Date(parsed.expires_at) < new Date()
  const hasArgs = parsed.arguments && Object.keys(parsed.arguments).length > 0
  const hasBody = parsed.request_body !== undefined && parsed.request_body !== null

  return (
    <div className="gate-card gate-request">
      <div className="gate-card-header">
        API Request{parsed.recipe_name ? `: ${parsed.recipe_name}` : ''}
      </div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div className="gate-verb-line">
          <span className={`gate-verb gate-verb-${parsed.verb.toLowerCase()}`}>{parsed.verb}</span>
          <code className="gate-url-resolved">{parsed.target_url}</code>
        </div>
        <div><strong>Endpoint:</strong> {parsed.target_endpoint}</div>
        <div><strong>Service:</strong> {parsed.target_service}</div>
        <div><strong>Org:</strong> {parsed.org_id}</div>
        <div><strong>Requester:</strong> {shortId(parsed.signer_kid)}</div>
        <div><strong>Expires:</strong> {new Date(parsed.expires_at).toLocaleTimeString()}</div>
        {hasArgs && (
          <div className="gate-args-display">
            <strong>Arguments:</strong>
            {Object.entries(parsed.arguments!).filter(([k]) => k !== '_body').map(([key, value]) => (
              <div key={key} className="gate-arg-item">
                <code>{key}</code>: {value}
              </div>
            ))}
          </div>
        )}
        {hasBody && (
          <div className="gate-body-preview">
            <strong>Request body:</strong>
            <pre className="gate-body-content">
              {typeof parsed.request_body === 'string'
                ? parsed.request_body
                : JSON.stringify(parsed.request_body, null, 2)}
            </pre>
          </div>
        )}
      </div>
      {!isExpired && (
        <button
          className="gate-approve-btn"
          type="button"
          disabled={isWorking}
          onClick={() => onApprove(parsed.request_id, message.conversationId)}
        >
          Approve
        </button>
      )}
      {isExpired && <div className="gate-expired">Expired</div>}
    </div>
  )
}

export function GateApprovalCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateApprovalBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-approval">
      <div className="gate-card-header">Approval</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div><strong>Approved by:</strong> {shortId(parsed.signer_kid)}</div>
      </div>
    </div>
  )
}

export function GateExecutedCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateExecutedBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-executed">
      <div className="gate-card-header">Request Executed</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div><strong>HTTP Status:</strong> {parsed.execution_status_code || 'N/A'}</div>
      </div>
    </div>
  )
}

export function GateExpiredCard({ message }: { message: ChatMessage }) {
  let parsed: GateExpiredBody | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  const expiredDate = new Date(parsed.expired_at)
  const timeAgo = Math.round((Date.now() - expiredDate.getTime()) / 60000)

  return (
    <div className="gate-card gate-expired" style={{
      borderColor: '#e67e22',
      backgroundColor: 'rgba(230, 126, 34, 0.08)',
      borderLeft: '4px solid #e67e22',
    }}>
      <div className="gate-card-header" style={{ color: '#e67e22' }}>
        Credential Expired
      </div>
      <div className="gate-card-body">
        <div><strong>Service:</strong> {parsed.service}</div>
        <div><strong>Secret:</strong> {shortId(parsed.secret_id)}</div>
        <div><strong>Expired:</strong> {timeAgo > 0 ? `${timeAgo}m ago` : 'just now'} ({expiredDate.toLocaleString()})</div>
        <div style={{ marginTop: '8px', color: '#e67e22', fontWeight: 500 }}>
          {parsed.message}
        </div>
      </div>
    </div>
  )
}

export function GatePromoteCard({ message }: { message: ChatMessage }) {
  let parsed: GatePromoteBody | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  const threshold = parsed.rules?.[0]?.m ?? '?'
  const n = parsed.signers?.length ?? '?'

  return (
    <div className="gate-card gate-promote">
      <div className="gate-card-header">API Gateway Enabled</div>
      <div className="gate-card-body">
        <div><strong>Org:</strong> {parsed.org_id}</div>
        <div><strong>Threshold:</strong> {threshold}-of-{n}</div>
        <div><strong>Signers:</strong> {parsed.signers?.length ?? 0}</div>
        {parsed.signers?.map((s) => (
          <div key={s.kid} className="gate-signer-item">
            <code>{shortId(s.kid)}</code>
          </div>
        ))}
        <div><strong>Rules:</strong> {parsed.rules?.length ?? 0}</div>
      </div>
    </div>
  )
}

export function GateConfigCard({ message }: { message: ChatMessage }) {
  let parsed: { rules?: Array<{ service: string; endpoint: string; verb: string; m: number; n: number }> } | null = null
  try {
    parsed = JSON.parse(message.text)
  } catch {
    return <div className="message-body">{message.text}</div>
  }
  if (!parsed) return <div className="message-body">{message.text}</div>

  return (
    <div className="gate-card gate-config">
      <div className="gate-card-header">Gateway Configuration</div>
      <div className="gate-card-body">
        <div><strong>Rules:</strong> {parsed.rules?.length ?? 0}</div>
        {parsed.rules?.map((r, i) => (
          <div key={i}>
            <code>{r.verb} {r.endpoint}</code> on <code>{r.service}</code>: M={r.m}
          </div>
        ))}
      </div>
    </div>
  )
}

export function GateResultCard({ message }: { message: ChatMessage }) {
  const parsed = parseGateMessage(message.text) as GateResultBody | null
  if (!parsed) return <div className="message-body">{message.text}</div>

  const isSuccess = parsed.status_code >= 200 && parsed.status_code < 300
  const isJson = parsed.content_type?.includes('json')
  const MAX_BODY_LENGTH = 2000

  let displayBody = parsed.body || ''
  if (isJson && displayBody) {
    try {
      displayBody = JSON.stringify(JSON.parse(displayBody), null, 2)
    } catch {
      // keep raw
    }
  }
  const truncated = displayBody.length > MAX_BODY_LENGTH
  if (truncated) {
    displayBody = displayBody.slice(0, MAX_BODY_LENGTH)
  }

  return (
    <div className={`gate-card gate-result ${isSuccess ? 'gate-result-ok' : 'gate-result-err'}`}>
      <div className="gate-card-header">API Response</div>
      <div className="gate-card-body">
        <div><strong>Request:</strong> {shortId(parsed.request_id)}</div>
        <div>
          <strong>Status:</strong>{' '}
          <span className={isSuccess ? 'gate-status-ok' : 'gate-status-err'}>
            {parsed.status_code}
          </span>
        </div>
        {parsed.content_type && (
          <div><strong>Content-Type:</strong> {parsed.content_type}</div>
        )}
        {displayBody && (
          <div className="gate-result-body-section">
            <strong>Response:</strong>
            <pre className="gate-result-body">{displayBody}{truncated ? '\n... (truncated)' : ''}</pre>
          </div>
        )}
      </div>
    </div>
  )
}
