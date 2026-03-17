export interface GateRequestBody {
  type: string
  recipe_name?: string
  conv_id: string
  request_id: string
  verb: string
  target_endpoint: string
  target_service: string
  target_url: string
  expires_at: string
  signer_kid: string
  signature: string
  arguments?: Record<string, string>
  payload?: unknown
  /** Frozen signer roster: kid strings of eligible signers at request-creation time */
  eligible_signer_kids: string[]
  /** Frozen threshold: minimum approvals required (must be >= promotion floor) */
  required_approvals: number
}

export interface GateApprovalBody {
  type: string
  request_id: string
  signer_kid: string
  signature: string
}

export interface GateExecutedBody {
  type: string
  request_id: string
  execution_status_code: number
}

export interface GateResultBody {
  type: string
  request_id: string
  status_code: number
  content_type?: string
  body?: string
}

export interface GateExpiredBody {
  type: string
  secret_id: string
  service: string
  expired_at: string
  message: string
}

export interface GatePromoteBody {
  type: string
  conv_id: string
  gateway_kid: string
  /** Conversation participants: kid → base64url public key (gateway excluded) */
  participants: Record<string, string>
  rules: Array<{ service: string; endpoint: string; verb: string; m: number }>
  /** Minimum approval threshold floor */
  floor: number
}
