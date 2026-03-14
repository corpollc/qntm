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
  arguments?: Record<string, string>
  request_body?: unknown
}

export interface GateApprovalBody {
  type: string
  request_id: string
  signer_kid: string
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
  conv_id: string
  signers: Array<{ kid: string; public_key: string }>
  rules: Array<{ service: string; endpoint: string; verb: string; m: number; n: number }>
}
