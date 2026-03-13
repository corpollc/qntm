import type { GateRequestBody, GateApprovalBody, GateExecutedBody } from './gate-types'

export function shortId(value: string): string {
  if (!value) {
    return ''
  }

  if (value.length <= 14) {
    return value
  }

  return `${value.slice(0, 8)}...${value.slice(-4)}`
}

export function formatTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function parseGateMessage(text: string): GateRequestBody | GateApprovalBody | GateExecutedBody | null {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}
