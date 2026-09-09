import type { GateRequestBody, GateApprovalBody, GateExecutedBody } from './gate-types'
import pkg from '../package.json'

export const APP_VERSION = pkg.version

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

export function formatSmartTime(value: string, now?: Date): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }

  const ref = now ?? new Date()
  const today = new Date(ref.getFullYear(), ref.getMonth(), ref.getDate())
  const yesterday = new Date(today.getTime() - 86400000)
  const weekAgo = new Date(today.getTime() - 6 * 86400000)
  const msgDay = new Date(date.getFullYear(), date.getMonth(), date.getDate())

  const hhmm = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  if (msgDay.getTime() === today.getTime()) {
    return hhmm
  }
  if (msgDay.getTime() === yesterday.getTime()) {
    return `Yesterday ${hhmm}`
  }
  if (msgDay >= weekAgo) {
    const dayName = date.toLocaleDateString([], { weekday: 'short' })
    return `${dayName} ${hhmm}`
  }
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

export function formatDateLabel(value: string, now?: Date): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }

  const ref = now ?? new Date()
  const today = new Date(ref.getFullYear(), ref.getMonth(), ref.getDate())
  const yesterday = new Date(today.getTime() - 86400000)
  const msgDay = new Date(date.getFullYear(), date.getMonth(), date.getDate())

  if (msgDay.getTime() === today.getTime()) {
    return 'Today'
  }
  if (msgDay.getTime() === yesterday.getTime()) {
    return 'Yesterday'
  }
  return date.toLocaleDateString([], { month: 'long', day: 'numeric' })
}

const AVATAR_COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316',
]

export function senderColor(name: string): string {
  let hash = 0
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]
}

export function isSameDay(a: string, b: string): boolean {
  const da = new Date(a)
  const db = new Date(b)
  return (
    da.getFullYear() === db.getFullYear() &&
    da.getMonth() === db.getMonth() &&
    da.getDate() === db.getDate()
  )
}

export function isSameGroup(a: { sender: string; createdAt: string }, b: { sender: string; createdAt: string }): boolean {
  if (a.sender !== b.sender) return false
  const diff = Math.abs(new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
  return diff < 5 * 60 * 1000
}

export function parseGateMessage(text: string): GateRequestBody | GateApprovalBody | GateExecutedBody | null {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** Extract a raw token from a pasted invite link or bare token, stripping all whitespace */
export function extractToken(input: string): string {
  const trimmed = input.trim()
  try {
    const url = new URL(trimmed)
    const invite = url.searchParams.get('invite')
    if (invite) return invite.replace(/\s+/g, '')
    if (url.hash) return url.hash.replace(/^#/, '').replace(/\s+/g, '')
  } catch {
    // Not a URL — treat as bare token
  }
  return trimmed.replace(/\s+/g, '')
}
