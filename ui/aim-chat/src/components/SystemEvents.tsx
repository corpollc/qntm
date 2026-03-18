import type { ChatMessage } from '../types'
import { shortId } from '../utils'

export interface GroupEventDisplay {
  icon: 'group' | 'add' | 'remove' | 'rekey'
  headline: string
  detail: string
}

/**
 * Parse a group event body and return a structured display object.
 * The body is expected to be JSON (converted from CBOR at the receive layer).
 * Returns null for non-group body types or unparseable bodies.
 */
export function formatGroupEvent(
  bodyType: string,
  body: string,
  senderName?: string,
): GroupEventDisplay | null {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(body)
  } catch {
    return null
  }

  switch (bodyType) {
    case 'group_genesis': {
      const name = (parsed.group_name as string) || 'Group'
      const members = (parsed.founding_members as unknown[]) || []
      const count = members.length
      return {
        icon: 'group',
        headline: `${name} created`,
        detail: `${count} member${count !== 1 ? 's' : ''}`,
      }
    }

    case 'group_add': {
      const newMembers = (parsed.new_members as unknown[]) || []
      const count = newMembers.length
      const who = senderName || 'Someone'
      return {
        icon: 'add',
        headline: `${who} added ${count} member${count !== 1 ? 's' : ''}`,
        detail: '',
      }
    }

    case 'group_remove': {
      const removed = (parsed.removed_members as unknown[]) || []
      const count = removed.length
      const who = senderName || 'Someone'
      const reason = (parsed.reason as string) || ''
      return {
        icon: 'remove',
        headline: `${who} removed ${count} member${count !== 1 ? 's' : ''}`,
        detail: reason,
      }
    }

    case 'group_rekey': {
      const epoch = parsed.new_conv_epoch as number
      return {
        icon: 'rekey',
        headline: 'Security keys rotated',
        detail: `epoch ${epoch}`,
      }
    }

    default:
      return null
  }
}

const ICONS: Record<string, string> = {
  group: '\u{1F465}',   // 👥
  add: '\u{2795}',      // ➕
  remove: '\u{2796}',   // ➖
  rekey: '\u{1F510}',   // 🔐
}

export function SystemEventCard({ message }: { message: ChatMessage }) {
  const display = formatGroupEvent(message.bodyType, message.text, message.sender)
    ?? formatGovEvent(message.bodyType, message.text, message.sender)
  if (!display) {
    return <div className="message-body">{message.text}</div>
  }

  return (
    <div className="system-event">
      <span className="system-event-icon">{ICONS[display.icon] || ''}</span>
      <div className="system-event-content">
        <span className="system-event-headline">{display.headline}</span>
        {display.detail && (
          <span className="system-event-detail">{display.detail}</span>
        )}
      </div>
    </div>
  )
}

/**
 * Format governance events (gov.propose, gov.approve, gov.disapprove, gov.applied)
 */
export function formatGovEvent(
  bodyType: string,
  body: string,
  senderName?: string,
): GroupEventDisplay | null {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(body)
  } catch {
    return null
  }

  const who = senderName || 'Someone'

  switch (bodyType) {
    case 'gov.propose': {
      const proposalType = (parsed.proposal_type as string) || 'change'
      let label: string
      if (proposalType === 'floor_change') {
        label = `floor to ${parsed.proposed_floor ?? '?'}`
      } else if (proposalType === 'member_add') {
        const count = (parsed.proposed_members as unknown[] || []).length
        label = `adding ${count} member${count !== 1 ? 's' : ''}`
      } else if (proposalType === 'member_remove') {
        const count = (parsed.removed_member_kids as unknown[] || []).length
        label = `removing ${count} member${count !== 1 ? 's' : ''}`
      } else {
        label = 'policy rules'
      }
      return {
        icon: 'group',
        headline: `${who} proposed ${label}`,
        detail: `Requires ${parsed.required_approvals ?? '?'} approval${(parsed.required_approvals as number) !== 1 ? 's' : ''}`,
      }
    }
    case 'gov.approve':
      return {
        icon: 'add',
        headline: `${who} approved governance proposal`,
        detail: shortId((parsed.proposal_id as string) || ''),
      }
    case 'gov.disapprove':
      return {
        icon: 'remove',
        headline: `${who} rejected governance proposal`,
        detail: shortId((parsed.proposal_id as string) || ''),
      }
    case 'gov.applied': {
      const proposalType = (parsed.proposal_type as string) || 'change'
      let label: string
      if (proposalType === 'floor_change') {
        label = `Floor changed to ${parsed.applied_floor ?? '?'}`
      } else if (proposalType === 'member_add') {
        const count = (parsed.applied_members as unknown[] || []).length
        label = `${count} member${count !== 1 ? 's' : ''} added`
      } else if (proposalType === 'member_remove') {
        const count = (parsed.removed_member_kids as unknown[] || []).length
        label = `${count} member${count !== 1 ? 's' : ''} removed`
      } else {
        label = 'Policy rules updated'
      }
      return {
        icon: 'rekey',
        headline: label,
        detail: 'Governance proposal applied',
      }
    }
    default:
      return null
  }
}
