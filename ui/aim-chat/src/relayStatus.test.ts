import { describe, expect, it } from 'vitest'
import {
  reconcileRelayStates,
  relayConversationIds,
  selectedConversationRelayStatus,
} from './relayStatus'

describe('relay status helpers', () => {
  it('excludes hidden conversations from relay subscriptions', () => {
    expect(relayConversationIds(
      ['alpha', 'beta', 'gamma'],
      new Set(['beta']),
    )).toEqual(['alpha', 'gamma'])
  })

  it('prunes stale relay states and keeps existing live state', () => {
    expect(reconcileRelayStates(
      {
        alpha: 'live',
        beta: 'reconnecting',
      },
      ['alpha', 'gamma'],
    )).toEqual({
      alpha: 'live',
      gamma: 'connecting',
    })
  })

  it('only surfaces degraded relay state for the selected conversation', () => {
    expect(selectedConversationRelayStatus(
      {
        alpha: 'live',
        beta: 'reconnecting',
      },
      'alpha',
    )).toBe('')

    expect(selectedConversationRelayStatus(
      {
        alpha: 'live',
        beta: 'reconnecting',
      },
      'beta',
    )).toBe('Reconnecting to relay...')
  })
})
