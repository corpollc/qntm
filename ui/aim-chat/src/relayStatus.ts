export type RelayConnectionState = 'connecting' | 'live' | 'reconnecting'

export function relayConversationIds(
  conversationIds: string[],
  hiddenConversationIds: Set<string>,
): string[] {
  return conversationIds.filter((conversationId) => !hiddenConversationIds.has(conversationId))
}

export function reconcileRelayStates(
  previous: Record<string, RelayConnectionState>,
  conversationIds: string[],
): Record<string, RelayConnectionState> {
  const next: Record<string, RelayConnectionState> = {}

  for (const conversationId of conversationIds) {
    next[conversationId] = previous[conversationId] ?? 'connecting'
  }

  return next
}

export function selectedConversationRelayStatus(
  relayStates: Record<string, RelayConnectionState>,
  selectedConversationId: string,
): string {
  const relayState = relayStates[selectedConversationId]

  if (relayState === 'connecting') {
    return 'Connecting to relay...'
  }

  if (relayState === 'reconnecting') {
    return 'Reconnecting to relay...'
  }

  return ''
}
