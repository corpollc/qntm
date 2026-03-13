import React from 'react';
import { Box, Text } from 'ink';

interface StatusBarProps {
  kid: string;
  name: string;
  connected: boolean;
  conversationCount: number;
  scrollMode: boolean;
  scrollOffset: number;
}

export default function StatusBar({
  kid,
  name,
  connected,
  conversationCount,
  scrollMode,
  scrollOffset,
}: StatusBarProps) {
  const kidShort = kid ? kid.slice(0, 12) + '..' : 'none';
  const connSymbol = connected ? '\u25cf' : '\u25cb';
  const connColor = connected ? 'green' : 'red';

  let rightText: string;
  if (scrollMode) {
    rightText = scrollOffset > 0 ? `\u2195 scrolled +${scrollOffset}` : '\u2195 scroll mode';
  } else if (conversationCount > 0) {
    rightText = `${conversationCount} conversation${conversationCount === 1 ? '' : 's'}`;
  } else {
    rightText = '/invite to start';
  }

  return (
    <Box paddingX={1} flexDirection="row" justifyContent="space-between">
      <Text>
        <Text color={connColor}>{connSymbol}</Text>
        {' '}
        <Text bold>{name || 'unnamed'}</Text>
        {' '}
        <Text dimColor>[{kidShort}]</Text>
      </Text>
      <Text dimColor>{rightText}</Text>
    </Box>
  );
}
