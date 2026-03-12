import React from 'react';
import { Box, Text } from 'ink';

interface StatusBarProps {
  kid: string;
  name: string;
  activeConversation: string | null;
  activeConversationName: string;
  connected: boolean;
  mode: string;
}

export default function StatusBar({
  kid,
  name,
  activeConversation,
  activeConversationName,
  connected,
  mode,
}: StatusBarProps) {
  const kidShort = kid ? kid.slice(0, 12) + '..' : 'none';
  const connSymbol = connected ? '\u25cf' : '\u25cb';
  const connColor = connected ? 'green' : 'red';

  return (
    <Box
      borderStyle="single"
      borderColor="gray"
      paddingX={1}
      flexDirection="row"
      justifyContent="space-between"
    >
      <Text>
        <Text color={connColor}>{connSymbol}</Text>
        {' '}
        <Text bold>{name || 'unnamed'}</Text>
        {' '}
        <Text dimColor>[{kidShort}]</Text>
      </Text>
      <Text>
        {activeConversation ? (
          <Text color="cyan">{activeConversationName || activeConversation.slice(0, 12)}</Text>
        ) : (
          <Text dimColor>no conversation</Text>
        )}
      </Text>
      <Text dimColor>{mode}</Text>
    </Box>
  );
}
