import React from 'react';
import { Box, Text } from 'ink';
import type { StoredConversation } from '../lib/store.js';

interface SidebarProps {
  conversations: StoredConversation[];
  activeId: string | null;
  unread: Record<string, number>;
  onSelect: (id: string) => void;
  visible: boolean;
}

export default function Sidebar({
  conversations,
  activeId,
  unread,
  visible,
}: SidebarProps) {
  if (!visible) return null;

  return (
    <Box
      flexDirection="column"
      borderStyle="single"
      borderColor="gray"
      paddingX={1}
      width="100%"
    >
      <Text bold underline>Conversations</Text>
      {conversations.length === 0 && (
        <Text dimColor>No conversations yet. Use /invite to create one.</Text>
      )}
      {conversations.map((conv, idx) => {
        const isActive = conv.id === activeId;
        const unreadCount = unread[conv.id] || 0;
        const label = conv.name || conv.id.slice(0, 12);
        const num = idx + 1;

        return (
          <Box key={conv.id} flexDirection="row">
            <Text dimColor>{num}. </Text>
            {isActive ? (
              <Text bold color="cyan">{'\u25b6'} {label}</Text>
            ) : (
              <Text>  {label}</Text>
            )}
            {unreadCount > 0 && (
              <Text color="red"> ({unreadCount})</Text>
            )}
            <Text dimColor> [{conv.type}]</Text>
          </Box>
        );
      })}
      <Box marginTop={1}>
        <Text dimColor>Tab: toggle sidebar | 1-9: switch conv</Text>
      </Box>
    </Box>
  );
}
