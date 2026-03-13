import React from 'react';
import { Box, Text } from 'ink';
import type { StoredConversation, StoredMessage } from '../lib/store.js';

interface SidebarProps {
  conversations: StoredConversation[];
  activeId: string | null;
  unread: Record<string, number>;
  lastMessages: Record<string, StoredMessage>;
  onSelect: (id: string) => void;
  visible: boolean;
}

/** Max characters for conversation name before truncation */
const MAX_NAME_LEN = 16;
/** Max characters for message preview */
const MAX_PREVIEW_LEN = 28;

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '\u2026' : s;
}

function relativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 0) return 'now';
    const secs = Math.floor(diff / 1000);
    if (secs < 60) return 'now';
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h`;
    const days = Math.floor(hrs / 24);
    if (days < 30) return `${days}d`;
    const months = Math.floor(days / 30);
    return `${months}mo`;
  } catch {
    return '';
  }
}

function typeIcon(type: string): string {
  if (type === 'group') return 'G ';
  if (type === 'announce') return 'A ';
  return '';
}

export default function Sidebar({
  conversations,
  activeId,
  unread,
  lastMessages,
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
        const hasUnread = unreadCount > 0;
        const rawLabel = conv.name || conv.id.slice(0, 12);
        const label = truncate(rawLabel, MAX_NAME_LEN);
        const num = idx + 1;
        const icon = typeIcon(conv.type);
        const lastMsg = lastMessages[conv.id];
        const timeStr = lastMsg ? relativeTime(lastMsg.createdAt) : '';

        return (
          <Box key={conv.id} flexDirection="column">
            <Box flexDirection="row">
              <Text dimColor>{num}. </Text>
              <Text dimColor>{icon}</Text>
              {isActive ? (
                <Text bold color="cyan">{'\u25b6'} {label}</Text>
              ) : hasUnread ? (
                <Text bold>  {label}</Text>
              ) : (
                <Text>  {label}</Text>
              )}
              {hasUnread && (
                <Text color="red" bold> ({unreadCount})</Text>
              )}
              {timeStr && (
                <Text dimColor> {timeStr}</Text>
              )}
            </Box>
            {lastMsg && (
              <Box marginLeft={3}>
                <Text dimColor>{truncate(lastMsg.text, MAX_PREVIEW_LEN)}</Text>
              </Box>
            )}
          </Box>
        );
      })}
      <Box marginTop={1}>
        <Text dimColor>Tab: toggle sidebar | 1-9: switch conv</Text>
      </Box>
    </Box>
  );
}
