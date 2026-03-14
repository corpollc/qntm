import React from 'react';
import { Box, Text } from 'ink';
import type { StoredMessage } from '../lib/store.js';
import GateCard from './GateCard.js';
import { theme } from '../lib/theme.js';

interface ChatPaneProps {
  messages: StoredMessage[];
  conversationName: string;
  scrollOffset: number;
  terminalHeight: number;
  resolveContact: (kid: string) => string;
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '??:??';
  }
}

function isGateType(bodyType: string): boolean {
  return bodyType.startsWith('gate.');
}

export default function ChatPane({
  messages,
  conversationName,
  scrollOffset,
  terminalHeight,
  resolveContact,
}: ChatPaneProps) {
  // Reserve space for header, status bar, composer, borders
  const visibleLines = Math.max(terminalHeight - 10, 5);

  // Show the most recent messages, adjusted by scroll offset
  const endIdx = Math.max(0, messages.length - scrollOffset);
  const startIdx = Math.max(0, endIdx - visibleLines);
  const visible = messages.slice(startIdx, endIdx);

  return (
    <Box flexDirection="column" flexGrow={1}>
      <Box borderStyle="single" borderColor={theme.borderActive} paddingX={1} flexDirection="column" flexGrow={1}>
        {messages.length > 0 && scrollOffset > 0 && (
          <Box justifyContent="flex-end">
            <Text dimColor>
              {startIdx + 1}-{endIdx}/{messages.length} (scrolled)
            </Text>
          </Box>
        )}

        {visible.length === 0 && (
          <Text dimColor>No messages yet. Type a message below to start the conversation.</Text>
        )}

        {visible.map((msg) => {
          const time = formatTime(msg.createdAt);
          let senderLabel = msg.sender;
          if (msg.direction === 'incoming' && msg.senderKey) {
            const alias = resolveContact(msg.senderKey);
            if (alias) senderLabel = alias;
            else senderLabel = msg.senderKey.slice(0, 12) + '..';
          }

          if (isGateType(msg.bodyType)) {
            return (
              <Box key={msg.id} flexDirection="column">
                <Text dimColor>{time} {senderLabel}</Text>
                <GateCard bodyType={msg.bodyType} text={msg.text} direction={msg.direction} />
              </Box>
            );
          }

          const senderColor = msg.direction === 'outgoing' ? theme.outgoing : theme.incoming;

          return (
            <Box key={msg.id} flexDirection="row" marginTop={0}>
              <Text dimColor>{time} </Text>
              <Text color={senderColor} bold>{senderLabel}</Text>
              <Text>: {msg.text}</Text>
            </Box>
          );
        })}
      </Box>

      {scrollOffset > 0 && (
        <Box justifyContent="center">
          <Text dimColor>Esc to scroll {'\u00b7'} j/k navigate</Text>
        </Box>
      )}
    </Box>
  );
}
