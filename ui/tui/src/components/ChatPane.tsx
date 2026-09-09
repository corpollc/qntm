import React from 'react';
import { Box, Text, useStdout } from 'ink';
import wrapAnsi from 'wrap-ansi';
import type { StoredMessage } from '../lib/store.js';
import { gatewaySummary } from './GateCard.js';
import { theme } from '../lib/theme.js';
import { terminalText } from '../lib/gateway.js';

interface ChatPaneProps {
  messages: StoredMessage[];
  conversationName: string;
  scrollOffset: number;
  terminalHeight: number;
  sidebarVisible?: boolean;
  resolveContact: (kid: string) => string;
}
const groupTypes = new Set(['group_genesis', 'group_add', 'group_remove', 'group_rekey']);
function groupSummary(type: string, text: string): string {
  try {
    const body = JSON.parse(text);
    if (type === 'group_rekey') return `Security keys rotated to epoch ${body.new_conv_epoch}`;
    if (type === 'group_remove') return `${body.removed_members.length} member(s) removed`;
    if (type === 'group_add') return `${body.new_members.length} member(s) added`;
    return `Group ${body.group_name || ''} created`;
  } catch { return text; }
}

export default function ChatPane({ messages, scrollOffset, terminalHeight, sidebarVisible, resolveContact }: ChatPaneProps) {
  const { stdout } = useStdout();
  const width = Math.max(10, (stdout?.columns ?? 80) - (sidebarVisible ? 30 : 0) - 4);
  const height = Math.max(3, terminalHeight - 9);
  const lines: { text: string; color: string }[] = [];
  for (const message of messages) {
    const isGateway = message.bodyType.startsWith('gate.') || message.bodyType.startsWith('gov.');
    const name = message.direction === 'incoming' && message.senderKey
      ? resolveContact(message.senderKey) || `${message.senderKey.slice(0, 12)}..` : message.sender;
    const body = groupTypes.has(message.bodyType) ? groupSummary(message.bodyType, message.text)
      : isGateway ? message.gatewayVerified ? gatewaySummary(message.bodyType, message.text) : `[unverified ${message.bodyType}] ${message.text}` : message.text;
    const text = terminalText(`${new Date(message.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} ${name}: ${body}`);
    const color = message.bodyType === 'system' ? theme.system : isGateway ? theme.info : message.direction === 'outgoing' ? theme.outgoing : theme.incoming;
    for (const line of wrapAnsi(text, width, { hard: true, trim: false }).split('\n')) lines.push({ text: line, color });
  }
  const end = Math.max(0, lines.length - scrollOffset);
  const visible = lines.slice(Math.max(0, end - height), end);
  return (
    <Box flexDirection="column" flexGrow={1} borderStyle="single" borderColor={theme.borderActive} paddingX={1}>
      {visible.length ? visible.map((line, index) => <Text key={index} color={line.color} wrap="truncate">{line.text}</Text>) : <Text dimColor>No messages yet. Type a message below.</Text>}
      {scrollOffset > 0 && <Text dimColor>Lines {Math.max(1, end - height + 1)}–{end}/{lines.length} · j/k scroll</Text>}
    </Box>
  );
}
