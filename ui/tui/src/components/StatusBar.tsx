import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import { theme } from '../lib/theme.js';

const SPINNER_FRAMES = ['\u25D0', '\u25D3', '\u25D1', '\u25D2'];

interface StatusBarProps {
  kid: string;
  name: string;
  connected: boolean;
  conversationCount: number;
  scrollMode: boolean;
  scrollOffset: number;
  isPolling?: boolean;
  lastMessageTime?: number | null;
  connectionError?: string | null;
  messageCount?: number;
}

function formatRelativeTime(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export default function StatusBar({
  kid,
  name,
  connected,
  conversationCount,
  scrollMode,
  scrollOffset,
  isPolling = false,
  lastMessageTime = null,
  connectionError = null,
  messageCount = 0,
}: StatusBarProps) {
  const kidShort = kid ? kid.slice(0, 12) + '..' : 'none';

  // Animated spinner
  const [spinnerIdx, setSpinnerIdx] = useState(0);

  useEffect(() => {
    if (!isPolling) {
      setSpinnerIdx(0);
      return;
    }
    const timer = setInterval(() => {
      setSpinnerIdx((prev) => (prev + 1) % SPINNER_FRAMES.length);
    }, 200);
    return () => clearInterval(timer);
  }, [isPolling]);

  // Re-render periodically so relative time stays fresh
  const [, setTick] = useState(0);
  useEffect(() => {
    if (lastMessageTime === null) return;
    const timer = setInterval(() => setTick((t) => t + 1), 10_000);
    return () => clearInterval(timer);
  }, [lastMessageTime]);

  // Connection indicator
  let connSymbol: string;
  let connColor: string;
  let connLabel: string;

  if (connectionError) {
    connSymbol = '\u25CF';
    connColor = theme.error;
    connLabel = connectionError.length > 20 ? connectionError.slice(0, 20) + '..' : connectionError;
  } else if (isPolling) {
    connSymbol = SPINNER_FRAMES[spinnerIdx];
    connColor = theme.warning;
    connLabel = 'polling';
  } else if (connected) {
    connSymbol = '\u25CF';
    connColor = theme.success;
    connLabel = 'online';
  } else {
    connSymbol = '\u25CB';
    connColor = theme.error;
    connLabel = 'offline';
  }

  // Right side info
  let rightText: string;
  if (scrollMode) {
    rightText = scrollOffset > 0 ? `\u2195 scrolled +${scrollOffset}` : '\u2195 scroll mode';
  } else if (conversationCount > 0) {
    rightText = `${conversationCount} conv${conversationCount === 1 ? '' : 's'}`;
    if (messageCount > 0) {
      rightText += ` | ${messageCount} msg${messageCount === 1 ? '' : 's'}`;
    }
  } else {
    rightText = '/invite to start';
  }

  const lastMsgText = lastMessageTime !== null
    ? `Last msg: ${formatRelativeTime(lastMessageTime)}`
    : '';

  return (
    <Box paddingX={1} flexDirection="row" justifyContent="space-between">
      <Text>
        <Text color={connColor}>{connSymbol}</Text>
        {' '}
        <Text dimColor>{connLabel}</Text>
        {lastMsgText ? <Text dimColor>{' | '}{lastMsgText}</Text> : null}
        {'  '}
        <Text bold>{name || 'unnamed'}</Text>
        {' '}
        <Text dimColor>[{kidShort}]</Text>
      </Text>
      <Text dimColor>{rightText}</Text>
    </Box>
  );
}
