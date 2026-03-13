import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import { matchCommands } from '../lib/commands.js';

interface ComposerProps {
  onSend: (text: string) => void;
  onCommand: (cmd: string, args: string) => void;
  activeConversation: string | null;
}

export default function Composer({ onSend, onCommand, activeConversation }: ComposerProps) {
  const [value, setValue] = useState('');

  const handleSubmit = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;

    if (trimmed.startsWith('/')) {
      const spaceIdx = trimmed.indexOf(' ');
      const cmd = spaceIdx === -1 ? trimmed.slice(1) : trimmed.slice(1, spaceIdx);
      const args = spaceIdx === -1 ? '' : trimmed.slice(spaceIdx + 1).trim();
      onCommand(cmd, args);
    } else {
      if (!activeConversation) {
        // Will be handled by App as a system message
        onCommand('_no_conv', trimmed);
      } else {
        onSend(trimmed);
      }
    }

    setValue('');
  };

  // Compute slash-command hints when the input starts with "/"
  const showHints = value.startsWith('/') && !value.includes(' ');
  const hintPrefix = value.slice(1).toLowerCase();
  const hints = showHints ? matchCommands(hintPrefix) : [];

  return (
    <Box flexDirection="column">
      {showHints && hints.length > 0 && (
        <Box paddingX={2}>
          <Text dimColor>
            {hints.map((c) => `${c.usage} — ${c.brief}`).join('  |  ')}
          </Text>
        </Box>
      )}
      <Box borderStyle="single" borderColor="green" paddingX={1}>
        <Text color="green">{'\u276f'} </Text>
        <TextInput
          value={value}
          onChange={setValue}
          onSubmit={handleSubmit}
          focus={true}
          placeholder={activeConversation ? 'Type a message or /help' : '/help for commands'}
        />
      </Box>
    </Box>
  );
}
