import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';

interface ComposerProps {
  onSend: (text: string) => void;
  onCommand: (cmd: string, args: string) => void;
  focus: boolean;
  activeConversation: string | null;
}

export default function Composer({ onSend, onCommand, focus, activeConversation }: ComposerProps) {
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

  return (
    <Box borderStyle="single" borderColor="green" paddingX={1}>
      <Text color="green">{'\u276f'} </Text>
      <TextInput
        value={value}
        onChange={setValue}
        onSubmit={handleSubmit}
        focus={focus}
        placeholder={activeConversation ? 'Type a message or /help' : '/help for commands'}
      />
    </Box>
  );
}
