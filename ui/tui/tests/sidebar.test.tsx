import React from 'react';
import { describe, expect, it } from 'vitest';
import { render } from 'ink-testing-library';
import Sidebar from '../src/components/Sidebar.js';
import type { StoredConversation, StoredMessage } from '../src/lib/store.js';

describe('Sidebar terminal escape sanitization', () => {
  it('escapes ANSI CSI, OSC, control, and bidi override sequences in conversation names and message previews', () => {
    const conv: StoredConversation = {
      id: '00112233445566778899aabbccddeeff',
      name: 'Ops\x1b]52;c;cHduZWQ=\x07\u202eRoom',
      type: 'group',
      keys: { root: '00', aeadKey: '00', nonceKey: '00' },
      participants: [],
      createdAt: new Date().toISOString(),
      currentEpoch: 0,
    };
    const lastMsg: StoredMessage = {
      id: 'deadbeef',
      conversationId: conv.id,
      direction: 'incoming',
      sender: 'peer',
      senderKey: 'peer',
      bodyType: 'text',
      text: '\x1b[2J\x1b]52;c;ZWNobyBwd25lZA==\x07\r\n\u202espoofed',
      createdAt: new Date().toISOString(),
    };

    const view = render(
      <Sidebar
        conversations={[conv]}
        activeId={null}
        unread={{ [conv.id]: 1 }}
        lastMessages={{ [conv.id]: lastMsg }}
        onSelect={() => {}}
        visible={true}
      />,
    );
    try {
      const frame = view.lastFrame() ?? '';
      expect(frame).not.toContain('\x1b]52;');
      expect(frame).not.toContain('\x1b[2J');
      expect(frame).not.toContain('\x07');
      expect(frame).not.toContain('\u202e');
      expect(frame).toContain('Ops\\u001b]52;c;\u2026');
      expect(frame).toContain('\\u001b[2J\\u001b]52;c;ZWNoby');
    } finally {
      view.unmount();
    }
  });
});
