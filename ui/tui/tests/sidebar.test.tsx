import React from 'react';
import { render } from 'ink-testing-library';
import { expect, it } from 'vitest';
import Sidebar from '../src/components/Sidebar.js';
import type { StoredConversation, StoredMessage } from '../src/lib/store.js';

it('renders terminal controls in peer-supplied group names and previews as text', () => {
  const conversation = { id: 'a', name: 'Bad\x1b[2Jname', type: 'group' } as StoredConversation;
  const message = { text: '\x1b]52;c;clipboard\x07', createdAt: new Date().toISOString() } as StoredMessage;
  const view = render(<Sidebar conversations={[conversation]} activeId="a" unread={{}}
    lastMessages={{ a: message }} onSelect={() => {}} visible />);
  try {
    expect(view.lastFrame()).toContain('Bad\\u001b[2J');
    expect(view.lastFrame()).toContain('\\u001b]52;c;');
    expect(view.lastFrame()).not.toContain('\x1b[2J');
    expect(view.lastFrame()).not.toContain('\x1b]52;');
  } finally { view.unmount(); }
});
