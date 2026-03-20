import React from 'react';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'ink-testing-library';
import { DropboxClient } from '@corpollc/qntm';
import { sendMessage } from '../src/lib/poller.js';
import { Store } from '../src/lib/store.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

interface ComposerProps {
  onSend: (text: string) => void;
  onCommand: (cmd: string, args: string) => void;
  activeConversation: string | null;
}

const composerState = vi.hoisted(() => ({ current: null as ComposerProps | null }));

vi.mock('../src/components/Composer.js', () => ({
  default: (props: ComposerProps) => {
    composerState.current = props;
    return null;
  },
}));

import App from '../src/App.js';

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('App integration', () => {
  const dirs: string[] = [];
  let relay: TestRelayServer;

  beforeEach(async () => {
    relay = new TestRelayServer();
    await relay.start();
  });

  afterEach(async () => {
    composerState.current = null;
    await relay.close();
    while (dirs.length > 0) {
      rmSync(dirs.pop()!, { recursive: true, force: true });
    }
  });

  it('boots, creates a conversation, sends a message, and receives a reply', async () => {
    const aliceDir = makeTempDir('qntm-tui-app-alice-');
    const bobDir = makeTempDir('qntm-tui-app-bob-');
    dirs.push(aliceDir, bobDir);

    const app = render(<App configDir={aliceDir} dropboxUrl={relay.url} />);

    try {
      await waitFor(() => {
        const frame = app.lastFrame() ?? '';
        return composerState.current !== null && frame.includes('Generated new keypair.');
      });

      composerState.current!.onCommand('invite', 'Smoke Test');

      await waitFor(() => {
        const frame = app.lastFrame() ?? '';
        return frame.includes('Invite created!') && frame.includes('Smoke Test');
      });

      composerState.current!.onSend('hello from alice');
      await waitFor(() => (app.lastFrame() ?? '').includes('hello from alice'));

      const aliceStore = new Store(aliceDir, relay.url);
      const bobStore = new Store(bobDir, relay.url);
      const bobIdentity = bobStore.generateIdentity();
      const [conversation] = aliceStore.loadConversations();
      expect(conversation?.inviteToken).toBeTruthy();

      bobStore.acceptInvite(bobIdentity, conversation!.inviteToken!, 'Smoke Test');
      await sendMessage(
        bobStore,
        new DropboxClient(relay.url),
        bobIdentity,
        conversation!.id,
        'hello from bob',
      );

      await waitFor(() => (app.lastFrame() ?? '').includes('hello from bob'), 10_000, 100);
    } finally {
      app.unmount();
    }
  });
});
