import React from 'react';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'ink-testing-library';
import { DropboxClient, createGateRequestBody } from '@corpollc/qntm';
import { gatewayFixture } from './support/gateway.js';
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

  it('requires every review page before confirmation and cancels without posting', async () => {
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), { service: 'demo', endpoint: '/records', verb: 'POST', targetUrl: 'https://api.example.test/records', payload: { exact: 'review me' } });
    await f.deliver(f.bob, request.type, request);
    const posted = vi.spyOn(DropboxClient.prototype, 'postMessage').mockResolvedValue(50);
    const app = render(<App configDir={f.dir} dropboxUrl={relay.url} />);
    try {
      await waitFor(() => !!composerState.current?.activeConversation);
      composerState.current!.onCommand('approve', request.request_id);
      await waitFor(() => (app.lastFrame() ?? '').includes('Review gate.approval'));
      expect(posted).not.toHaveBeenCalled();
      const pages = Number((app.lastFrame() ?? '').match(/page 1\/(\d+)/)![1]);
      expect(pages).toBeGreaterThan(1);
      composerState.current!.onCommand('confirm', '');
      await waitFor(() => (app.lastFrame() ?? '').includes(`Review all ${pages} pages`));
      expect(posted).not.toHaveBeenCalled();
      for (let page = 2; page <= pages; page++) {
        composerState.current!.onCommand('review', String(page));
        await waitFor(() => (app.lastFrame() ?? '').includes(`page ${page}/${pages}`));
      }
      composerState.current!.onCommand('cancel', '');
      await waitFor(() => !(app.lastFrame() ?? '').includes('Review gate.approval'));
      expect(posted).not.toHaveBeenCalled();
    } finally { app.unmount(); posted.mockRestore(); }
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
