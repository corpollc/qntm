import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DropboxClient } from '@corpollc/qntm';
import { pollConversation, sendMessage } from '../src/lib/poller.js';
import { Store } from '../src/lib/store.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('poller', () => {
  const dirs: string[] = [];
  let relay: TestRelayServer;

  beforeEach(async () => {
    relay = new TestRelayServer();
    await relay.start();
  });

  afterEach(async () => {
    await relay.close();
    while (dirs.length > 0) {
      rmSync(dirs.pop()!, { recursive: true, force: true });
    }
  });

  it('sends an outgoing message, records sender history, and suppresses self-echoes', async () => {
    const aliceDir = makeTempDir('qntm-tui-poller-alice-');
    dirs.push(aliceDir);

    const aliceStore = new Store(aliceDir, relay.url);
    const aliceIdentity = aliceStore.generateIdentity();
    const { convId } = aliceStore.createInvite(aliceIdentity, 'Self Echo');
    const dropbox = new DropboxClient(relay.url);

    const sent = await sendMessage(aliceStore, dropbox, aliceIdentity, convId, 'hello from alice');
    expect(sent?.text).toBe('hello from alice');
    expect(aliceStore.loadHistory(convId)).toHaveLength(1);
    expect(relay.messageCount(convId)).toBe(1);

    const polled = await pollConversation(aliceStore, dropbox, aliceIdentity, convId);
    expect(polled.messages).toEqual([]);
    expect(aliceStore.loadHistory(convId)).toHaveLength(1);
    expect(aliceStore.loadCursor(convId)).toBe(1);
    expect(relay.messageCount(convId)).toBe(1);
  });

  it('receipts incoming messages and deletes them once quorum is met', async () => {
    const aliceDir = makeTempDir('qntm-tui-poller-alice-');
    const bobDir = makeTempDir('qntm-tui-poller-bob-');
    dirs.push(aliceDir, bobDir);

    const aliceStore = new Store(aliceDir, relay.url);
    const bobStore = new Store(bobDir, relay.url);
    const aliceIdentity = aliceStore.generateIdentity();
    const bobIdentity = bobStore.generateIdentity();
    const { token, convId } = aliceStore.createInvite(aliceIdentity, 'Relay Flow');
    bobStore.acceptInvite(bobIdentity, token, 'Relay Flow');

    const dropbox = new DropboxClient(relay.url);
    await sendMessage(aliceStore, dropbox, aliceIdentity, convId, 'hello bob');

    expect(relay.messageCount(convId)).toBe(1);

    const received = await pollConversation(bobStore, dropbox, bobIdentity, convId);

    expect(received.messages).toHaveLength(1);
    expect(received.messages[0]?.text).toBe('hello bob');
    expect(received.newCursor).toBe(1);
    expect(bobStore.loadHistory(convId)).toHaveLength(1);
    expect(bobStore.loadCursor(convId)).toBe(1);
    await waitFor(() => relay.messageCount(convId) === 0);
  });
});
