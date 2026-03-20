import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Store } from '../src/lib/store.js';

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('Store', () => {
  const dirs: string[] = [];

  afterEach(() => {
    while (dirs.length > 0) {
      rmSync(dirs.pop()!, { recursive: true, force: true });
    }
  });

  it('persists identity, metadata, contacts, and cursors', () => {
    const configDir = makeTempDir('qntm-tui-store-');
    dirs.push(configDir);

    const store = new Store(configDir, 'https://relay.example.test');
    const identity = store.generateIdentity();
    store.setName('Alice');
    store.setContact('AABBCC', 'Bob');
    store.saveCursor('conv-1', 42);

    const reloaded = new Store(configDir, 'https://ignored.example.test');

    expect(reloaded.loadIdentity()).toEqual(identity);
    expect(reloaded.getName()).toBe('Alice');
    expect(reloaded.resolveContact('aabbcc')).toBe('Bob');
    expect(reloaded.loadCursor('conv-1')).toBe(42);
    expect(reloaded.loadStoreData().dropboxUrl).toBe('https://relay.example.test');
  });

  it('creates and accepts invites without duplicating conversations', () => {
    const aliceDir = makeTempDir('qntm-tui-store-alice-');
    const bobDir = makeTempDir('qntm-tui-store-bob-');
    dirs.push(aliceDir, bobDir);

    const aliceStore = new Store(aliceDir, 'https://relay.example.test');
    const bobStore = new Store(bobDir, 'https://relay.example.test');
    const aliceIdentity = aliceStore.generateIdentity();
    const bobIdentity = bobStore.generateIdentity();

    const { token, convId } = aliceStore.createInvite(aliceIdentity, 'Ops Room');
    const joinedConvId = bobStore.acceptInvite(bobIdentity, token, 'Joined Ops');
    const joinedAgain = bobStore.acceptInvite(bobIdentity, token, 'Joined Ops');

    expect(joinedConvId).toBe(convId);
    expect(joinedAgain).toBe(convId);

    const aliceConversations = aliceStore.loadConversations();
    const bobConversations = bobStore.loadConversations();

    expect(aliceConversations).toHaveLength(1);
    expect(aliceConversations[0]?.inviteToken).toBe(token);
    expect(aliceConversations[0]?.participants).toHaveLength(1);
    expect(bobConversations).toHaveLength(1);
    expect(bobConversations[0]?.id).toBe(convId);
    expect(bobConversations[0]?.type).toBe('direct');
  });

  it('deduplicates near-identical history entries', () => {
    const configDir = makeTempDir('qntm-tui-history-');
    dirs.push(configDir);

    const store = new Store(configDir, 'https://relay.example.test');
    const createdAt = new Date().toISOString();

    store.appendHistory('conv-1', {
      id: 'msg-1',
      conversationId: 'conv-1',
      direction: 'outgoing',
      sender: 'You',
      senderKey: '',
      bodyType: 'text',
      text: 'hello',
      createdAt,
    });
    store.appendHistory('conv-1', {
      id: 'msg-2',
      conversationId: 'conv-1',
      direction: 'outgoing',
      sender: 'You',
      senderKey: '',
      bodyType: 'text',
      text: 'hello',
      createdAt: new Date(Date.parse(createdAt) + 1000).toISOString(),
    });

    expect(store.loadHistory('conv-1')).toHaveLength(1);
  });
});
