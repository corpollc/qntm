import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { addParticipant, createConversation, createGroupControlMessage, createGroupGenesisBody,
  createGroupRemoveBody, createGroupSession, createInvite, deriveConversationKeys, generateIdentity,
  GroupState, groupSessionConversation, parseGroupGenesisBody, prepareGroupSessionAddition,
  receiveGroupEvent, restoreGroupSession } from '@corpollc/qntm';
import { Store, bytesToHex } from '../src/lib/store.js';

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

  it('keeps separate message IDs even when text and time match', () => {
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

    expect(store.loadHistory('conv-1')).toHaveLength(2);
  });

  it('preserves admission checkpoints and removal fences in the read-only group projection', () => {
    const configDir = makeTempDir('qntm-tui-admission-state-');
    dirs.push(configDir);
    const store = new Store(configDir, 'https://relay.example.test');
    const recipient = store.generateIdentity(), creator = generateIdentity(), added = generateIdentity();
    const invite = createInvite(creator, 'group');
    const conversation = createConversation(invite, deriveConversationKeys(invite));
    addParticipant(conversation, creator.publicKey); addParticipant(conversation, recipient.publicKey);
    const roster = new GroupState();
    roster.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Projection', '', creator, [recipient.publicKey])));
    const owner = createGroupSession(creator, conversation, roster);
    let state = createGroupSession(recipient, conversation, roster);
    const addition = prepareGroupSessionAddition(creator, owner, [added.publicKey]);
    for (const envelope of [addition.addition, addition.rekey]) state = receiveGroupEvent(recipient, envelope, state).state;
    const remove = createGroupControlMessage(creator, groupSessionConversation(state), 'group_remove', createGroupRemoveBody([recipient.keyID]));
    state = receiveGroupEvent(recipient, remove, state).state;
    expect(state.admissions[bytesToHex(added.keyID)].completion).not.toBeNull();
    expect(state.rekeys[0].admissions[bytesToHex(added.keyID)].completion).toBeNull();
    expect(state.removedAtEpoch).toBe(1);
    const crypto = groupSessionConversation(state);
    mkdirSync(store.groups.profileDir, { mode: 0o700 });
    writeFileSync(join(store.groups.profileDir, 'identity.json'), readFileSync(join(configDir, 'identity.json')), { mode: 0o600 });
    const filename = join(store.groups.profileDir, 'conversations.json');
    const raw = JSON.stringify([{ id: state.conversationId, name: 'Projection', type: 'group',
      keys: { root: bytesToHex(crypto.keys.root), aead_key: bytesToHex(crypto.keys.aeadKey), nonce_key: bytesToHex(crypto.keys.nonceKey) },
      participants: crypto.participants.map(bytesToHex), created_at: new Date().toISOString(), current_epoch: state.epoch,
      group_session: state, group_cursor: 4, relay_url: store.dropboxUrl }]);
    writeFileSync(filename, raw, { mode: 0o600 });
    const restarted = new Store(configDir, store.dropboxUrl);
    const projected = restarted.findConversation(state.conversationId)!;
    expect(projected.groupSession).toEqual(state);
    expect(restoreGroupSession(recipient, projected.groupSession)).toEqual(state);
    restarted.saveConversations(restarted.loadConversations());
    expect(readFileSync(filename, 'utf8')).toBe(raw);
  });
});
