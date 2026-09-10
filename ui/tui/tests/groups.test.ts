import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DropboxClient, generateIdentity, openGroupWelcome, deserializeEnvelope, isGroupWelcomeEnvelope,
  createMessage, serializeEnvelope, decryptMessage, groupSessionFromWelcome, checkGroupWelcomeReplay,
  checkExpiredGroupControl, receiveGroupEvent, assertGroupCanSend, groupSessionConversation,
  restoreGroupSession, prepareGroupSessionRekey } from '@corpollc/qntm';
import { Store, bytesToHex } from '../src/lib/store.js';
import { runGroupCommand } from '../src/lib/group-commands.js';
import { groupNotice, splitGroupArguments } from '../src/lib/groups.js';
import { sendMessage, pollConversation } from '../src/lib/poller.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

describe.sequential('terminal contact groups through the real Python receiver', () => {
  const root = mkdtempSync(join(tmpdir(), 'qntm-tui-groups-'));
  const relay = new TestRelayServer();
  const oldPython = process.env.QNTM_TUI_PYTHON, oldPath = process.env.PYTHONPATH;
  let alice: Store, bob: Store, id: string, link: string;
  let stop: (() => void) | undefined;
  beforeAll(async () => {
    process.env.QNTM_TUI_PYTHON = process.env.QNTM_TEST_PYTHON || 'python3';
    process.env.PYTHONPATH = resolve('../../python-dist/src');
    await relay.start();
    alice = new Store(join(root, 'alice'), relay.url); alice.generateIdentity();
    bob = new Store(join(root, 'bob'), relay.url); bob.generateIdentity();
  });
  afterAll(async () => {
    stop?.();
    await relay.close();
    if (oldPython === undefined) delete process.env.QNTM_TUI_PYTHON; else process.env.QNTM_TUI_PYTHON = oldPython;
    if (oldPath === undefined) delete process.env.PYTHONPATH; else process.env.PYTHONPATH = oldPath;
    rmSync(root, { recursive: true, force: true });
  });

  it('pins full keys without shell interpolation or silent name replacement', async () => {
    const result = await runGroupCommand(alice, 'contact', `add "Bob $(touch never)" ${bytesToHex(bob.loadIdentity()!.publicKey)}`, null);
    expect(result.text).toContain('Pinned contact Bob $(touch never)');
    await expect(runGroupCommand(alice, 'contact', `add "Bob $(touch never)" ${bytesToHex(generateIdentity().publicKey)}`, null)).rejects.toThrow('already pins another key');
    expect((await runGroupCommand(alice, 'contact', 'list', null)).text).toContain(bytesToHex(bob.loadIdentity()!.publicKey));
    expect(statSync(alice.groups.profileDir).mode & 0o777).toBe(0o700);
    expect(statSync(join(alice.groups.profileDir, 'identity.json')).mode & 0o777).toBe(0o600);
    expect(splitGroupArguments('refresh "Bob $(touch never)" --challenge abc')).toEqual(['refresh', 'Bob $(touch never)', '--challenge', 'abc']);
    expect(() => splitGroupArguments('add "unfinished')).toThrow('Close');
  });

  it('adds and opens a contact group while preserving native conversations and private atomic state', async () => {
    const legacy = alice.createInvite(alice.loadIdentity()!, 'Existing chat');
    // Legacy CLI creation is initialized by the first addition; /group create
    // uses the durable --contact mode in the shared client.
    const created = await alice.groups.run(['group', 'create', 'Contact test']);
    id = created.conversation_id;
    const added = await runGroupCommand(alice, 'group', 'add "Bob $(touch never)"', id);
    link = added.text.match(/https:\/\/chat\.corpo\.llc\/#group=\S+/)![0];
    await runGroupCommand(bob, 'join', link, null);
    expect(bob.findConversation(id)?.groupSession?.epoch).toBe(1);
    const bytes = readFileSync(join(alice.groups.profileDir, 'conversations.json'), 'utf8');
    alice.saveConversations(alice.loadConversations());
    expect(readFileSync(join(alice.groups.profileDir, 'conversations.json'), 'utf8')).toBe(bytes);
    expect(alice.findConversation(legacy.convId)?.inviteToken).toBe(legacy.token);
    expect(() => alice.updateConversation(id, () => {})).toThrow('group client');
    expect(() => alice.gatewaySession(id, alice.loadIdentity()!)).toThrow('Gateway promotion');
  });

  it('holds a subscription open, receives and sends after restart without duplicate history', async () => {
    let online = false;
    const errors: string[] = [];
    stop = bob.groups.watch(id, { onChange() {}, onStatus(ready, error) { online = ready; if (error) errors.push(error); } }).close;
    await waitFor(() => online);
    await sendMessage(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id, 'hello through Python');
    await waitFor(() => bob.loadHistory(id).some(message => message.text === 'hello through Python'));
    // Replace the resident process immediately: its profile lock must be
    // released before the next process starts.
    online = false;
    stop();
    stop = bob.groups.watch(id, { onChange() {}, onStatus(ready, error) { online = ready; if (error) errors.push(error); } }).close;
    await waitFor(() => online, 10000);
    // The link's saved relay survives a different global terminal default.
    const restarted = new Store(bob.configDir, 'http://127.0.0.1:1');
    await sendMessage(restarted, new DropboxClient('http://127.0.0.1:1'), restarted.loadIdentity()!, id, 'reply after restart');
    await pollConversation(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id);
    expect(alice.loadHistory(id).filter(message => message.text === 'reply after restart')).toHaveLength(1);
    expect(bob.loadHistory(id).filter(message => message.text === 'hello through Python')).toHaveLength(1);
    expect(errors).toEqual([]);
  });

  it('allows a noncreator to add a TypeScript peer without disclosing earlier history', async () => {
    const peer = generateIdentity();
    await runGroupCommand(bob, 'contact', `add Charlie ${bytesToHex(peer.publicKey)}`, id);
    await runGroupCommand(bob, 'group', 'add Charlie', id);
    const replay = await new DropboxClient(relay.url).receiveMessages(Buffer.from(id, 'hex'), 0);
    const envelopes = replay.entries.map(row => ({ seq: row.seq, envelope: deserializeEnvelope(row.envelope) }));
    const selected = envelopes.filter(row => isGroupWelcomeEnvelope(row.envelope)).flatMap(row => {
      try { return [{ seq: row.seq, welcome: openGroupWelcome(peer, serializeEnvelope(row.envelope),
        { inviterPublicKey: bob.loadIdentity()!.publicKey, conversationId: Buffer.from(id, 'hex') }) }]; } catch { return []; }
    }).at(-1)!;
    const opened = selected.welcome;
    let state = groupSessionFromWelcome(peer, opened, selected.seq);
    state = checkGroupWelcomeReplay(state, opened, replay.sequence, replay.entries);
    for (const { seq, envelope } of envelopes.filter(row => row.seq > opened.replayFromSequence)) {
      if (isGroupWelcomeEnvelope(envelope)) continue;
      state = checkExpiredGroupControl(peer, state, envelope, seq);
      if (state.recovery || envelope.expiry_ts < Math.floor(Date.now() / 1000) || envelope.conv_epoch < state.epoch) continue;
      const event = receiveGroupEvent(peer, envelope, state);
      expect(event.rewound).toBe(false);
      state = event.state;
    }
    assertGroupCanSend(peer, state);
    expect(opened.conversation.currentEpoch).toBe(2);
    const before = envelopes.find(row => row.envelope.conv_epoch === 1 && !isGroupWelcomeEnvelope(row.envelope))!.envelope;
    expect(() => decryptMessage(before, opened.conversation)).toThrow();
    const message = createMessage(peer, groupSessionConversation(state), 'text', new TextEncoder().encode('hello from TypeScript'));
    await new DropboxClient(relay.url).postMessage(opened.conversation.id, serializeEnvelope(message));
    await waitFor(() => bob.loadHistory(id).some(message => message.text === 'hello from TypeScript'));
  });

  it('keeps missing history blocked until a fresh challenge-bound welcome is opened', async () => {
    stop?.(); stop = undefined;
    await waitFor(() => relay.conversations.get(id)!.subscribers.size === 0);
    await alice.groups.run(['send', id, 'lost while offline']);
    const conversation = relay.conversations.get(id)!;
    conversation.messages.pop(); // Retention leaves its sequence in the captured head.
    await bob.groups.run(['recv', id]);
    const state = bob.findConversation(id)!.groupSession!;
    expect(state.recovery?.challenge).toMatch(/^[a-f0-9]{64}$/);
    expect(groupNotice(bob.findConversation(id))).toContain('Incomplete group history');
    expect((await runGroupCommand(bob, 'group', 'status', id)).text).toContain(state.recovery!.challenge);
    await expect(sendMessage(bob, new DropboxClient(relay.url), bob.loadIdentity()!, id, 'must not send')).rejects.toThrow(/recovery|history/i);
    const without = await alice.groups.run(['group', 'refresh', id, 'Bob $(touch never)']);
    await expect(runGroupCommand(bob, 'join', without.group_link, id)).rejects.toThrow(/challenge/i);
    const fresh = await alice.groups.run(['group', 'refresh', id, 'Bob $(touch never)', '--challenge', state.recovery!.challenge]);
    await runGroupCommand(bob, 'join', fresh.group_link, id);
    expect(bob.findConversation(id)!.groupSession!.recovery).toBeNull();
    expect(groupNotice(bob.findConversation(id))).toBe('');
    await sendMessage(bob, new DropboxClient(relay.url), bob.loadIdentity()!, id, 'recovered reply');
  });

  it('persists removal, refuses refresh, and excludes later keys after restart', async () => {
    await runGroupCommand(alice, 'group', 'remove "Bob $(touch never)"', id);
    await bob.groups.run(['recv', id]);
    const restored = new Store(bob.configDir, relay.url);
    expect(groupNotice(restored.findConversation(id))).toContain('Removed');
    await expect(sendMessage(restored, new DropboxClient(relay.url), restored.loadIdentity()!, id, 'removed reply')).rejects.toThrow(/removed/i);
    await expect(runGroupCommand(alice, 'group', 'refresh "Bob $(touch never)"', id)).rejects.toThrow(/member/i);
    await alice.groups.run(['send', id, 'only remaining members']);
    await restored.groups.run(['recv', id]);
    expect(restored.loadHistory(id).some(message => message.text === 'only remaining members')).toBe(false);
    await expect(runGroupCommand(restored, 'join', link, id)).rejects.toThrow();
  });

  it('refuses an unrelated private identity in the group profile', async () => {
    const filename = join(bob.groups.profileDir, 'identity.json');
    const saved = readFileSync(filename, 'utf8');
    try {
      writeFileSync(filename, readFileSync(join(alice.configDir, 'identity.json'), 'utf8'));
      expect(() => bob.loadConversations()).toThrow('identity differs');
      await expect(bob.groups.run(['contact', 'list'])).rejects.toThrow('identity differs');
    } finally { writeFileSync(filename, saved); }
  });

  it('preserves an uncertain addition across restart and retries identical ciphertext', async () => {
    const created = await alice.groups.run(['group', 'create', 'Interrupted addition']);
    const interruptedId = String(created.conversation_id);
    relay.rejectNextSend = 503;
    await expect(runGroupCommand(alice, 'group', 'add "Bob $(touch never)"', interruptedId)).rejects.toThrow();
    const record = JSON.parse(readFileSync(join(alice.groups.profileDir, 'conversations.json'), 'utf8')).find((row: any) => row.id === interruptedId);
    const wires = [...record.group_operation.controls, ...record.group_operation.welcomes];
    expect(groupNotice(alice.findConversation(interruptedId))).toContain('operation pending');
    const restarted = new Store(alice.configDir, relay.url);
    await expect(sendMessage(restarted, new DropboxClient(relay.url), restarted.loadIdentity()!, interruptedId, 'blocked pending add')).rejects.toThrow(/pending/i);
    await runGroupCommand(restarted, 'group', 'retry', interruptedId);
    expect(restarted.findConversation(interruptedId)!.groupOperation).toBeUndefined();
    const posted = relay.conversations.get(interruptedId)!.messages.map(message => message.envelopeB64);
    for (const wire of wires) expect(posted.filter(value => value === wire)).toHaveLength(1);
  });

  it('does not report superseded same-batch plaintext as new delivery', async () => {
    const created = await alice.groups.run(['group', 'create', 'Competing batch', '--contact']);
    const batchId = String(created.conversation_id);
    const added = await alice.groups.run(['group', 'add', batchId, 'Bob $(touch never)']);
    await bob.groups.run(['group', 'join', '--', added.group_link]);
    const record = JSON.parse(readFileSync(join(alice.groups.profileDir, 'conversations.json'), 'utf8'))
      .find((row: any) => row.id === batchId);
    const identity = alice.loadIdentity()!;
    const source = restoreGroupSession(identity, record.group_session);
    const [winner, loser] = [prepareGroupSessionRekey(identity, source), prepareGroupSessionRekey(identity, source)]
      .sort((a, b) => bytesToHex(a.rekey.msg_id).localeCompare(bytesToHex(b.rekey.msg_id)));
    const superseded = createMessage(identity, loser.conversation, 'text', new TextEncoder().encode('superseded batch text'));
    const transport = new DropboxClient(relay.url);
    for (const envelope of [loser.rekey, superseded, winner.rekey]) {
      await transport.postMessage(Buffer.from(batchId, 'hex'), serializeEnvelope(envelope));
    }
    const result = await pollConversation(bob, transport, bob.loadIdentity()!, batchId);
    expect(result.messages.some(message => message.text === 'superseded batch text')).toBe(false);
    expect(bob.loadHistory(batchId).some(message => message.text === 'superseded batch text')).toBe(true);
    expect(bob.findConversation(batchId)!.groupSession!.root).toBe(bytesToHex(winner.conversation.keys.root));
  });

  it('rejects an older receiver contract even when the group APIs exist', async () => {
    const compatibility = join(root, 'old-python-contract');
    mkdirSync(compatibility);
    writeFileSync(join(compatibility, 'sitecustomize.py'),
      'import qntm.watch\nqntm.watch.GROUP_RECEIVE_CONTRACT_VERSION = 0\n', { mode: 0o600 });
    const fresh = new Store(join(root, 'compatibility-profile'), relay.url);
    fresh.generateIdentity();
    const previousPath = process.env.PYTHONPATH;
    try {
      process.env.PYTHONPATH = compatibility + delimiter + previousPath;
      await expect(fresh.groups.run(['contact', 'list'])).rejects.toThrow('matching qntm Python package');
    } finally {
      if (previousPath === undefined) delete process.env.PYTHONPATH; else process.env.PYTHONPATH = previousPath;
    }
    // A corrected installation can retry without recreating the terminal.
    await expect(fresh.groups.run(['contact', 'list'])).resolves.toHaveProperty('contacts');
  });
});
