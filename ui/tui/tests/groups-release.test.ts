import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DropboxClient, decryptMessage, deserializeEnvelope, groupSessionConversation, isGroupWelcomeEnvelope,
  restoreGroupSession } from '@corpollc/qntm';
import { Store, bytesToHex } from '../src/lib/store.js';
import { runGroupCommand } from '../src/lib/group-commands.js';
import { groupNotice } from '../src/lib/groups.js';
import { sendMessage, pollConversation } from '../src/lib/poller.js';
import { TuiAgent } from '../../../integration/src/tui-agent.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

const execute = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const python = process.env.QNTM_TUI_PYTHON || process.env.QNTM_TEST_PYTHON || 'python3';
const pythonPath = join(repo, 'python-dist/src');

describe.sequential('terminal release of a stale unproven removal', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'qntm-tui-release-'));
  const relay = new TestRelayServer();
  const oldPython = process.env.QNTM_TUI_PYTHON, oldPath = process.env.PYTHONPATH;
  let alice: Store, bob: Store, id: string, tui: TuiAgent | undefined;
  const record = (store: Store) => JSON.parse(readFileSync(join(store.groups.profileDir, 'conversations.json'), 'utf8'))
    .find((row: { id: string }) => row.id === id);
  beforeAll(async () => {
    process.env.QNTM_TUI_PYTHON = python;
    process.env.PYTHONPATH = pythonPath;
    await relay.start();
    alice = new Store(join(scratch, 'alice'), relay.url); alice.generateIdentity();
    bob = new Store(join(scratch, 'bob'), relay.url); bob.generateIdentity();
  });
  afterAll(async () => {
    await tui?.stop();
    await relay.close();
    if (oldPython === undefined) delete process.env.QNTM_TUI_PYTHON; else process.env.QNTM_TUI_PYTHON = oldPython;
    if (oldPath === undefined) delete process.env.PYTHONPATH; else process.env.PYTHONPATH = oldPath;
    rmSync(scratch, { recursive: true, force: true });
  });

  it('releases through the command path and PTY without posting, then a later remove excludes the peer', async () => {
    await runGroupCommand(alice, 'contact', `add Bob ${bytesToHex(bob.loadIdentity()!.publicKey)}`, null);
    const created = await alice.groups.run(['group', 'create', 'Release unproven']);
    id = String(created.conversation_id);
    const added = await runGroupCommand(alice, 'group', 'add Bob', id);
    const link = added.text.match(/https:\/\/chat\.corpo\.llc\/#group=\S+/)![0];
    await runGroupCommand(bob, 'join', link, null);
    expect(bob.findConversation(id)?.groupSession?.epoch).toBe(1);
    const staged = JSON.parse((await execute(python, [join(repo, 'integration/src/stage-unposted-removal.py'),
      alice.groups.profileDir, relay.url, id, bytesToHex(bob.loadIdentity()!.keyID), '8'],
      { env: { ...process.env, PYTHONPATH: pythonPath }, timeout: 30_000 })).stdout);
    expect(record(alice).group_operation.kind).toBe('remove');
    expect(groupNotice(alice.findConversation(id))).toContain('operation pending');
    await expect(sendMessage(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id, 'blocked while pending')).rejects.toThrow(/pending/i);
    await waitFor(() => Math.floor(Date.now() / 1000) > staged.removal_expires_at, 20_000);
    await expect(runGroupCommand(alice, 'group', 'retry', id)).rejects.toThrow(/expired before its acceptance/);
    expect(record(alice).group_operation.controls).toEqual(expect.any(Array));
    expect(record(alice).released_group_operations ?? []).toEqual([]);

    tui = new TuiAgent(alice.configDir, relay.url, python);
    await tui.start();
    await tui.waitFor('operation pending', 0, 15_000);
    const helpFrom = await tui.command('/help group');
    await tui.waitFor(text => text.replace(/\s/g, '').includes('--release-unproven'), helpFrom);
    const help = tui.text(helpFrom).replace(/\s/g, '');
    expect(help).toContain('--release-unproven');
    expect(help).toContain('sendsnothing');
    expect(help).not.toMatch(/successfulremoval|cancelled|canceled|undone/i);
    const before = relay.conversations.get(id)?.messages.map(row => row.envelopeB64) ?? [];
    const from = await tui.command('/group retry --release-unproven');
    const shown = await tui.waitFor('Local retry released', from, 30_000);
    const compact = shown.replace(/\s/g, '');
    expect(compact).toMatch(/membershipisunchanged|ciphertextstaysintheprivateprofile/i);
    expect(compact).not.toMatch(/Groupretrycomplete|removedandkeysrotated|cancelled|canceled|undone/i);
    await tui.stop(); tui = undefined;

    const after = record(alice);
    expect(after.group_operation).toBeUndefined();
    expect(after.released_group_operations).toHaveLength(1);
    expect(after.released_group_operations[0]).toMatchObject({
      kind: 'remove', controls: expect.any(Array), welcomes: [], welcomes_sent: 0, delivery: 'unknown', released_reason: 'expired',
    });
    expect(after.released_group_operations[0]).not.toHaveProperty('expected');
    expect((relay.conversations.get(id)?.messages ?? []).map(row => row.envelopeB64)).toEqual(before);
    expect(after.participants).toContain(bytesToHex(bob.loadIdentity()!.keyID));

    await sendMessage(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id, 'after local release');
    await pollConversation(bob, new DropboxClient(relay.url), bob.loadIdentity()!, id);
    expect(bob.loadHistory(id).some(message => message.text === 'after local release')).toBe(true);
    await sendMessage(bob, new DropboxClient(relay.url), bob.loadIdentity()!, id, 'bob still present');
    await pollConversation(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id);
    expect(alice.loadHistory(id).some(message => message.text === 'bob still present')).toBe(true);

    const prior = restoreGroupSession(bob.loadIdentity()!, record(bob).group_session);
    const priorConversation = groupSessionConversation(prior);
    const postedBeforeRemove = relay.conversations.get(id)?.messages.length ?? 0;
    await runGroupCommand(alice, 'group', 'remove Bob', id);
    expect((relay.conversations.get(id)?.messages.length ?? 0) - postedBeforeRemove).toBe(2);
    await sendMessage(alice, new DropboxClient(relay.url), alice.loadIdentity()!, id, 'survivor after explicit removal');
    const batch = await new DropboxClient(relay.url).receiveMessages(Buffer.from(id, 'hex'), 0);
    expect(() => {
      for (const row of batch.entries) {
        const envelope = deserializeEnvelope(row.envelope);
        if (!isGroupWelcomeEnvelope(envelope) && envelope.conv_epoch > prior.epoch) decryptMessage(envelope, priorConversation);
      }
    }).toThrow();
    await bob.groups.run(['recv', id]);
    expect(record(bob).group_session.removed).toBe(true);
    await expect(sendMessage(bob, new DropboxClient(relay.url), bob.loadIdentity()!, id, 'removed reply')).rejects.toThrow(/removed/i);
    expect(record(alice).released_group_operations).toHaveLength(1);
  }, 120_000);
});
