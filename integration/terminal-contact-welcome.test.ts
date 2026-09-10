import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DropboxClient, generateIdentity, openGroupWelcome, isGroupWelcomeEnvelope, deserializeEnvelope,
  createMessage, serializeEnvelope, groupSessionFromWelcome, receiveGroupEvent, groupSessionConversation,
  assertGroupCanSend, checkGroupReplayCoverage, checkExpiredGroupControl,
  decryptMessage, type GroupSessionState, type ReceiveResult } from '@corpollc/qntm';
import { ManagedProcess, workerTestEnv } from './src/runtime.js';
import { TuiAgent } from './src/tui-agent.js';
import { Store, bytesToHex } from '../ui/tui/src/lib/store.js';

const execute = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.QNTM_TEST_PYTHON || 'python3';

describe.sequential('terminal contact welcomes with real relay, Python and TypeScript peers', () => {
  const root = mkdtempSync(join(tmpdir(), 'qntm-terminal-contact-'));
  const artifacts = process.env.QNTM_ACCEPTANCE_ARTIFACT_DIR || join(root, 'proof');
  let relayProcess: ManagedProcess, relay: DropboxClient, relayUrl: string;
  let terminal: TuiAgent, newcomer: TuiAgent | undefined, store: Store;
  let bobWatch: ChildProcess | undefined;
  let id: string, link: string, tsState: GroupSessionState, tsCursor = 0;
  const peer = generateIdentity();
  const bobProfile = join(root, 'python-bob');
  const oldPython = process.env.QNTM_TUI_PYTHON, oldPath = process.env.PYTHONPATH;
  const cli = async (...args: string[]) => {
    const result = await execute(python, ['-m', 'qntm', '--config-dir', bobProfile, '--dropbox-url', relayUrl, ...args],
      { env: { ...process.env, PYTHONPATH: join(repo, 'python-dist/src') }, maxBuffer: 8 << 20, timeout: 60000 });
    return JSON.parse(result.stdout).data;
  };
  const bobRecord = () => JSON.parse(readFileSync(join(bobProfile, 'conversations.json'), 'utf8')).find((row: any) => row.id === id);
  const proof = (name: string, tui = terminal) => writeFileSync(join(artifacts, `${name}.ansi`), tui.output, { mode: 0o600 });
  const stopTerminal = async (tui: TuiAgent) => {
    const groups = new Store(tui.configDir, relayUrl).loadConversations().filter(row => row.managedGroup);
    await tui.stop();
    for (const group of groups) {
      const lock = join(tui.configDir, 'contact-groups', 'watch', group.id + '.lock');
      const deadline = Date.now() + 10000;
      let released = false;
      while (Date.now() < deadline) {
        try {
          await execute(python, ['-c', 'import sys; from qntm.storage import private_lock\nwith private_lock(sys.argv[1], blocking=False): pass', lock],
            { env: { ...process.env, PYTHONPATH: join(repo, 'python-dist/src') } });
          released = true; break;
        } catch { await delay(50); }
      }
      if (!released) throw new Error('Terminal shutdown left its group receiver running');
    }
  };
  const command = async (text: string, match: string | RegExp, tui = terminal) => {
    const from = await tui.command(text);
    if (!text.startsWith('/') && match === 'You') {
      const selected = new Store(tui.configDir, relayUrl);
      await expect.poll(() => selected.loadHistory(id).some(row => row.text === text), { timeout: 30000 }).toBe(true);
    }
    const shown = await tui.waitFor(match, from, 30000);
    proof('live', tui);
    return shown;
  };
  const applyTsReplay = (result: ReceiveResult) => {
    tsState = checkGroupReplayCoverage(tsState, tsCursor, result.sequence, result.entries.map(row => row.seq));
    const messages: string[] = [];
    for (const row of result.entries.filter(row => row.seq > tsCursor).sort((a, b) => a.seq - b.seq)) {
      const envelope = deserializeEnvelope(row.envelope);
      if (isGroupWelcomeEnvelope(envelope)) continue;
      tsState = checkExpiredGroupControl(peer, tsState, envelope, row.seq);
      if (tsState.recovery || envelope.expiry_ts < Math.floor(Date.now() / 1000)) continue;
      // Bootstrap never discloses pre-admission roots. Such rows still count
      // toward coverage, but cannot supply application or membership history.
      if (envelope.conv_epoch < tsState.epoch && !tsState.rekeys.some(frame => frame.epoch === envelope.conv_epoch
        && Buffer.from(envelope.msg_id).toString('hex') < frame.messageId)) continue;
      const event = receiveGroupEvent(peer, envelope, tsState);
      tsState = event.state;
      expect(event.rewound, 'this linear fixture must not silently skip branch replay').toBe(false);
      if (!event.duplicate && event.message.inner.body_type === 'text') messages.push(new TextDecoder().decode(event.message.inner.body));
    }
    tsCursor = result.sequence;
    return messages;
  };
  const openTs = async () => {
    const result = await relay.receiveMessages(Buffer.from(id, 'hex'), 0);
    const welcomes = result.entries.filter(row => isGroupWelcomeEnvelope(deserializeEnvelope(row.envelope))).flatMap(row => {
      try { return [{ sequence: row.seq, welcome: openGroupWelcome(peer, row.envelope,
        { conversationId: Buffer.from(id, 'hex'), inviterPublicKey: store.loadIdentity()!.publicKey }) }]; }
      catch { return []; }
    });
    const selected = welcomes.at(-1)!;
    expect(selected).toBeDefined();
    const { welcome, sequence } = selected;
    tsState = groupSessionFromWelcome(peer, welcome, sequence, tsState);
    tsCursor = welcome.replayFromSequence;
    applyTsReplay(result);
    assertGroupCanSend(peer, tsState);
    return { result, welcome };
  };
  const receiveTs = async () => applyTsReplay(await relay.receiveMessages(Buffer.from(id, 'hex'), tsCursor));
  const sendTs = async (text: string) => {
    await receiveTs();
    assertGroupCanSend(peer, tsState);
    const envelope = createMessage(peer, groupSessionConversation(tsState), 'text', new TextEncoder().encode(text));
    await relay.postMessage(Buffer.from(id, 'hex'), serializeEnvelope(envelope));
  };
  beforeAll(async () => {
    mkdirSync(artifacts, { recursive: true, mode: 0o700 });
    process.env.QNTM_TUI_PYTHON = python;
    process.env.PYTHONPATH = join(repo, 'python-dist/src');
    relayProcess = new ManagedProcess('terminal-contact-relay', ['npx', 'wrangler', 'dev', '--local',
      '--name', basename(root).toLowerCase(), '--port', '0', '--ip', '127.0.0.1', '--inspector-port', '0',
      '--persist-to', join(root, 'relay'), '--var', 'RATE_LIMIT_PER_MIN:5000', '--var', 'ENVELOPE_TTL_SECONDS:60'],
    join(repo, 'worker'), workerTestEnv(root));
    relayUrl = await relayProcess.waitForLocalUrl('worker', '/healthz');
    relay = new DropboxClient(relayUrl);
    terminal = new TuiAgent(join(root, 'terminal'), relayUrl, python);
    await terminal.start();
    store = new Store(terminal.configDir, relayUrl);
    await cli('identity', 'generate');
  }, 60000);
  afterAll(async () => {
    if (terminal) proof('terminal-final');
    if (bobWatch && bobWatch.exitCode === null && bobWatch.signalCode === null) {
      const exited = once(bobWatch, 'exit'); bobWatch.kill('SIGTERM');
      await Promise.race([exited, delay(10000)]);
      if (bobWatch.exitCode === null && bobWatch.signalCode === null) bobWatch.kill('SIGKILL');
    }
    const stopped = await Promise.allSettled([...(newcomer ? [stopTerminal(newcomer)] : []), ...(terminal ? [stopTerminal(terminal)] : [])]);
    await relayProcess?.stop();
    if (oldPython === undefined) delete process.env.QNTM_TUI_PYTHON; else process.env.QNTM_TUI_PYTHON = oldPython;
    if (oldPath === undefined) delete process.env.PYTHONPATH; else process.env.PYTHONPATH = oldPath;
    // Keep only replayable terminal evidence, never private test identities.
    for (const name of ['terminal', 'newcomer', 'python-bob', 'relay']) rmSync(join(root, name), { recursive: true, force: true });
    console.log(`Terminal contact proof: ${artifacts}`);
    const failed = stopped.find(result => result.status === 'rejected');
    if (failed?.status === 'rejected') throw failed.reason;
  }, 30000);

  it('creates in the PTY, admits two contacts, then opens them in reverse order', async () => {
    await command('/group create Terminal contact acceptance', 'Created contact group');
    id = store.loadConversations().find(row => row.managedGroup)!.id;
    expect(store.findConversation(id)!.groupSession).toBeDefined();
    await command('before anyone was admitted', 'You');
    const bobKey = JSON.parse(readFileSync(join(bobProfile, 'identity.json'), 'utf8')).public_key;
    await command(`/contact add Bob ${bobKey}`, 'Pinned contact Bob');
    await command('/group add Bob', 'Group add complete for Bob');
    link = (await store.groups.run(['group', 'link', id])).group_link;
    await command(`/contact add Charlie ${bytesToHex(peer.publicKey)}`, 'Pinned contact Charlie');
    await command('/group add Charlie', 'Group add complete for Charlie');
    expect((await store.groups.run(['group', 'link', id])).group_link).toBe(link);
    const { result, welcome } = await openTs();
    expect(welcome.conversation.currentEpoch).toBe(2);
    const earlier = result.messages.map(deserializeEnvelope).find(envelope => envelope.conv_epoch === 0)!;
    expect(() => decryptMessage(earlier, welcome.conversation)).toThrow();
    await cli('group', 'join', '--', link);
    bobWatch = spawn(python, ['-m', 'qntm', '--config-dir', bobProfile, '--dropbox-url', relayUrl, 'recv', id, '--watch'],
      { env: { ...process.env, PYTHONPATH: join(repo, 'python-dist/src') }, stdio: ['ignore', 'pipe', 'pipe'] });
    let bobStatus = '';
    bobWatch.stdout!.resume(); bobWatch.stderr!.on('data', chunk => { bobStatus += chunk; });
    await expect.poll(() => bobStatus.includes('"state":"ready"'), { timeout: 15000 }).toBe(true);
    expect(bobRecord().current_epoch).toBe(2);
    expect(bobRecord().group_history.some((row: any) => row.unsafe_body === 'before anyone was admitted')).toBe(false);
    await cli('send', id, 'Python opened its earlier welcome second');
    await expect.poll(() => store.loadHistory(id).some(row => row.text === 'Python opened its earlier welcome second'), { timeout: 20000 }).toBe(true);
    expect(await receiveTs()).toContain('Python opened its earlier welcome second');
    await sendTs('TypeScript opened second admission first');
    await expect.poll(() => store.loadHistory(id).some(row => row.text === 'TypeScript opened second admission first'), { timeout: 20000 }).toBe(true);
    await terminal.waitFor('TypeScript opened second admission first');
    expect(await receiveTs()).toContain('TypeScript opened second admission first');
    proof('01-open-order');
  }, 90000);

  it('refreshes a current member, removes and readmits a peer, and resumes after a terminal restart', async () => {
    await command('/group refresh Bob', 'Group refresh complete for Bob');
    expect(store.findConversation(id)!.currentEpoch).toBe(2);
    await command('/group remove Charlie', 'Group remove complete for Charlie');
    await receiveTs();
    expect(tsState.removed).toBe(true);
    await command('/group refresh Charlie', /not.*member|member.*not/i);
    await command('during Charlie exclusion', 'You');
    const beforeEpoch = store.findConversation(id)!.currentEpoch;
    await command('/group add Charlie', 'Group add complete for Charlie');
    await expect.poll(() => store.findConversation(id)!.currentEpoch > beforeEpoch && !store.findConversation(id)!.groupOperation, { timeout: 30000 }).toBe(true);
    const { result, welcome } = await openTs();
    expect(welcome.conversation.currentEpoch).toBe(4);
    const excluded = result.messages.map(deserializeEnvelope).find(envelope => envelope.conv_epoch === 3 && !isGroupWelcomeEnvelope(envelope))!;
    expect(() => decryptMessage(excluded, welcome.conversation)).toThrow();
    const previous = store.loadHistory(id).map(row => row.id);
    proof('02-remove-readmit');
    await stopTerminal(terminal); await terminal.start();
    expect(store.loadHistory(id).map(row => row.id)).toEqual(previous);
    await cli('send', id, 'received after terminal process restart');
    await expect.poll(() => store.loadHistory(id).some(row => row.text === 'received after terminal process restart'), { timeout: 20000 }).toBe(true);
    proof('03-restart');
  }, 90000);

  it('reports real relay retention, blocks sending, and accepts a challenged refresh through the PTY', async () => {
    await stopTerminal(terminal);
    const cursor = store.loadCursor(id);
    await cli('send', id, 'expires while terminal is offline');
    // The worker's actual retention alarm removes ciphertext, preserving head.
    await delay(65000);
    expect((await relay.receiveMessages(Buffer.from(id, 'hex'), cursor)).messages).toHaveLength(0);
    await terminal.start();
    await terminal.waitFor('Incomplete group history', 0, 30000);
    await command('/group status', 'Recovery challenge:');
    const challenge = store.findConversation(id)!.groupSession!.recovery!.challenge;
    expect(challenge).toMatch(/^[a-f0-9]{64}$/);
    await command('blocked until recovery', 'Send failed');
    proof('04-recovery-required');
    await cli('contact', 'add', 'Alice', bytesToHex(store.loadIdentity()!.publicKey));
    const refresh = await cli('group', 'refresh', id, 'Alice', '--challenge', challenge);
    await command(`/join ${refresh.group_link}`, 'Opened group');
    expect(store.findConversation(id)!.groupSession!.recovery).toBeNull();
    await command('terminal recovered with a fresh welcome', 'You');
    await cli('recv', id);
    expect(bobRecord().group_history.some((row: any) => row.unsafe_body === 'terminal recovered with a fresh welcome')).toBe(true);
    proof('05-recovered');
  }, 150000);

  it('opens a late terminal joiner, then visibly blocks that terminal after removal', async () => {
    newcomer = new TuiAgent(join(root, 'newcomer'), relayUrl, python);
    await newcomer.start();
    await command(`/contact add Eve ${newcomer.readIdentity().public_key}`, 'Pinned contact Eve');
    await command('/group add Eve', 'Group add complete for Eve');
    const freshLink = (await store.groups.run(['group', 'link', id])).group_link;
    await command(`/group open ${freshLink}`, 'Opened group', newcomer);
    await command('late terminal joined', 'You', newcomer);
    await expect.poll(() => store.loadHistory(id).some(row => row.text === 'late terminal joined'), { timeout: 20000 }).toBe(true);
    await command('/group remove Eve', 'Group remove complete for Eve');
    await newcomer.waitFor('Removed from this group', 0, 30000);
    await command('removed terminal cannot send', 'Send failed', newcomer);
    const otherStore = new Store(newcomer.configDir, relayUrl);
    expect(otherStore.findConversation(id)!.groupSession!.removed).toBe(true);
    proof('06-removed-terminal', newcomer);
    await stopTerminal(newcomer); newcomer = undefined;
  }, 90000);
});
