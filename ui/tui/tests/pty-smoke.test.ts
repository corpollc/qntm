import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DropboxClient } from '@corpollc/qntm';
import { sendMessage } from '../src/lib/poller.js';
import { Store } from '../src/lib/store.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

const execFileAsync = promisify(execFile);
const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const TUI_DIR = resolve(TEST_DIR, '..');
const BUILT_ENTRY = resolve(TUI_DIR, 'dist/index.js');

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

async function runExpectSession(expectBody: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  const scratchDir = mkdtempSync(join(tmpdir(), 'qntm-tui-expect-'));
  const scriptPath = join(scratchDir, 'session.exp');
  writeFileSync(scriptPath, expectBody, 'utf8');
  try {
    return await execFileAsync('expect', [scriptPath, ...args], {
      cwd: TUI_DIR,
      maxBuffer: 10 * 1024 * 1024,
      env: {
        ...process.env,
        FORCE_COLOR: '0',
      },
    });
  } finally {
    unlinkSync(scriptPath);
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

async function runTuiForSeconds(configDir: string, relayUrl: string, seconds: number): Promise<{ stdout: string; stderr: string }> {
  const script = `
    set timeout ${Math.max(seconds + 5, 10)}
    lassign $argv node entry configDir relayUrl
    spawn env TERM=xterm-256color FORCE_COLOR=0 $node $entry --config-dir $configDir --relay-url $relayUrl
    sleep ${seconds}
    send -- "\\003"
    expect eof
  `;

  return await runExpectSession(script, [process.execPath, BUILT_ENTRY, configDir, relayUrl]);
}

describe('TUI PTY smoke', () => {
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

  it('runs the real terminal entry point under a PTY and prints help text', async () => {
    const helpScript = `
      set timeout 10
      lassign $argv node entry
      spawn $node $entry --help
      expect "qntm Messenger — Terminal client"
      expect -- "--relay-url <url>"
      expect "Slash commands (in chat):"
      expect eof
    `;

    const result = await runExpectSession(helpScript, [process.execPath, BUILT_ENTRY]);

    expect(result.stdout).toContain('qntm Messenger — Terminal client');
    expect(result.stdout).toContain('--config-dir <path>');
    expect(result.stdout).toContain('/invite [name]');
  });

  it('boots in a custom config directory and creates identity state', async () => {
    const configDir = makeTempDir('qntm-tui-pty-boot-');
    dirs.push(configDir);

    await runTuiForSeconds(configDir, relay.url, 3);

    const store = new Store(configDir, relay.url);
    const identity = store.loadIdentity();

    expect(identity).not.toBeNull();
    expect(identity!.keyID).toHaveLength(16);
  });

  it('polls an incoming message on startup and stores it in history', async () => {
    const aliceDir = makeTempDir('qntm-tui-pty-alice-');
    const bobDir = makeTempDir('qntm-tui-pty-bob-');
    dirs.push(aliceDir, bobDir);

    const aliceStore = new Store(aliceDir, relay.url);
    const bobStore = new Store(bobDir, relay.url);
    const aliceIdentity = aliceStore.generateIdentity();
    const bobIdentity = bobStore.generateIdentity();
    const { token, convId } = aliceStore.createInvite(aliceIdentity, 'PTy Poll');
    bobStore.acceptInvite(bobIdentity, token, 'PTY Poll');

    await sendMessage(
      bobStore,
      new DropboxClient(relay.url),
      bobIdentity,
      convId,
      'hello from bob',
    );

    await runTuiForSeconds(aliceDir, relay.url, 4);

    const history = aliceStore.loadHistory(convId);
    expect(history).toHaveLength(1);
    expect(history[0]?.direction).toBe('incoming');
    expect(history[0]?.text).toBe('hello from bob');
    expect(aliceStore.loadCursor(convId)).toBe(1);

    await waitFor(() => relay.messageCount(convId) === 0);
  });

  it('suppresses self-echoes during startup polling while still advancing the cursor', async () => {
    const aliceDir = makeTempDir('qntm-tui-pty-self-');
    dirs.push(aliceDir);

    const aliceStore = new Store(aliceDir, relay.url);
    const aliceIdentity = aliceStore.generateIdentity();
    const { convId } = aliceStore.createInvite(aliceIdentity, 'PTY Self');

    await sendMessage(
      aliceStore,
      new DropboxClient(relay.url),
      aliceIdentity,
      convId,
      'hello from alice',
    );

    expect(aliceStore.loadHistory(convId)).toHaveLength(1);
    expect(relay.messageCount(convId)).toBe(1);

    await runTuiForSeconds(aliceDir, relay.url, 4);

    const history = aliceStore.loadHistory(convId);
    expect(history).toHaveLength(1);
    expect(history[0]?.direction).toBe('outgoing');
    expect(history[0]?.text).toBe('hello from alice');
    expect(aliceStore.loadCursor(convId)).toBe(1);
    expect(relay.messageCount(convId)).toBe(1);
  });
});
