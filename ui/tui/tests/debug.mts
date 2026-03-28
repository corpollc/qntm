import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { DropboxClient } from '@corpollc/qntm';
import { sendMessage } from './ui/tui/src/lib/poller.js';
import { Store } from './ui/tui/src/lib/store.js';
import { TestRelayServer } from './ui/tui/tests/support/relay.js';

const execAsync = promisify(execFile);

async function main() {
  const relay = new TestRelayServer();
  await relay.start();
  console.log('relay:', relay.url);

  const aliceDir = mkdtempSync(join(tmpdir(), 'qntm-dbg-alice-'));
  const bobDir = mkdtempSync(join(tmpdir(), 'qntm-dbg-bob-'));

  const aliceStore = new Store(aliceDir, relay.url);
  const bobStore = new Store(bobDir, relay.url);
  const aliceId = aliceStore.generateIdentity();
  const bobId = bobStore.generateIdentity();
  const { token, convId } = aliceStore.createInvite(aliceId, 'Debug Test');
  bobStore.acceptInvite(bobId, token, 'Debug Test');

  await sendMessage(bobStore, new DropboxClient(relay.url), bobId, convId, 'hello from bob');
  console.log('relay msgs:', relay.messageCount(convId));
  console.log('alice convs:', aliceStore.loadConversations().length);
  console.log('alice cursor before TUI:', aliceStore.loadCursor(convId));
  console.log('aliceDir:', aliceDir);
  console.log('convId:', convId);

  const BUILT_ENTRY = resolve('ui/tui/dist/index.js');

  const script = `
    set timeout 10
    lassign $argv node entry configDir relayUrl
    spawn env TERM=xterm-256color FORCE_COLOR=0 $node $entry --config-dir $configDir --relay-url $relayUrl
    sleep 4
    send -- "\\003"
    expect eof
  `;

  const scriptPath = join(aliceDir, 'run.exp');
  writeFileSync(scriptPath, script);

  try {
    const result = await execAsync('expect', [scriptPath, process.execPath, BUILT_ENTRY, aliceDir, relay.url], {
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, FORCE_COLOR: '0' },
    });
    console.log('STDOUT (last 500):', result.stdout.slice(-500));
    console.log('STDERR:', result.stderr.slice(0, 2000));
  } catch (e: any) {
    console.log('expect error:', e.message?.slice(0, 200));
    if (e.stderr) console.log('expect stderr:', e.stderr.slice(0, 2000));
    if (e.stdout) console.log('expect stdout (last 500):', e.stdout.slice(-500));
  }

  console.log('alice cursor after TUI:', aliceStore.loadCursor(convId));
  console.log('alice history after TUI:', aliceStore.loadHistory(convId).length);

  await relay.close();
  rmSync(aliceDir, { recursive: true, force: true });
  rmSync(bobDir, { recursive: true, force: true });
}
main().catch(e => console.error(e));
