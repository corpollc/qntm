/** Ordinary groups use the Python receiver and its locked, atomic profile.
 * The terminal only projects persisted results; it never rewrites checkpoints.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import { validateIdentity } from '@corpollc/qntm';
import type { StoredConversation, StoredMessage } from './store.js';

const execute = promisify(execFile);
type Json = Record<string, any>;
export interface GroupSubscription { close(): void }
const liveReceivers = new Set<GroupSubscription>();
/** Called before Ink exits: React cleanup can be deferred past process exit. */
export function stopGroupReceivers(): void {
  for (const receiver of [...liveReceivers]) receiver.close();
}
export interface GroupWatchCallbacks {
  onChange(): void;
  onStatus(connected: boolean, error?: string): void;
}
const read = (filename: string, fallback: any): any => fs.existsSync(filename)
  ? JSON.parse(fs.readFileSync(filename, 'utf8')) : fallback;

export function groupNotice(record?: StoredConversation | null): string {
  if (!record?.managedGroup) return '';
  const state = record.groupSession;
  if (state?.removed) return 'Removed from this group. Sending is disabled.';
  if (state?.recovery) return 'Incomplete group history. Sending is paused; /group status shows your recovery challenge.';
  if (record.groupOperation) return 'Group operation pending. Sending is paused; use /group retry.';
  if (state?.needsRekey) return 'Membership needs fresh keys. Sending is paused; use /group rekey.';
  if (!state) return 'Group setup is incomplete. Sending is paused; use /group retry.';
  return '';
}

export class GroupBridge {
  readonly profileDir: string;
  private available?: Promise<void>;
  private watches = new Map<string, { done: Promise<void>; close(): void }>();
  constructor(readonly configDir: string, readonly relayUrl: string) {
    this.profileDir = path.join(configDir, 'contact-groups');
  }

  private identity(): Json {
    const raw = read(path.join(this.configDir, 'identity.json'), null);
    if (!raw) throw new Error('No terminal identity loaded.');
    const bytes = (value: string) => {
      if (typeof value !== 'string' || !/^(?:[a-fA-F0-9]{2})+$/.test(value)) throw new Error('Invalid saved identity');
      return new Uint8Array(Buffer.from(value, 'hex'));
    };
    validateIdentity({ privateKey: bytes(raw.private_key), publicKey: bytes(raw.public_key), keyID: bytes(raw.key_id) });
    return raw;
  }

  private ensureProfile(): void {
    const identity = this.identity();
    fs.mkdirSync(this.profileDir, { recursive: true, mode: 0o700 });
    fs.chmodSync(this.profileDir, 0o700);
    const filename = path.join(this.profileDir, 'identity.json');
    try { fs.writeFileSync(filename, JSON.stringify(identity) + '\n', { flag: 'wx', mode: 0o600 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const saved = read(filename, null);
    if (!saved || ['private_key', 'public_key', 'key_id'].some(field => saved[field] !== identity[field])) {
      throw new Error('Contact-group identity differs from the terminal identity. Restore the matching profile before continuing.');
    }
  }

  private executable(): string { return process.env.QNTM_TUI_PYTHON || 'python3'; }

  private checkAvailable(): Promise<void> {
    if (!this.available) this.available = execute(this.executable(), ['-c',
      [
        'import inspect',
        'from qntm.group_client import GroupClient',
        'from qntm.group_session import group_session_from_welcome, prepare_group_welcome_refresh, check_group_welcome_replay, check_group_unverifiable_epoch',
        'from qntm.watch import GROUP_RECEIVE_CONTRACT_VERSION',
        'assert "challenge" in inspect.signature(GroupClient.refresh).parameters',
        'assert "release_unproven" in inspect.signature(GroupClient.retry).parameters',
        'assert "replay_from_sequence" in inspect.signature(prepare_group_welcome_refresh).parameters',
        'assert GROUP_RECEIVE_CONTRACT_VERSION == 1',
      ].join('\n'),
    ], { timeout: 15000, maxBuffer: 65536 }).then(() => {}).catch(() => {
      this.available = undefined;
      throw new Error('Contact groups require the matching qntm Python package. Install python-dist from this checkout and set QNTM_TUI_PYTHON to its Python executable; see ui/tui/README.md.');
    });
    return this.available;
  }

  private arguments(args: string[]): string[] {
    // Locate the conversation positional, never a matching string in message
    // text or a contact name. Flags may precede `--` and the conversation ID.
    const scoped = args[0] === 'group' || args[0] === 'convo';
    const positional = args.slice(scoped ? 2 : 1);
    let id: string | undefined;
    for (let i = 0; i < positional.length; i++) {
      if (positional[i] === '--') { id = positional[i + 1]; break; }
      if (['--challenge', '--reason'].includes(positional[i])) { i++; continue; }
      if (positional[i] === '--release-unproven') continue;
      if (!positional[i].startsWith('--')) { id = positional[i]; break; }
    }
    if (args[0] === 'contact' || (args[0] === 'group' && ['create', 'join'].includes(args[1]))) id = undefined;
    const relay = this.rawRecords().find(row => row.id === id)?.relay_url || this.relayUrl;
    return ['-m', 'qntm', '--config-dir', this.profileDir, '--dropbox-url', relay, ...args];
  }

  async run(args: string[]): Promise<Json> {
    this.ensureProfile();
    await this.checkAvailable();
    let output: string;
    try {
      output = (await execute(this.executable(), this.arguments(args), { timeout: 60000, maxBuffer: 8 << 20 })).stdout;
    } catch (error) {
      const failed = error as { stderr?: string; killed?: boolean };
      const lines = (failed.stderr || '').trim().split('\n');
      for (const line of lines.reverse()) {
        try { const result = JSON.parse(line); if (typeof result.error === 'string') throw new Error(result.error); }
        catch (parsed) { if (parsed instanceof Error && !(parsed instanceof SyntaxError)) throw parsed; }
      }
      throw new Error(failed.killed ? 'Group command timed out. Check /group status and use /group retry for a pending operation.' : 'Group command failed. Check the matching Python installation and local profile.');
    }
    const result = JSON.parse(output);
    if (result.ok !== true || !result.data) throw new Error('Unexpected response from the group client.');
    return result.data;
  }

  private rawRecords(): Json[] {
    const rows = read(path.join(this.profileDir, 'conversations.json'), []);
    if (!Array.isArray(rows)) throw new Error('Invalid contact-group profile');
    return rows;
  }

  conversations(): StoredConversation[] {
    const rows = this.rawRecords();
    if (!rows.length) return [];
    const kid = this.identity().key_id;
    const saved = read(path.join(this.profileDir, 'identity.json'), null);
    if (saved?.key_id !== kid || saved?.public_key !== this.identity().public_key) throw new Error('Contact-group identity differs from the terminal identity.');
    return rows.map(row => ({
      id: row.id, name: row.name, type: row.type,
      keys: { root: row.keys.root, aeadKey: row.keys.aead_key, nonceKey: row.keys.nonce_key },
      participants: row.participants, createdAt: row.created_at, currentEpoch: row.current_epoch,
      managedGroup: true, groupSession: row.group_session, groupOperation: row.group_operation?.kind,
      relayUrl: row.relay_url || this.relayUrl, cursor: row.group_cursor || 0,
      messages: this.projectHistory(row, kid),
    }));
  }

  private projectHistory(row: Json, kid: string): StoredMessage[] {
    const history: Json[] = row.group_history || read(path.join(this.profileDir, 'chats', row.id + '.json'), []);
    return history.map(message => {
      const self = message.sender_kid === kid || message.direction === 'outgoing';
      const body = message.system_message || message.unsafe_body || (message.unsafe_body_b64 ? '[binary message]' : '');
      return { id: message.msg_id, conversationId: row.id, direction: self ? 'outgoing' : 'incoming',
        sender: self ? 'You' : message.sender_kid, senderKey: message.sender_kid || kid,
        bodyType: message.body_type, text: typeof body === 'string' ? body : JSON.stringify(body),
        createdAt: new Date(message.created_ts * 1000).toISOString() };
    });
  }

  status(id: string): string {
    const record = this.conversations().find(row => row.id === id);
    if (!record) throw new Error('Select a contact group first.');
    const state = record.groupSession;
    const parts = [groupNotice(record) || 'Group state is ready. Sends recheck the relay before posting.',
      `Group: ${id}`, `Epoch: ${record.currentEpoch}; members: ${record.participants.length}`, `Relay: ${record.relayUrl}`];
    if (state?.recovery) parts.push(`Missing history after sequence ${state.recovery.afterSequence} (${state.recovery.reason}).`,
      `Recovery challenge: ${state.recovery.challenge}`,
      'Send this challenge to a current member through your existing contact channel. They use /group refresh <your-contact> --challenge <challenge>, then you /join their returned public link. A refresh cannot undo removal.');
    if (record.groupOperation) parts.push(`Saved operation: ${record.groupOperation}; /group retry checks current group state before continuing.`);
    return parts.join('\n');
  }

  watch(id: string, callbacks: GroupWatchCallbacks): GroupSubscription {
    const previous = this.watches.get(id);
    previous?.close();
    let finish!: () => void;
    const done = new Promise<void>(resolve => { finish = resolve; });
    let stopped = false;
    let child: ReturnType<typeof spawn> | undefined;
    let watcher: fs.FSWatcher | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = () => {
      if (stopped || timer) return;
      timer = setTimeout(() => { timer = undefined; if (!stopped) callbacks.onChange(); }, 20);
    };
    void (async () => {
      await previous?.done;
      this.ensureProfile();
      await this.checkAvailable();
      if (stopped) { finish(); return; }
      watcher = fs.watch(this.profileDir, (_event, filename) => { if (filename === 'conversations.json') refresh(); });
      child = spawn(this.executable(), this.arguments(['recv', id, '--watch']), { stdio: ['ignore', 'pipe', 'pipe'] });
      createInterface({ input: child.stdout! }).on('line', () => refresh());
      createInterface({ input: child.stderr! }).on('line', line => {
        if (stopped) return;
        try {
          const result = JSON.parse(line);
          if (result.kind === 'recv.status') callbacks.onStatus(['ready', 'recovery_required'].includes(result.data.state));
          if (result.ok === false) callbacks.onStatus(false, result.error || 'Group receiver stopped.');
        } catch { /* Raw interpreter output is not chat content. */ }
        refresh();
      });
      child.on('error', () => { finish(); if (!stopped) callbacks.onStatus(false, 'Group receiver could not start.'); });
      child.on('exit', () => { finish(); if (!stopped) callbacks.onStatus(false, 'Group receiver stopped. Restart the terminal to reconnect.'); });
    })().catch(error => { finish(); if (!stopped) callbacks.onStatus(false, error instanceof Error ? error.message : 'Group receiver failed.'); });
    const subscription = { done, close: () => {
      liveReceivers.delete(subscription);
      stopped = true; watcher?.close(); if (timer) clearTimeout(timer);
      child?.kill('SIGTERM');
      if (child) { const processToStop = child; const force = setTimeout(() => {
        if (processToStop.exitCode === null && processToStop.signalCode === null) processToStop.kill('SIGKILL');
      }, 5000); force.unref(); }
    } };
    this.watches.set(id, subscription);
    liveReceivers.add(subscription);
    void done.then(() => { liveReceivers.delete(subscription); if (this.watches.get(id) === subscription) this.watches.delete(id); });
    return subscription;
  }
}

/** Quotes group contact names and paths without executing shell syntax. */
export function splitGroupArguments(value: string): string[] {
  const result: string[] = [];
  let word = '', quote = '', started = false;
  for (const character of value) {
    if (quote) { if (character === quote) quote = ''; else word += character; started = true; }
    else if (character === '"' || character === "'") { quote = character; started = true; }
    else if (/\s/.test(character)) { if (started) { result.push(word); word = ''; started = false; } }
    else { word += character; started = true; }
  }
  if (quote) throw new Error('Close the quoted contact name.');
  if (started) result.push(word);
  return result;
}
