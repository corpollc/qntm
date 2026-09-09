import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';
import { StringDecoder } from 'node:string_decoder';

const repo = join(dirname(fileURLToPath(import.meta.url)), '../..');
const clean = (value: string) => value.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
const compact = (value: string) => value.replace(/[│\s]/g, '');
const composers = (text: string) => text.split('❯').slice(1).map(part => compact(part.split('└')[0]));
export class TuiAgent {
  process?: ChildProcessWithoutNullStreams;
  childPid?: number;
  output = '';
  stderr = '';
  constructor(readonly configDir: string, readonly relayUrl: string, private python = 'python3') {}
  async start(): Promise<void> {
    this.output = ''; this.stderr = ''; this.childPid = undefined;
    this.process = spawn(this.python, ['-u', join(repo, 'integration/src/tui-pty.py'), process.execPath, join(repo, 'ui/tui/dist/index.js'), '--config-dir', this.configDir, '--relay-url', this.relayUrl]);
    const decoder = new StringDecoder('utf8');
    createInterface({ input: this.process.stdout }).on('line', line => {
      const event = JSON.parse(line);
      if (typeof event.pid === 'number') this.childPid = event.pid;
      if (typeof event.output === 'string') this.output += decoder.write(Buffer.from(event.output, 'base64'));
    });
    this.process.stderr.on('data', chunk => { this.stderr += chunk; });
    await this.waitFor(/\[[0-9a-f]{12}\.\.\]/);
  }
  text(from = 0): string { return clean(this.output.slice(from)); }
  async waitFor(pattern: string | RegExp | ((text: string) => boolean), from = 0, timeout = 20000): Promise<string> {
    const until = Date.now() + timeout;
    while (Date.now() < until) {
      const value = this.text(from);
      if (typeof pattern === 'string' ? value.includes(pattern) : typeof pattern === 'function' ? pattern(value) : pattern.test(value)) return value;
      if (!this.process || this.process.exitCode !== null || this.process.signalCode !== null) throw new Error(`TUI exited: ${this.stderr}`);
      await delay(50);
    }
    throw new Error(`TUI did not show ${pattern}: ${this.text(from).slice(-4000)}`);
  }
  async command(value: string): Promise<number> {
    if (!value.trim() || /[\r\n]/.test(value)) throw new Error('PTY command must be one nonempty line');
    const from = this.output.length;
    this.process!.stdin.write(JSON.stringify({ write: value }) + '\n');
    // A busy Ink process can coalesce text + Return into a single paste. Wait
    // for its rendered composer, including wrapped invite tokens, not a timer.
    await this.waitFor(text => composers(text).includes(compact(value)), from);
    const submitted = this.output.length;
    this.process!.stdin.write(JSON.stringify({ write: '\r' }) + '\n');
    if (value.trim() !== '/quit') {
      await this.waitFor(text => composers(text).some(composer =>
        composer === 'Typeamessageor/help' || composer === '/helpforcommands'), submitted);
    }
    return from;
  }
  async review(command: string, confirm = true): Promise<string> {
    const from = await this.command(command);
    const shown = await this.waitFor(/Review .+page 1\/(\d+)/, from);
    const pages = Number(shown.match(/Review .+page 1\/(\d+)/)![1]);
    for (let page = 2; page <= pages; page++) {
      const next = await this.command(`/review ${page}`);
      await this.waitFor(`page ${page}/${pages}`, next);
    }
    const details = this.text(from);
    if (confirm) {
      const type = shown.match(/Review ([\w.]+)\s/)![1];
      const messages = () => (JSON.parse(readFileSync(join(this.configDir, 'conversations.json'), 'utf8')) as any[])
        .flatMap(conversation => conversation.messages ?? []);
      const previous = new Set(messages().map(message => message.id));
      const next = await this.command('/confirm');
      // Every Ink redraw contains earlier notices. Correlate completion with
      // this action's persisted envelope, never a generic historical "sent".
      await this.waitFor(text => messages().some(message =>
        message.direction === 'outgoing' && message.bodyType === type && !previous.has(message.id)
        && compact(text).includes(`Message${message.id}.`)), next);
    }
    return details;
  }
  readIdentity(): Record<string, string> { return JSON.parse(readFileSync(join(this.configDir, 'identity.json'), 'utf8')); }
  conversation(id: string): any { return JSON.parse(readFileSync(join(this.configDir, 'conversations.json'), 'utf8')).find((c: any) => c.id === id); }
  history(id: string): any[] { return this.conversation(id)?.messages ?? []; }
  async stop(): Promise<void> {
    if (!this.process || this.process.exitCode !== null) return;
    this.process.stdin.end();
    await Promise.race([once(this.process, 'exit'), delay(5000)]);
    if (this.process.exitCode === null) this.process.kill('SIGTERM');
  }
}
