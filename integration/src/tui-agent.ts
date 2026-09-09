import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';

const repo = join(dirname(fileURLToPath(import.meta.url)), '../..');
const clean = (value: string) => value.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
export class TuiAgent {
  process?: ChildProcessWithoutNullStreams;
  output = '';
  stderr = '';
  constructor(readonly configDir: string, readonly relayUrl: string, private python = 'python3') {}
  async start(): Promise<void> {
    this.output = ''; this.stderr = '';
    this.process = spawn(this.python, ['-u', join(repo, 'integration/src/tui-pty.py'), process.execPath, join(repo, 'ui/tui/dist/index.js'), '--config-dir', this.configDir, '--relay-url', this.relayUrl]);
    createInterface({ input: this.process.stdout }).on('line', line => { this.output += Buffer.from(JSON.parse(line).output, 'base64').toString('utf8'); });
    this.process.stderr.on('data', chunk => { this.stderr += chunk; });
    await this.waitFor(/\[[0-9a-f]{12}\.\.\]/);
  }
  text(from = 0): string { return clean(this.output.slice(from)); }
  async waitFor(pattern: string | RegExp, from = 0, timeout = 20000): Promise<string> {
    const until = Date.now() + timeout;
    while (Date.now() < until) {
      const value = this.text(from);
      if (typeof pattern === 'string' ? value.includes(pattern) : pattern.test(value)) return value;
      if (this.process?.exitCode !== null) throw new Error(`TUI exited: ${this.stderr}`);
      await delay(50);
    }
    throw new Error(`TUI did not show ${pattern}: ${this.text(from).slice(-4000)}`);
  }
  async command(value: string): Promise<number> {
    const from = this.output.length;
    this.process!.stdin.write(JSON.stringify({ write: value }) + '\n');
    await delay(120); // Let Ink commit the new composer value before Return.
    this.process!.stdin.write(JSON.stringify({ write: '\r' }) + '\n');
    await delay(120);
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
      const next = await this.command('/confirm');
      await this.waitFor(/sent\.|Invitation posted\./, next);
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
