/** Actual packaged OpenClaw host with a deterministic loopback model fixture. */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { generateIdentity, serializeIdentity, base64UrlEncode, type GatewaySessionState } from '@corpollc/qntm';
import { stagePlugin } from '../../openclaw-qntm/scripts/package.mjs';
import { createToolProvider, type ToolPlan, type ToolResult } from '../../openclaw-qntm/tests/support/tool-provider.mjs';
import { getFreePort, waitForCliHistory, type HistoryAgent } from './runtime.js';

// Resolve from the installed adapter's SDK, not from an alternate global host.
const adapterRequire = createRequire(new URL('../../openclaw-qntm/package.json', import.meta.url));
const host = fileURLToPath(new URL('../../openclaw.mjs', pathToFileURL(adapterRequire.resolve('openclaw/plugin-sdk/channel-core'))));
export class OpenClawAgent {
  readonly identity = generateIdentity();
  readonly stateDir: string;
  readonly configPath: string;
  log = '';
  private child?: ReturnType<typeof spawn>;
  private env: NodeJS.ProcessEnv;
  private provider!: Awaited<ReturnType<typeof createToolProvider>>;
  constructor(readonly rootDir: string, readonly conversationId: string) {
    if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('OpenClaw acceptance requires Node 24.16+ or 26.1+');
    this.stateDir = join(rootDir, 'state'); this.configPath = join(this.stateDir, 'openclaw.json');
    this.env = { ...process.env };
    for (const key of Object.keys(this.env)) {
      if (key.startsWith('OPENCLAW_') || key.startsWith('VITEST') || /(API_KEY|ACCESS_TOKEN|AUTH_TOKEN)$/.test(key)) delete this.env[key];
    }
    Object.assign(this.env, { NODE_ENV: 'production', PATH: `${dirname(process.execPath)}:${process.env.PATH}`, OPENCLAW_STATE_DIR: this.stateDir,
      OPENCLAW_CONFIG_PATH: this.configPath, OPENCLAW_SKIP_GMAIL_WATCHER: '1', OPENCLAW_SKIP_CANVAS_HOST: '1' });
  }
  private kill(child: ReturnType<typeof spawn>, signal: NodeJS.Signals): void {
    if (!child.pid) return;
    try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, signal); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
  }
  private command(command: string, args: string[], cwd = this.rootDir): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, { cwd, env: this.env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '', errors = '';
      const timeout = setTimeout(() => this.kill(child, 'SIGKILL'), 180_000);
      child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { errors += data; });
      child.once('error', error => { clearTimeout(timeout); reject(error); });
      child.once('exit', code => { clearTimeout(timeout); this.log += errors; code === 0 ? resolve(output) : reject(new Error(`OpenClaw test command exited ${code}\n${output}\n${errors}`)); });
    });
  }
  async configure(relayUrl: string, token: string): Promise<void> {
    await mkdir(this.stateDir, { recursive: true, mode: 0o700 });
    this.provider = await createToolProvider();
    const stage = join(this.rootDir, 'plugin'); await stagePlugin(stage);
    const config = {
      gateway: { mode: 'local', bind: 'loopback', port: await getFreePort(), auth: { mode: 'token', token: 'disposable-cross-client-test-token' } },
      agents: { defaults: { workspace: join(this.rootDir, 'workspace'), model: { primary: 'qntm-fixture/fixture' }, thinkingDefault: 'off', models: { 'qntm-fixture/fixture': {} } } },
      models: { providers: { 'qntm-fixture': { baseUrl: this.provider.url, apiKey: 'disposable-loopback-provider-key', api: 'openai-completions',
        models: [{ id: 'fixture', name: 'qntm test fixture', reasoning: false, input: ['text'], contextWindow: 200000, maxTokens: 4096,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } },
      session: { dmScope: 'per-account-channel-peer', store: join(this.stateDir, 'test-sessions.json') },
      tools: { alsoAllow: ['qntm_gateway'] }, plugins: { enabled: true, allow: ['qntm'] },
    };
    await writeFile(this.configPath, JSON.stringify(config), { mode: 0o600 });
    const [artifact] = JSON.parse(await this.command('npm', ['pack', '--json', '--pack-destination', this.rootDir], stage));
    await this.command(process.execPath, [host, 'plugins', 'install', '--force', '--accept-capabilities', join(this.rootDir, artifact.filename)]);
    const installed = JSON.parse(await readFile(this.configPath, 'utf8'));
    installed.channels = { qntm: { identity: base64UrlEncode(serializeIdentity(this.identity)), relayUrl, conversations: { test: {
      invite: token, name: 'OpenClaw cross-client acceptance', trigger: 'mention', triggerNames: ['gateway-tool-smoke:'],
      gatewayActions: ['invite', 'request', 'approve', 'disapprove', 'secret', 'propose', 'gov-approve', 'gov-disapprove'],
    } } } };
    await writeFile(this.configPath, JSON.stringify(installed), { mode: 0o600 });
    const doctor = await this.command(process.execPath, [host, 'plugins', 'doctor']);
    if (!doctor.includes('checks passed')) throw new Error(`${doctor}\n${this.log}`);
  }
  async start(): Promise<void> {
    if (this.child && this.child.exitCode === null && this.child.signalCode === null) throw new Error('Test host is already live');
    const from = this.log.length;
    this.child = spawn(process.execPath, [host, 'gateway', 'run'], { cwd: this.rootDir, env: this.env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    this.child.stdout!.on('data', data => { this.log += data; }); this.child.stderr!.on('data', data => { this.log += data; });
    await this.waitFor(() => this.log.slice(from).includes('[gateway] ready'), 'OpenClaw startup');
  }
  async waitFor(predicate: () => boolean | Promise<boolean>, description: string, timeout = 60_000): Promise<void> {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (this.provider.failures.length) throw new Error(this.provider.failures.join('\n'));
      if (this.child && (this.child.exitCode !== null || this.child.signalCode !== null)) throw new Error(`OpenClaw exited\n${this.log}`);
      if (await predicate()) return;
      await delay(100);
    }
    throw new Error(`Timed out: ${description}\n${this.log}`);
  }
  async checkpoint(): Promise<{ cursor: number; conversation: { currentEpoch: number }; session: GatewaySessionState } | undefined> {
    try { return JSON.parse(await readFile(join(this.stateDir, 'plugins/qntm/accounts/default/conversations', `${this.conversationId}.json`), 'utf8')); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  }
  async journey(peer: HistoryAgent, plan: ToolPlan, beforePrepare?: () => Promise<void>): Promise<ToolResult[]> {
    if (this.provider.outcomes.has(plan.id)) throw new Error('Duplicate test journey ID');
    if (beforePrepare) this.provider.beforePrepare.set(plan.id, beforePrepare);
    const marker = 'gateway-tool-smoke:' + Buffer.from(JSON.stringify(plan)).toString('base64url');
    const sent = await peer.run(['send', this.conversationId, marker]);
    if (!sent.ok) throw new Error(sent.error);
    await this.waitFor(() => this.provider.outcomes.has(plan.id), `native gateway tool: ${plan.id}`);
    await waitForCliHistory(peer, this.conversationId, entry => entry.unsafe_body === `gateway-tool-complete:${plan.id}`, 'native agent turn completion');
    return this.provider.outcomes.get(plan.id)!;
  }
  async stop(signal: NodeJS.Signals = 'SIGTERM'): Promise<void> {
    const child = this.child;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const exit = new Promise<void>(resolve => child.once('exit', () => resolve())); this.kill(child, signal);
    const timer = setTimeout(() => this.kill(child, 'SIGKILL'), 10_000);
    try { await exit; } finally { clearTimeout(timer); }
  }
  async close(): Promise<void> { await this.stop(); await this.provider?.close(); }
}
