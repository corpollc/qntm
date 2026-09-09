import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { promisify, stripVTControlCharacters } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import type { Browser, BrowserContext, Page } from 'playwright';
import { chromium } from 'playwright';
import { GateClient } from '@corpollc/qntm';
import { TslibAgent } from './ts-agent.js';

const execFileAsync = promisify(execFile);
const EXEC_MAX_BUFFER = 10 * 1024 * 1024;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const RETRY_INTERVAL_MS = 250;
const RATE_LIMIT_RETRY_MS = 500;
const GATEWAY_POLL_INTERVAL_MS = 250;

export interface JsonResult {
  ok: boolean;
  kind: string;
  data?: Record<string, unknown>;
  error?: string;
}

export interface HistoryAgent {
  name: string;
  run(args: string[], extraEnv?: Record<string, string>): Promise<JsonResult>;
  readHistory(convId: string): Array<Record<string, unknown>>;
}

export interface ConversationAgent extends HistoryAgent {
  readConversation(convId: string): Record<string, unknown>;
}

export async function waitForHttp(url: string, init?: RequestInit, timeoutMs = 30_000): Promise<void> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Readiness timeout must be positive');
  const deadline = performance.now() + timeoutMs;
  let lastFailure = 'no response';
  let lastStatus: number | undefined;
  while (performance.now() < deadline) {
    init?.signal?.throwIfAborted();
    const timeout = AbortSignal.timeout(Math.max(1, Math.ceil(Math.min(1_000, deadline - performance.now()))));
    try {
      const response = await fetch(url, {
        ...init,
        redirect: 'manual',
        signal: init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout,
      });
      lastStatus = response.status;
      await response.body?.cancel();
      if (response.ok) return;
      lastFailure = `HTTP ${response.status}`;
    } catch (error) {
      init?.signal?.throwIfAborted();
      lastFailure = error instanceof Error ? error.message : String(error);
    }
    const remaining = deadline - performance.now();
    if (remaining > 0) await delay(Math.ceil(Math.min(250, remaining)), undefined, { signal: init?.signal ?? undefined });
  }
  throw new Error(`Timed out waiting for ${url}: ${lastFailure}${lastStatus === undefined ? '' : ` (last response: HTTP ${lastStatus})`}`);
}

// Best-effort selection for hosts requiring preconfigured nonzero ports.
// Prefer --port 0 and waitForLocalUrl when the server supports it.
// Keep the whole batch bound while allocating. Releasing each port before
// choosing the next can give a Worker and its inspector the same port.
// Callers must still start promptly: another process can bind after release.
export async function getFreePorts(count: number): Promise<number[]> {
  if (!Number.isInteger(count) || count < 1) throw new Error('Port count must be a positive integer');
  const servers: Server[] = [];
  const ports: number[] = [];
  try {
    for (let index = 0; index < count; index++) {
      const server = createServer();
      servers.push(server);
      await new Promise<void>((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolveListen);
      });
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Failed to allocate port');
      ports.push(address.port);
    }
    return ports;
  } finally {
    await Promise.all(servers.filter(server => server.listening).map(server => new Promise<void>((resolveClose, reject) => {
      server.close(error => error ? reject(error) : resolveClose());
    })));
  }
}

export async function getFreePort(): Promise<number> {
  return (await getFreePorts(1))[0];
}

// Scope Wrangler discovery to the fixture so concurrent tests and developers'
// local Workers cannot replace one another in the shared registry.
export function workerTestEnv(rootDir: string): NodeJS.ProcessEnv {
  return { ...process.env, WRANGLER_REGISTRY_PATH: join(rootDir, 'registry') };
}

function parseCliJson(stdout: string, stderr: string, command: string[]): JsonResult {
  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new Error(`No CLI output for ${command.join(' ')}\nstderr:\n${stderr}`);
  }
  try {
    return JSON.parse(trimmed) as JsonResult;
  } catch (error) {
    throw new Error(`Failed to parse CLI output for ${command.join(' ')}\nstdout:\n${stdout}\nstderr:\n${stderr}\n${String(error)}`);
  }
}

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

export class ManagedProcess {
  readonly name: string;
  readonly command: string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  child: ReturnType<typeof spawn>;
  stdout = '';
  stderr = '';
  private stdoutStart = 0;
  private stderrStart = 0;
  private spawnError: Error | undefined;

  constructor(name: string, command: string[], cwd: string, env: NodeJS.ProcessEnv) {
    this.name = name;
    this.command = command;
    this.cwd = cwd;
    this.env = env;
    this.child = this.start();
  }

  private start(): ReturnType<typeof spawn> {
    this.stdoutStart = this.stdout.length;
    this.stderrStart = this.stderr.length;
    this.spawnError = undefined;
    const [cmd, ...args] = this.command;
    const child = spawn(cmd, args, {
      cwd: this.cwd,
      env: this.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      this.stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      this.stderr += chunk.toString();
    });
    child.once('error', error => { this.spawnError = error; });
    return child;
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null) return;
    this.child.kill('SIGTERM');
    await Promise.race([
      new Promise<void>((resolveExit) => {
        this.child.once('exit', () => resolveExit());
      }),
      delay(5_000).then(() => {
        if (this.child.exitCode === null) this.child.kill('SIGKILL');
      }),
    ]);
  }

  async restart(): Promise<void> {
    await this.stop();
    this.stdout += '\n--- restarted ---\n';
    this.stderr += '\n--- restarted ---\n';
    this.child = this.start();
  }

  async waitForHttp(url: string, init?: RequestInit, timeoutMs = 30_000): Promise<void> {
    try {
      await waitForHttp(url, init, timeoutMs);
    } catch (error) {
      throw new Error(`${this.name} failed readiness: ${String(error)}\nstdout:\n${this.stdout.slice(-8_192)}\nstderr:\n${this.stderr.slice(-8_192)}`, { cause: error });
    }
  }

  /** Discover the socket the server actually bound with --port 0, then check
   * HTTP health. Keep that port for explicit restarts at the same endpoint. */
  async waitForLocalUrl(kind: 'worker' | 'vite', healthPath = '/', timeoutMs = 30_000): Promise<string> {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Readiness timeout must be positive');
    const deadline = performance.now() + timeoutMs;
    const pattern = kind === 'worker'
      ? /Ready on (http:\/\/127\.0\.0\.1:(\d+))\/?[ \t]*\r?\n/
      : /Local:[ \t]+(http:\/\/127\.0\.0\.1:(\d+))\/?[ \t]*\r?\n/;
    try {
      while (performance.now() < deadline) {
        if (this.spawnError) throw this.spawnError;
        if (this.child.exitCode !== null || this.child.signalCode !== null) throw new Error('Process exited before readiness');
        const match = pattern.exec(stripVTControlCharacters(this.stdout.slice(this.stdoutStart)))
          ?? pattern.exec(stripVTControlCharacters(this.stderr.slice(this.stderrStart)));
        if (match) {
          const port = Number(match[2]);
          if (port < 1 || port > 65535) throw new Error('Server reported an invalid listener port');
          await waitForHttp(`${match[1]}${healthPath}`, undefined, Math.max(1, deadline - performance.now()));
          const portArg = this.command.indexOf('--port');
          if (portArg >= 0 && this.command[portArg + 1] === '0') this.command[portArg + 1] = String(port);
          return match[1];
        }
        await delay(Math.max(1, Math.min(50, deadline - performance.now())));
      }
      throw new Error('Timed out waiting for the bound local listener');
    } catch (error) {
      throw new Error(`${this.name} failed readiness: ${String(error)}\nstdout:\n${this.stdout.slice(-8_192)}\nstderr:\n${this.stderr.slice(-8_192)}`, { cause: error });
    }
  }
}

function npmCommand(): string {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function npxCommand(): string {
  return process.platform === 'win32' ? 'npx.cmd' : 'npx';
}

export class CliAgent {
  readonly name: string;
  readonly configDir: string;
  readonly qntmBin: string;
  private readonly relayUrl: string;
  private readonly recipeCatalogPath: string;
  private readonly repoRoot: string;

  constructor(name: string, qntmBin: string, relayUrl: string, recipeCatalogPath: string, repoRoot: string, baseDir: string) {
    this.name = name;
    this.qntmBin = qntmBin;
    this.relayUrl = relayUrl;
    this.recipeCatalogPath = recipeCatalogPath;
    this.repoRoot = repoRoot;
    this.configDir = join(baseDir, name);
    mkdirSync(this.configDir, { recursive: true });
  }

  async run(args: string[], extraEnv: Record<string, string> = {}): Promise<JsonResult> {
    const command = [
      '--config-dir', this.configDir,
      '--dropbox-url', this.relayUrl,
      ...args,
    ];
    const { stdout, stderr } = await execFileAsync(this.qntmBin, command, {
      cwd: this.repoRoot,
      env: {
        ...process.env,
        QNTM_RECIPE_CATALOG_PATH: this.recipeCatalogPath,
        ...extraEnv,
      },
      maxBuffer: EXEC_MAX_BUFFER,
    });
    const parsed = parseCliJson(stdout, stderr, [this.qntmBin, ...command]);
    if (!parsed.ok) {
      throw new Error(`CLI command failed: ${JSON.stringify(parsed)}`);
    }
    return parsed;
  }

  start(args: string[]): ManagedProcess {
    return new ManagedProcess(`${this.name}-watch`, [this.qntmBin,
      '--config-dir', this.configDir, '--dropbox-url', this.relayUrl, ...args],
    this.repoRoot, { ...process.env, QNTM_RECIPE_CATALOG_PATH: this.recipeCatalogPath });
  }

  readIdentity(): Record<string, string> {
    return JSON.parse(readFileSync(join(this.configDir, 'identity.json'), 'utf8')) as Record<string, string>;
  }

  readConversations(): Array<Record<string, unknown>> {
    const path = join(this.configDir, 'conversations.json');
    if (!existsSync(path)) return [];
    return JSON.parse(readFileSync(path, 'utf8')) as Array<Record<string, unknown>>;
  }

  readConversation(convId: string): Record<string, unknown> {
    const conversation = this.readConversations().find((entry) => String(entry.id).toLowerCase() === convId.toLowerCase());
    if (!conversation) {
      throw new Error(`Conversation ${convId} not found for ${this.name}`);
    }
    return conversation;
  }

  readHistory(convId: string): Array<Record<string, unknown>> {
    const path = join(this.configDir, 'chats', `${convId}.json`);
    if (!existsSync(path)) return [];
    const rawEntries = JSON.parse(readFileSync(path, 'utf8')) as Array<Record<string, unknown>>;
    return rawEntries.map((entry) => {
      const messageId = entry.message_id ?? entry.msg_id;
      return messageId === undefined
        ? { ...entry }
        : { ...entry, message_id: messageId };
    });
  }
}

async function ensureChromiumInstalled(integrationDir: string): Promise<void> {
  const executablePath = chromium.executablePath();
  if (executablePath && existsSync(executablePath)) {
    return;
  }
  await execFileAsync(npxCommand(), ['playwright', 'install', 'chromium'], {
    cwd: integrationDir,
    env: { ...process.env },
    maxBuffer: EXEC_MAX_BUFFER,
  });
}

export class AimUiAgent {
  readonly context: BrowserContext;
  readonly page: Page;
  readonly baseUrl: string;

  private constructor(context: BrowserContext, page: Page, baseUrl: string) {
    this.context = context;
    this.page = page;
    this.baseUrl = baseUrl;
  }

  static async launch(browser: Browser, baseUrl: string, relayUrl: string): Promise<AimUiAgent> {
    const context = await browser.newContext();
    await context.addInitScript((dropboxUrl: string) => {
      window.localStorage.setItem('aim-store', JSON.stringify({ dropboxUrl }));
    }, relayUrl);
    const page = await context.newPage();
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    return new AimUiAgent(context, page, baseUrl);
  }

  async close(): Promise<void> {
    await this.context.close();
  }

  async ensurePanel(title: string): Promise<void> {
    const header = this.page.locator('.collapsible-header', { hasText: title }).first();
    if ((await header.getAttribute('aria-expanded')) !== 'true') {
      await header.click();
    }
  }

  async generateIdentity(): Promise<void> {
    await this.ensurePanel('Profile');
    await this.page.locator('.pubkey-value').waitFor({ state: 'visible', timeout: 10_000 });
  }

  async joinConversation(token: string, label: string): Promise<void> {
    await this.ensurePanel('Invites');
    await this.page.getByPlaceholder('Paste an invite link or token').fill(token);
    await this.page.getByPlaceholder('Label for this conversation (optional)').fill(label);
    await this.page.getByRole('button', { name: 'Join' }).click();
    await this.waitForConversation(label);
  }

  async waitForConversation(label: string, timeoutMs = 15_000): Promise<void> {
    const byLabel = this.page.getByRole('button', { name: new RegExp(label) });
    const anyConversation = this.page.locator('.conversation-select').first();
    try {
      await byLabel.waitFor({ timeout: timeoutMs });
      return;
    } catch {
      await Promise.race([
        this.page.getByText('Joined successfully!').waitFor({ timeout: timeoutMs }),
        anyConversation.waitFor({ timeout: timeoutMs }),
      ]);
    }
  }

  async selectConversation(label: string): Promise<void> {
    await this.ensurePanel('Conversations');
    const matching = this.page.locator('.conversation-select', { hasText: label }).first();
    if (await matching.count()) {
      await matching.click();
      return;
    }
    await this.page.locator('.conversation-select').first().click();
  }

  async openGatewayPanel(): Promise<void> {
    const panel = this.page.locator('.gate-panel').first();
    if (await panel.count() > 0 && await panel.isVisible()) {
      return;
    }
    await this.page.getByRole('button', { name: /API Gateway/ }).click();
    await panel.waitFor({ state: 'visible', timeout: 10_000 });
  }

  async enableGateway(gatewayUrl: string, threshold: number): Promise<void> {
    await this.openGatewayPanel();
    await this.page.locator('#gate-promote-url').fill(gatewayUrl);
    await this.page.locator('#gate-promote-threshold').fill(String(threshold));
    await this.page.getByRole('button', { name: 'Invite API Gateway' }).click();
    await this.page.getByText('API Gateway Active').waitFor({ timeout: 15_000 });
  }

  async addApiKey(
    service: string,
    value: string,
    headerName = 'Authorization',
    headerTemplate = 'Bearer {value}',
  ): Promise<void> {
    await this.openGatewayPanel();
    await this.ensurePanel('API Keys');
    await this.page.locator('#secret-service').fill(service);
    await this.page.locator('#secret-header-name').fill(headerName);
    await this.page.locator('#secret-header-template').fill(headerTemplate);
    await this.page.locator('#secret-value').fill(value);
    await this.page.getByRole('button', { name: 'Add API key' }).click();
  }

  async submitGateRequest(recipeName: string, args: Record<string, string> = {}): Promise<void> {
    await this.openGatewayPanel();
    await this.ensurePanel('API Request');
    await this.page.locator('#gate-recipe').selectOption(recipeName);
    for (const [key, value] of Object.entries(args)) {
      const selectors = [
        `#gate-path-${key}`,
        `#gate-query-${key}`,
        `#gate-body-${key}`,
      ];
      let filled = false;
      for (const selector of selectors) {
        const locator = this.page.locator(selector);
        if (await locator.count() > 0) {
          await locator.fill(value);
          filled = true;
          break;
        }
      }
      if (!filled) {
        throw new Error(`No AIM gate input found for argument ${key}`);
      }
    }
    await this.page.getByRole('button', { name: 'Submit API request' }).click();
  }

  async countRequestCardsContaining(text: string): Promise<number> {
    return await this.page.locator('.gate-card.gate-request', { hasText: text }).count();
  }

  async sendText(text: string): Promise<void> {
    await this.page.locator('.composer input').fill(text);
    await this.page.getByRole('button', { name: 'Send' }).click();
  }

  async approveLatestRequest(): Promise<void> {
    const card = this.page.locator('.gate-card.gate-request').last();
    await card.getByRole('button', { name: 'Approve' }).click();
  }

  async rejectLatestRequest(): Promise<void> {
    const card = this.page.locator('.gate-card.gate-request').last();
    await card.getByRole('button', { name: 'Deny' }).click();
  }

  async approveLatestProposal(): Promise<void> {
    const card = this.page.locator('.gate-card', { hasText: 'Governance Proposal' }).last();
    await card.getByRole('button', { name: 'Approve' }).click();
  }

  async hasText(text: string): Promise<boolean> {
    return (await this.page.getByText(text, { exact: false }).count()) > 0;
  }

  async readStoredHistory(conversationId: string): Promise<Array<Record<string, unknown>>> {
    return await this.page.evaluate((convId) => {
      const raw = window.localStorage.getItem('aim-store');
      if (!raw) return [];
      const parsed = JSON.parse(raw) as {
        activeProfileId?: string;
        history?: Record<string, Record<string, Array<Record<string, unknown>>>>;
      };
      const profileId = parsed.activeProfileId || '';
      if (!profileId) return [];
      return parsed.history?.[profileId]?.[convId] || [];
    }, conversationId);
  }
}

export async function waitForUiText(ui: AimUiAgent, text: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await ui.hasText(text)) return;
    await delay(RETRY_INTERVAL_MS);
  }
  throw new Error(`Timed out waiting for UI text: ${text}`);
}

export async function waitForUiStoredHistory(
  ui: AimUiAgent,
  convId: string,
  predicate: (entry: Record<string, unknown>) => boolean,
  description: string,
  timeoutMs = 20_000,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const entry = (await ui.readStoredHistory(convId)).find(predicate);
    if (entry) return entry;
    await delay(RETRY_INTERVAL_MS);
  }
  throw new Error(`Timed out waiting for ${description} in AIM UI`);
}

function isRateLimited(error: unknown): boolean {
  return error instanceof Error && /HTTP Error 429|Too Many Requests/.test(error.message);
}

export async function waitForCliHistory(
  agent: HistoryAgent,
  convId: string,
  predicate: (entry: Record<string, unknown>) => boolean,
  description: string,
  timeoutMs = 20_000,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await agent.run(['recv', convId]);
    } catch (error) {
      if (isRateLimited(error)) {
        await delay(RATE_LIMIT_RETRY_MS);
        continue;
      }
      throw error;
    }
    const entry = agent.readHistory(convId).find(predicate);
    if (entry) return entry;
    await delay(RETRY_INTERVAL_MS);
  }
  throw new Error(`Timed out waiting for ${description} in ${agent.name}`);
}

export async function assertNoCliHistory(
  agent: HistoryAgent,
  convId: string,
  predicate: (entry: Record<string, unknown>) => boolean,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await agent.run(['recv', convId]);
    } catch (error) {
      if (isRateLimited(error)) {
        await delay(RATE_LIMIT_RETRY_MS);
        continue;
      }
      throw error;
    }
    if (agent.readHistory(convId).some(predicate)) {
      throw new Error(`Unexpected history entry in ${agent.name}`);
    }
    await delay(RETRY_INTERVAL_MS);
  }
}

export class FixtureServer {
  readonly server: Server;
  readonly baseUrl: string;
  private readonly state: { counterExecutions: number };

  private constructor(server: Server, port: number, state: { counterExecutions: number }) {
    this.server = server;
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.state = state;
  }

  static async start(port = 0): Promise<FixtureServer> {
    const state = { counterExecutions: 0 };
    const server = createServer((req, res) => {
      void handleFixtureRequest(req, res, state);
    });
    await new Promise<void>((resolveServer, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolveServer);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing fixture listener');
    return new FixtureServer(server, address.port, state);
  }

  async close(): Promise<void> {
    await new Promise<void>((resolveServer, reject) => {
      this.server.close((error) => {
        if (error) reject(error);
        else resolveServer();
      });
    });
  }

  getCounterExecutions(): number {
    return this.state.counterExecutions;
  }

  resetCounterExecutions(): void {
    this.state.counterExecutions = 0;
  }
}

async function handleFixtureRequest(
  req: IncomingMessage,
  res: ServerResponse,
  state: { counterExecutions: number },
): Promise<void> {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (req.method === 'GET' && req.url === '/topstories.json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112]));
    return;
  }

  const itemMatch = req.method === 'GET' ? req.url?.match(/^\/item\/(\d+)\.json$/) : null;
  if (itemMatch) {
    const id = Number(itemMatch[1]);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id, title: `Fixture story ${id}`, type: 'story' }));
    return;
  }

  if (req.method === 'POST' && req.url === '/leet') {
    const body = await new Promise<string>((resolveBody) => {
      let data = '';
      req.on('data', (chunk) => {
        data += chunk.toString();
      });
      req.on('end', () => resolveBody(data));
    });
    const parsed = body ? JSON.parse(body) as { text?: string } : {};
    const text = parsed.text || '';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ leet: text.replace(/a/gi, '4').replace(/e/gi, '3').replace(/o/gi, '0') }));
    return;
  }

  if (req.method === 'POST' && req.url === '/post') {
    let body = ''; for await (const chunk of req) body += chunk.toString();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ json: JSON.parse(body || '{}') }));
    return;
  }

  if (req.method === 'POST' && req.url === '/counter') {
    state.counterExecutions += 1;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: state.counterExecutions }));
    return;
  }

  if (req.method === 'GET' && req.url === '/counter') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ count: state.counterExecutions }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
}

export interface LongHarness {
  rootDir: string;
  relayUrl: string;
  gatewayUrl: string;
  uiUrl: string;
  recipeCatalogPath: string;
  gatewayBootstrap: { gateway_public_key: string; gateway_kid: string };
  fixture: FixtureServer;
  browser: Browser | null;
  ui: AimUiAgent | null;
  alice: CliAgent;
  charlie: TslibAgent;
  dave: CliAgent;
  processes: ManagedProcess[];
  artifactDir: string;
  stop(): Promise<void>;
  bootstrapGateway(convId: string, agent: ConversationAgent): Promise<{ gateway_public_key: string; gateway_kid: string }>;
  restartGateway(convId: string, agent: ConversationAgent): Promise<void>;
  getCounterExecutions(): number;
  resetCounterExecutions(): void;
}

export interface LongHarnessOptions {
  withUi?: boolean;
  withMcp?: boolean;
}

function writeRecipeCatalog(path: string, baseUrl: string): void {
  const catalog = {
    profiles: {
      hackernews: {
        service: 'hackernews',
        description: 'Deterministic Hacker News-compatible fixture',
        base_url: baseUrl,
        hosts: ['127.0.0.1'],
        auth_required: false,
        endpoints: [
          { path: '/topstories.json', verb: 'GET', description: 'Top stories', risk_tier: 'read' },
          { path: '/item/{id}.json', verb: 'GET', description: 'Get item by ID', risk_tier: 'read' },
        ],
      },
      fun: {
        service: 'fun',
        description: 'Local fun fixture',
        base_url: baseUrl,
        hosts: ['127.0.0.1'],
        auth_required: false,
        endpoints: [
          { path: '/leet', verb: 'POST', description: 'Leet translation', risk_tier: 'read' },
          { path: '/counter', verb: 'POST', description: 'Increment execution counter', risk_tier: 'read' },
        ],
      },
    },
    recipes: {
      'hn.top-stories': {
        name: 'hn.top-stories',
        description: 'Fixture Hacker News top stories',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/topstories.json',
        target_url: `${baseUrl}/topstories.json`,
        risk_tier: 'read',
        threshold: 2,
        content_type: 'application/json',
      },
      'hn.top-stories.strict': {
        name: 'hn.top-stories.strict',
        description: 'Fixture Hacker News top stories requiring 3 approvals',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/topstories.json',
        target_url: `${baseUrl}/topstories.json`,
        risk_tier: 'read',
        threshold: 3,
        content_type: 'application/json',
      },
      'hn.get-item': {
        name: 'hn.get-item',
        description: 'Fixture Hacker News item lookup',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/item/{id}.json',
        target_url: `${baseUrl}/item/{id}.json`,
        risk_tier: 'read',
        threshold: 2,
        content_type: 'application/json',
        path_params: [
          {
            name: 'id',
            description: 'Hacker News item ID',
            required: true,
            type: 'string',
          },
        ],
      },
      'leet.translate': {
        name: 'leet.translate',
        description: 'Leet translation fixture',
        service: 'fun',
        verb: 'POST',
        endpoint: '/leet',
        target_url: `${baseUrl}/leet`,
        risk_tier: 'read',
        threshold: 2,
        content_type: 'application/json',
        body_schema: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'Text to translate' },
          },
          required: ['text'],
        },
        body_example: { text: 'hello world' },
      },
      'counter.bump': {
        name: 'counter.bump',
        description: 'Increment a local counter fixture',
        service: 'fun',
        verb: 'POST',
        endpoint: '/counter',
        target_url: `${baseUrl}/counter`,
        risk_tier: 'read',
        threshold: 2,
        content_type: 'application/json',
      },
    },
  };
  writeFileSync(path, JSON.stringify(catalog, null, 2));
}

async function createPythonVenv(rootDir: string, repoRoot: string, withMcp = false): Promise<string> {
  const venvDir = join(rootDir, 'venv');
  const systemPython = process.platform === 'win32' ? 'python.exe' : 'python3';
  await execFileAsync(systemPython, ['-m', 'venv', venvDir], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  const binDir = join(venvDir, process.platform === 'win32' ? 'Scripts' : 'bin');
  const python = join(binDir, process.platform === 'win32' ? 'python.exe' : 'python');
  await execFileAsync(python, ['-m', 'pip', 'install', '-q', '-e', withMcp ? 'python-dist[mcp]' : 'python-dist'], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  return join(binDir, process.platform === 'win32' ? 'qntm.exe' : 'qntm');
}

export async function createLongHarness(options: LongHarnessOptions = {}): Promise<LongHarness> {
  const withUi = options.withUi ?? true;
  const repoRoot = REPO_ROOT;
  const integrationDir = join(repoRoot, 'integration');
  const rootDir = mkdtempSync(join(tmpdir(), 'qntm-long-'));
  const cliBaseDir = join(rootDir, 'agents');
  mkdirSync(cliBaseDir, { recursive: true });

  const relayPersistDir = join(rootDir, 'relay-state');
  const gatewayPersistDir = join(rootDir, 'gateway-state');
  mkdirSync(relayPersistDir, { recursive: true });
  mkdirSync(gatewayPersistDir, { recursive: true });

  const qntmBin = await createPythonVenv(rootDir, repoRoot, options.withMcp);
  const fixture = await FixtureServer.start();
  const recipeCatalogPath = join(rootDir, 'recipes.json');
  writeRecipeCatalog(recipeCatalogPath, fixture.baseUrl);

  let relayUrl = '', gatewayUrl = '', uiUrl = '';
  const processes: ManagedProcess[] = [];
  let gatewayProcess: ManagedProcess;
  try {
    const relayProcess = new ManagedProcess(
        'relay',
        [
          npxCommand(), 'wrangler', 'dev', '--local',
          '--name', `${basename(rootDir).toLowerCase()}-relay`,
          '--port', '0',
          '--ip', '127.0.0.1',
          '--inspector-port', '0',
          '--persist-to', relayPersistDir,
          '--var', 'RATE_LIMIT_PER_MIN:5000',
        ],
        join(repoRoot, 'worker'),
        workerTestEnv(rootDir),
      );
    processes.push(relayProcess);
    relayUrl = await relayProcess.waitForLocalUrl('worker', '/healthz');
    gatewayProcess = new ManagedProcess(
        'gateway',
        [
          npxCommand(), 'wrangler', 'dev', '--local',
          '--name', `${basename(rootDir).toLowerCase()}-gateway`,
          '--port', '0',
          '--ip', '127.0.0.1',
          '--inspector-port', '0',
          '--persist-to', gatewayPersistDir,
          '--var', `DROPBOX_URL:${relayUrl}`,
          '--var', `POLL_INTERVAL_MS:${GATEWAY_POLL_INTERVAL_MS}`,
          '--var', `GATE_VAULT_KEY:${'00'.repeat(32)}`,
        ],
        join(repoRoot, 'gateway-worker'),
        workerTestEnv(rootDir),
      );
    processes.push(gatewayProcess);
    gatewayUrl = await gatewayProcess.waitForLocalUrl('worker', '/health');
    if (withUi) {
      const uiProcess = new ManagedProcess(
          'aim-ui',
          [npmCommand(), 'run', 'dev', '--', '--host', '127.0.0.1', '--port', '0', '--strictPort'],
          join(repoRoot, 'ui/aim-chat'),
          { ...process.env },
        );
      processes.push(uiProcess);
      uiUrl = await uiProcess.waitForLocalUrl('vite');
    }
  } catch (error) {
    await fixture.close();
    for (const process of processes.reverse()) await process.stop();
    rmSync(rootDir, { recursive: true, force: true });
    throw error;
  }

  let browser: Browser | null = null;
  let ui: AimUiAgent | null = null;
  if (withUi) {
    await ensureChromiumInstalled(integrationDir);
    browser = await chromium.launch({ headless: true });
    ui = await AimUiAgent.launch(browser, uiUrl, relayUrl);
  }
  const alice = new CliAgent('alice', qntmBin, relayUrl, recipeCatalogPath, repoRoot, cliBaseDir);
  const charlie = new TslibAgent('charlie', relayUrl);
  const dave = new CliAgent('dave', qntmBin, relayUrl, recipeCatalogPath, repoRoot, cliBaseDir);
  const artifactDir = join(integrationDir, 'test-results', `long-${Date.now()}-${process.pid}`);

  const bootstrapGateway = async (
    convId: string,
    agent: ConversationAgent,
  ): Promise<{ gateway_public_key: string; gateway_kid: string }> => {
    const promoted = await agent.run(['gate-promote', '-c', convId, '--gateway-url', gatewayUrl, '--threshold', '2']);
    if (!promoted.ok) throw new Error(promoted.error);
    await waitForCliHistory(agent, convId, entry => entry.body_type === 'gate.accept', 'gateway signed acceptance', 30_000);
    return { gateway_public_key: String(promoted.data!.gateway_public_key), gateway_kid: String(promoted.data!.gateway_kid) };

  };

  return {
    rootDir,
    relayUrl,
    gatewayUrl,
    uiUrl,
    recipeCatalogPath,
    gatewayBootstrap: { gateway_public_key: '', gateway_kid: '' },
    fixture,
    browser,
    ui,
    alice,
    charlie,
    dave,
    processes,
    artifactDir,
    async stop() {
      if (ui) {
        await ui.close();
      }
      if (browser) {
        await browser.close();
      }
      await fixture.close();
      for (const process of processes.reverse()) {
        await process.stop();
      }
      rmSync(rootDir, { recursive: true, force: true });
    },
    bootstrapGateway,
    async restartGateway(convId: string, agent: ConversationAgent) {
      await gatewayProcess.restart();
      await gatewayProcess.waitForHttp(`${gatewayUrl}/health`);
      // Replaying the idempotent bootstrap is the public recovery contract: it
      // routes to the persisted Durable Object and re-establishes its relay
      // subscription after a local worker process restart.
      const gateway = agent.readConversation(convId).gateway as { bootstrap: { request: Parameters<GateClient['promote']>[0] } };
      await new GateClient(gatewayUrl).promote(gateway.bootstrap.request);
    },
    getCounterExecutions() {
      return fixture.getCounterExecutions();
    },
    resetCounterExecutions() {
      fixture.resetCounterExecutions();
    },
  };
}
