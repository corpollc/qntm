import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
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

async function isHttpReady(url: string, init?: RequestInit): Promise<boolean> {
  try {
    const response = await fetch(url, init);
    return response.ok || response.status >= 400;
  } catch {
    return false;
  }
}

export async function waitForHttp(url: string, init?: RequestInit, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isHttpReady(url, init)) return;
    await delay(250);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolvePort, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to allocate port'));
        return;
      }
      const { port } = address;
      server.close((err) => {
        if (err) reject(err);
        else resolvePort(port);
      });
    });
  });
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

  constructor(name: string, command: string[], cwd: string, env: NodeJS.ProcessEnv) {
    this.name = name;
    this.command = command;
    this.cwd = cwd;
    this.env = env;
    this.child = this.start();
  }

  private start(): ReturnType<typeof spawn> {
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
}

function bunCommand(): string {
  return process.platform === 'win32' ? 'bun.exe' : 'bun';
}

function bunxCommand(): string {
  return process.platform === 'win32' ? 'bunx.cmd' : 'bunx';
}

function uvCommand(): string {
  return process.platform === 'win32' ? 'uv.exe' : 'uv';
}

export class CliAgent {
  readonly name: string;
  readonly configDir: string;
  private readonly qntmBin: string;
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
  await execFileAsync(bunxCommand(), ['playwright', 'install', 'chromium'], {
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
    await this.page.getByRole('button', { name: 'Generate keypair', exact: true }).click();
    await this.page.locator('.toast-message', { hasText: 'Keypair generated' }).waitFor({ timeout: 10_000 });
  }

  async joinConversation(token: string, label: string): Promise<void> {
    await this.ensurePanel('Invites');
    await this.page.getByPlaceholder('Paste an invite token').fill(token);
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
    await this.page.getByRole('button', { name: 'Enable API Gateway' }).click();
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

  async checkMessages(): Promise<void> {
    await this.page.getByRole('button', { name: 'Check for messages' }).click();
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
    await ui.checkMessages();
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
    await ui.checkMessages();
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

  static async start(port: number): Promise<FixtureServer> {
    const state = { counterExecutions: 0 };
    const server = createServer((req, res) => {
      void handleFixtureRequest(req, res, state);
    });
    await new Promise<void>((resolveServer) => server.listen(port, '127.0.0.1', () => resolveServer()));
    return new FixtureServer(server, port, state);
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
    res.end(JSON.stringify([101, 102, 103, 104]));
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
  stop(): Promise<void>;
  bootstrapGateway(convId: string, agent: ConversationAgent): Promise<{ gateway_public_key: string; gateway_kid: string }>;
  pumpGateway(convId: string): Promise<void>;
  restartGateway(): Promise<void>;
  getCounterExecutions(): number;
  resetCounterExecutions(): void;
}

export interface LongHarnessOptions {
  withUi?: boolean;
}

function writeRecipeCatalog(path: string, baseUrl: string): void {
  const catalog = {
    profiles: {
      hackernews: {
        service: 'hackernews',
        description: 'Live Hacker News API',
        base_url: 'https://hacker-news.firebaseio.com/v0',
        hosts: ['hacker-news.firebaseio.com'],
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
        description: 'Live Hacker News top stories',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/topstories.json',
        target_url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
        risk_tier: 'read',
        threshold: 2,
        content_type: 'application/json',
      },
      'hn.top-stories.strict': {
        name: 'hn.top-stories.strict',
        description: 'Live Hacker News top stories requiring 3 approvals',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/topstories.json',
        target_url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
        risk_tier: 'read',
        threshold: 3,
        content_type: 'application/json',
      },
      'hn.get-item': {
        name: 'hn.get-item',
        description: 'Live Hacker News item lookup',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/item/{id}.json',
        target_url: 'https://hacker-news.firebaseio.com/v0/item/{id}.json',
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

async function createPythonVenv(rootDir: string, repoRoot: string): Promise<string> {
  const venvDir = join(rootDir, 'venv');
  await execFileAsync(uvCommand(), ['venv', venvDir], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  const python = join(venvDir, 'bin', 'python');
  await execFileAsync(uvCommand(), ['pip', 'install', '--python', python, '-q', '-e', 'python-dist'], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  return join(venvDir, 'bin', 'qntm');
}

export async function createLongHarness(options: LongHarnessOptions = {}): Promise<LongHarness> {
  const withUi = options.withUi ?? true;
  const repoRoot = REPO_ROOT;
  const integrationDir = join(repoRoot, 'integration');
  const rootDir = mkdtempSync(join(tmpdir(), 'qntm-long-'));
  const cliBaseDir = join(rootDir, 'agents');
  mkdirSync(cliBaseDir, { recursive: true });

  const fixturePort = await getFreePort();
  const relayPort = await getFreePort();
  const gatewayPort = await getFreePort();
  const uiPort = await getFreePort();
  const relayInspectorPort = await getFreePort();
  const gatewayInspectorPort = await getFreePort();
  const relayPersistDir = join(rootDir, 'relay-state');
  const gatewayPersistDir = join(rootDir, 'gateway-state');
  mkdirSync(relayPersistDir, { recursive: true });
  mkdirSync(gatewayPersistDir, { recursive: true });

  const fixture = await FixtureServer.start(fixturePort);
  const recipeCatalogPath = join(rootDir, 'recipes.json');
  writeRecipeCatalog(recipeCatalogPath, fixture.baseUrl);

  const qntmBin = await createPythonVenv(rootDir, repoRoot);
  const relayUrl = `http://127.0.0.1:${relayPort}`;
  const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
  const uiUrl = withUi ? `http://127.0.0.1:${uiPort}` : '';

  const relayProcess = new ManagedProcess(
      'relay',
      [
        bunxCommand(), 'wrangler', 'dev', '--local',
        '--port', String(relayPort),
        '--ip', '127.0.0.1',
        '--inspector-port', String(relayInspectorPort),
        '--persist-to', relayPersistDir,
        '--var', 'RATE_LIMIT_PER_MIN:5000',
      ],
      join(repoRoot, 'worker'),
      { ...process.env },
    );
  const gatewayProcess = new ManagedProcess(
      'gateway',
      [
        bunxCommand(), 'wrangler', 'dev', '--local',
        '--port', String(gatewayPort),
        '--ip', '127.0.0.1',
        '--inspector-port', String(gatewayInspectorPort),
        '--persist-to', gatewayPersistDir,
        '--var', `DROPBOX_URL:${relayUrl}`,
        '--var', `POLL_INTERVAL_MS:${GATEWAY_POLL_INTERVAL_MS}`,
        '--var', `GATE_VAULT_KEY:${'00'.repeat(32)}`,
        '--var', 'ENABLE_DEBUG_ROUTES:1',
      ],
      join(repoRoot, 'gateway-worker'),
      { ...process.env },
    );
  const uiProcess = withUi
    ? new ManagedProcess(
        'aim-ui',
        [bunCommand(), 'run', 'dev', '--host', '127.0.0.1', '--port', String(uiPort)],
        join(repoRoot, 'ui/aim-chat'),
        { ...process.env },
      )
    : null;
  const processes = [relayProcess, gatewayProcess, uiProcess].filter((process): process is ManagedProcess => process !== null);

  await waitForHttp(`${relayUrl}/v1/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ conversations: [{ conv_id: '00000000000000000000000000000000', from_seq: 0 }] }),
  });
  await waitForHttp(`${gatewayUrl}/health`);
  if (withUi) {
    await waitForHttp(uiUrl);
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
    async bootstrapGateway(convId: string, agent: CliAgent) {
      const conversation = agent.readConversation(convId);
      const keys = conversation.keys as Record<string, string>;
      const gate = new GateClient(gatewayUrl);
      return await gate.promote(
        convId,
        hexToBase64Url(keys.aead_key),
        hexToBase64Url(keys.nonce_key),
        Number(conversation.current_epoch || 0),
      );
    },
    async pumpGateway(convId: string) {
      let lastCursor = -1;

      for (let attempt = 0; attempt < 8; attempt += 1) {
        const response = await fetch(`${gatewayUrl}/v1/debug/poll-once?conv_id=${convId}`, { method: 'POST' });
        if (!response.ok) {
          throw new Error(`gateway debug pump failed: HTTP ${response.status} ${await response.text()}`);
        }
        const status = await response.json() as { poll_cursor?: unknown };
        const pollCursor = Number(status.poll_cursor ?? 0);
        if (pollCursor === lastCursor) {
          return;
        }
        lastCursor = pollCursor;
      }
      throw new Error(`gateway debug pump did not converge for ${convId}`);
    },
    async restartGateway() {
      await gatewayProcess.restart();
      await waitForHttp(`${gatewayUrl}/health`);
    },
    getCounterExecutions() {
      return fixture.getCounterExecutions();
    },
    resetCounterExecutions() {
      fixture.resetCounterExecutions();
    },
  };
}
