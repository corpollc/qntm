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

const execFileAsync = promisify(execFile);
const EXEC_MAX_BUFFER = 10 * 1024 * 1024;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

export interface JsonResult {
  ok: boolean;
  kind: string;
  data?: Record<string, unknown>;
  error?: string;
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
  readonly child: ReturnType<typeof spawn>;
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
    return JSON.parse(readFileSync(path, 'utf8')) as Array<Record<string, unknown>>;
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
    await delay(500);
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
    await delay(500);
  }
  throw new Error(`Timed out waiting for ${description} in AIM UI`);
}

function isRateLimited(error: unknown): boolean {
  return error instanceof Error && /HTTP Error 429|Too Many Requests/.test(error.message);
}

export async function waitForCliHistory(
  agent: CliAgent,
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
        await delay(1_000);
        continue;
      }
      throw error;
    }
    const entry = agent.readHistory(convId).find(predicate);
    if (entry) return entry;
    await delay(500);
  }
  throw new Error(`Timed out waiting for ${description} in ${agent.name}`);
}

export async function assertNoCliHistory(
  agent: CliAgent,
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
        await delay(1_000);
        continue;
      }
      throw error;
    }
    if (agent.readHistory(convId).some(predicate)) {
      throw new Error(`Unexpected history entry in ${agent.name}`);
    }
    await delay(500);
  }
}

export class FixtureServer {
  readonly server: Server;
  readonly baseUrl: string;

  private constructor(server: Server, port: number) {
    this.server = server;
    this.baseUrl = `http://127.0.0.1:${port}`;
  }

  static async start(port: number): Promise<FixtureServer> {
    const server = createServer((req, res) => {
      void handleFixtureRequest(req, res);
    });
    await new Promise<void>((resolveServer) => server.listen(port, '127.0.0.1', () => resolveServer()));
    return new FixtureServer(server, port);
  }

  async close(): Promise<void> {
    await new Promise<void>((resolveServer, reject) => {
      this.server.close((error) => {
        if (error) reject(error);
        else resolveServer();
      });
    });
  }
}

async function handleFixtureRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
  browser: Browser;
  ui: AimUiAgent;
  alice: CliAgent;
  charlie: CliAgent;
  processes: ManagedProcess[];
  stop(): Promise<void>;
  bootstrapGateway(convId: string, agent: CliAgent): Promise<{ gateway_public_key: string; gateway_kid: string }>;
  pumpGateway(convId: string): Promise<void>;
}

function writeRecipeCatalog(path: string, baseUrl: string): void {
  const catalog = {
    profiles: {
      hackernews: {
        service: 'hackernews',
        description: 'Local HN fixture',
        base_url: baseUrl,
        hosts: ['127.0.0.1'],
        auth_required: false,
        endpoints: [
          { path: '/topstories.json', verb: 'GET', description: 'Top stories', risk_tier: 'read' },
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
        ],
      },
    },
    recipes: {
      'hn.top-stories': {
        name: 'hn.top-stories',
        description: 'Top stories fixture',
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
        description: 'Top stories fixture requiring 3 approvals',
        service: 'hackernews',
        verb: 'GET',
        endpoint: '/topstories.json',
        target_url: `${baseUrl}/topstories.json`,
        risk_tier: 'read',
        threshold: 3,
        content_type: 'application/json',
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
    },
  };
  writeFileSync(path, JSON.stringify(catalog, null, 2));
}

async function createPythonVenv(rootDir: string, repoRoot: string): Promise<string> {
  const venvDir = join(rootDir, 'venv');
  await execFileAsync('python3', ['-m', 'venv', venvDir], { cwd: repoRoot });
  const pip = join(venvDir, 'bin', 'pip');
  const python = join(venvDir, 'bin', 'python');
  await execFileAsync(pip, ['install', '-q', '-e', 'python-dist'], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  await execFileAsync(python, ['-m', 'pip', 'install', '-q', 'pytest'], {
    cwd: repoRoot,
    maxBuffer: EXEC_MAX_BUFFER,
  });
  return join(venvDir, 'bin', 'qntm');
}

export async function createLongHarness(): Promise<LongHarness> {
  const repoRoot = REPO_ROOT;
  const integrationDir = join(repoRoot, 'integration');
  const rootDir = mkdtempSync(join(tmpdir(), 'qntm-long-'));
  const cliBaseDir = join(rootDir, 'agents');
  mkdirSync(cliBaseDir, { recursive: true });

  const fixturePort = await getFreePort();
  const relayPort = await getFreePort();
  const gatewayPort = await getFreePort();
  const uiPort = await getFreePort();

  const fixture = await FixtureServer.start(fixturePort);
  const recipeCatalogPath = join(rootDir, 'recipes.json');
  writeRecipeCatalog(recipeCatalogPath, fixture.baseUrl);

  const qntmBin = await createPythonVenv(rootDir, repoRoot);
  const relayUrl = `http://127.0.0.1:${relayPort}`;
  const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
  const uiUrl = `http://127.0.0.1:${uiPort}`;

  const processes = [
    new ManagedProcess(
      'relay',
      [
        npxCommand(), 'wrangler', 'dev', '--local',
        '--port', String(relayPort),
        '--ip', '127.0.0.1',
        '--var', 'RATE_LIMIT_PER_MIN:5000',
      ],
      join(repoRoot, 'worker'),
      { ...process.env },
    ),
    new ManagedProcess(
      'gateway',
      [
        npxCommand(), 'wrangler', 'dev', '--local',
        '--port', String(gatewayPort),
        '--ip', '127.0.0.1',
        '--var', `DROPBOX_URL:${relayUrl}`,
        '--var', 'POLL_INTERVAL_MS:500',
        '--var', `GATE_VAULT_KEY:${'00'.repeat(32)}`,
        '--var', 'ENABLE_DEBUG_ROUTES:1',
      ],
      join(repoRoot, 'gateway-worker'),
      { ...process.env },
    ),
    new ManagedProcess(
      'aim-ui',
      [npmCommand(), 'run', 'dev', '--', '--host', '127.0.0.1', '--port', String(uiPort)],
      join(repoRoot, 'ui/aim-chat'),
      { ...process.env },
    ),
  ];

  await waitForHttp(`${relayUrl}/v1/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ conversations: [{ conv_id: '00000000000000000000000000000000', from_seq: 0 }] }),
  });
  await waitForHttp(`${gatewayUrl}/health`);
  await waitForHttp(uiUrl);

  await ensureChromiumInstalled(integrationDir);
  const browser = await chromium.launch({ headless: true });
  const ui = await AimUiAgent.launch(browser, uiUrl, relayUrl);
  const alice = new CliAgent('alice', qntmBin, relayUrl, recipeCatalogPath, repoRoot, cliBaseDir);
  const charlie = new CliAgent('charlie', qntmBin, relayUrl, recipeCatalogPath, repoRoot, cliBaseDir);

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
    processes,
    async stop() {
      await ui.close();
      await browser.close();
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
      const response = await fetch(`${gatewayUrl}/v1/debug/poll-once?conv_id=${convId}`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(`gateway debug pump failed: HTTP ${response.status} ${await response.text()}`);
      }
    },
  };
}
