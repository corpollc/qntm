import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest } from 'node:http';
import { connect as connectTcp, type Socket } from 'node:net';
import { once } from 'node:events';
import { dirname, join } from 'node:path';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { matchesGatewayAcceptance } from '@corpollc/qntm';
import type { ReceiveEvent } from '@corpollc/qntm';
import { createLongHarness, waitForUiStoredHistory } from './src/runtime.js';
import type { LongHarness, ManagedProcess } from './src/runtime.js';
import { LONG_TIMEOUT, setupTwoPartyGovernedConversation, waitForCliHistory, requireUi, printDiagnostics } from './long-helpers.js';

describe.sequential('new release features across real clients and relay', () => {
  let harness: LongHarness, conversation: string, bobKid: string;
  let mcp: Client;
  beforeAll(async () => {
    harness = await createLongHarness({ withUi: true, withMcp: true });
    const setup = await setupTwoPartyGovernedConversation(harness, 'Guidance acceptance');
    conversation = setup.convId;
    bobKid = String(harness.alice.readHistory(conversation).find(entry => entry.unsafe_body === 'hello from bob ui')!.sender_kid);
    mcp = new Client({ name: 'release-acceptance', version: '1' });
    await mcp.connect(new StdioClientTransport({
      command: join(dirname(harness.alice.qntmBin), 'qntm-mcp'),
      env: { QNTM_CONFIG_DIR: harness.alice.configDir, QNTM_RELAY_URL: harness.relayUrl }, stderr: 'pipe',
    }));
  }, LONG_TIMEOUT);
  afterAll(async () => { await mcp?.close(); await harness?.stop(); }, LONG_TIMEOUT);

  async function tool(name: string, args: Record<string, unknown> = {}): Promise<Record<string, any>> {
    const result = await mcp.callTool({ name, arguments: args });
    expect(result.isError).not.toBe(true);
    return result.structuredContent as Record<string, any> ?? JSON.parse((result.content as Array<{ text: string }>)[0].text);
  }

  it('closes CLI gateway admission with an authenticated acceptance visible to the browser', async () => {
    const history = harness.alice.readHistory(conversation);
    const invitation = history.find(entry => entry.body_type === 'gate.promote')!;
    const acceptance = history.find(entry => entry.body_type === 'gate.accept')!;
    const body = JSON.parse(String(acceptance.unsafe_body));
    expect(matchesGatewayAcceptance(body, Buffer.from(String(acceptance.sender_kid), 'hex').toString('base64url'),
      String(invitation.message_id), String(invitation.unsafe_body ?? invitation.body))).toBe(true);
    const shown = await waitForUiStoredHistory(requireUi(harness), conversation, entry => entry.bodyType === 'gate.accept', 'signed gateway acceptance');
    expect(JSON.parse(String(shown.text))).toEqual(body);
    expect(harness.alice.readConversation(conversation).gateway).toMatchObject({ status: 'active' });
  });

  it('discovers CLI pins through MCP and delivers only the reviewed guidance to the browser', async () => {
    const ui = requireUi(harness);
    expect((await tool('guidance_contacts')).contacts).toEqual([]);
    await harness.alice.run(['send', conversation, 'PRIVATE HISTORY MARKER: never attach automatically']);
    for (const category of ['legal', 'ethical', 'law_enforcement']) {
      await harness.alice.run(['guidance', 'pin', category, '--category', category, '--name', `Bob ${category}`,
        '--conversation', conversation, '--recipient', bobKid]);
    }
    const contacts = await tool('guidance_contacts');
    expect(contacts.contacts.map((contact: any) => contact.category).sort()).toEqual(['ethical', 'law_enforcement', 'legal']);
    for (const category of ['legal', 'ethical', 'law_enforcement']) {
      const question = `Please review the ${category} release question.`;
      const prepared = await tool('guidance_prepare', { contact: category, question, context: 'Only this chosen context.' });
      expect(prepared.status).toBe('prepared');
      expect(prepared.message).not.toContain('PRIVATE HISTORY MARKER');
      expect(prepared.contact.recipient_key_id).toBe(bobKid);
      expect(prepared.audience).toContain(bobKid);
      const refused = await tool('guidance_send', { contact: category, question: `${question} Changed`, context: 'Only this chosen context.', review_token: prepared.review_token });
      expect(refused.error).toMatch(/changed|review/i);
      const sent = await tool('guidance_send', { contact: category, question, context: 'Only this chosen context.', review_token: prepared.review_token });
      expect(sent.status).toBe('sent');
      const received = await waitForUiStoredHistory(ui, conversation, entry => entry.id === sent.message_id, 'MCP guidance in browser');
      expect(received.text).toBe(prepared.message);
      expect(received.text).not.toContain('Changed');
    }
    expect(statSync(join(harness.alice.configDir, 'guidance_contacts.json')).mode & 0o777).toBe(0o600);
  }, LONG_TIMEOUT);

  it('pins a browser contact and sends the exact reviewed message back to the CLI', async () => {
    const ui = requireUi(harness), page = ui.page;
    try {
      await page.getByRole('button', { name: 'Request guidance', exact: true }).click();
      await page.getByRole('button', { name: 'Pin a contact', exact: true }).click();
      await page.getByLabel('Contact name', { exact: true }).fill('Alice release counsel');
      await page.getByLabel('Conversation', { exact: true }).selectOption(conversation);
      await page.getByLabel('Recipient key ID', { exact: true }).selectOption(harness.alice.readIdentity().key_id);
      await page.getByRole('button', { name: 'Save pin', exact: true }).click();
      await page.getByLabel('What do you need guidance on?', { exact: true }).fill('Browser guidance: may we proceed?');
      await page.getByLabel('Context to share (optional)', { exact: true }).fill('Only the stated question.');
      await page.getByRole('button', { name: 'Review request', exact: true }).click();
      const reviewed = await page.locator('.guidance-review pre').innerText();
      expect(reviewed).toContain('Browser guidance: may we proceed?');
      expect(reviewed).not.toContain('PRIVATE HISTORY MARKER');
      await harness.alice.run(['recv', conversation]);
      expect(harness.alice.readHistory(conversation).some(entry => entry.unsafe_body === reviewed)).toBe(false);
      await page.getByRole('button', { name: 'Send guidance request', exact: true }).click();
      await page.getByText('Request sent to the relay', { exact: true }).waitFor();
      await waitForCliHistory(harness.alice, conversation, entry => entry.unsafe_body === reviewed, 'browser guidance in CLI');
      await page.getByRole('button', { name: 'Open conversation', exact: true }).click();
    } catch (error) { await printDiagnostics(harness, conversation); throw error; }
  }, LONG_TIMEOUT);

  it('delivers TS messages to independent hooks and resumes after restart and a shared CLI receive', async () => {
    const created = await harness.alice.run(['group', 'create', 'Receive hooks acceptance']);
    const id = String(created.data!.conversation_id);
    await harness.charlie.run(['group', 'join', '--', String(created.data!.invite_token)]);
    const attempts: ReceiveEvent[] = [], accepted: ReceiveEvent[] = [];
    let allowFirst = false;
    const sink = createServer(async (req, res) => {
      let body = ''; for await (const chunk of req) body += chunk;
      const event = JSON.parse(body).data as ReceiveEvent;
      expect(req.headers['idempotency-key']).toBe(event.event_id);
      attempts.push(event);
      if (event.message.unsafe_body === 'hooks: first Ω' && !allowFirst) { res.writeHead(503).end(); return; }
      accepted.push(event); res.writeHead(204).end();
    });
    sink.listen(0, '127.0.0.1'); await once(sink, 'listening');
    const sinkUrl = `http://127.0.0.1:${(sink.address() as { port: number }).port}/receive`;
    const script = join(harness.rootDir, 'record hook.py'), output = join(harness.rootDir, 'hook events.jsonl');
    writeFileSync(script, 'import pathlib,sys\nwith pathlib.Path(sys.argv[1]).open("a") as out: out.write(sys.stdin.read())\n');
    const command = [join(dirname(harness.alice.qntmBin), 'python'), script, output].map(value => JSON.stringify(value)).join(' ');
    const args = ['recv', id, '--watch', '--webhook', sinkUrl, '--on-receive', command, '--hook-timeout', '2'];
    let watcher: ManagedProcess | undefined;
    const executableEvents = (): ReceiveEvent[] => existsSync(output) ? readFileSync(output, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line).data) : [];
    try {
      watcher = harness.alice.start(args);
      const first = await harness.charlie.run(['send', id, 'hooks: first Ω']);
      const firstId = String(first.data!.message_id);
      await expect.poll(() => attempts.some(event => event.message.message_id === firstId), { timeout: 20_000 }).toBe(true);
      await expect.poll(() => executableEvents().some(event => event.message.message_id === firstId), { timeout: 20_000 }).toBe(true);
      expect(accepted.some(event => event.message.message_id === firstId)).toBe(false);
      await watcher.stop(); watcher = undefined;
      const second = await harness.charlie.run(['send', id, 'hooks: while watcher is offline']);
      await harness.alice.run(['recv', id]); // Shared cursor moves ahead of pending hook delivery.
      allowFirst = true;
      watcher = harness.alice.start(args);
      await expect.poll(() => accepted.filter(event => event.message.message_id === firstId).length, { timeout: 20_000 }).toBe(1);
      await expect.poll(() => accepted.some(event => event.message.message_id === second.data!.message_id), { timeout: 20_000 }).toBe(true);
      await expect.poll(() => executableEvents().some(event => event.message.message_id === second.data!.message_id), { timeout: 20_000 }).toBe(true);
      expect(executableEvents().filter(event => event.message.message_id === firstId)).toHaveLength(1);
      const delivered = accepted.find(event => event.message.message_id === firstId)!;
      expect(delivered).toMatchObject({ version: 1, event_id: `qntm:${id}:${firstId}`, conversation_id: id,
        message: { verified: true, unsafe_body: 'hooks: first Ω', sender_kid: harness.charlie.readIdentity().key_id } });
      expect(executableEvents().find(event => event.event_id === delivered.event_id)).toEqual(delivered);
      const self = await harness.alice.run(['send', id, 'hooks: self should not wake me']);
      await harness.charlie.run(['send', id, 'hooks: barrier']);
      await expect.poll(() => accepted.some(event => event.message.unsafe_body === 'hooks: barrier'), { timeout: 20_000 }).toBe(true);
      expect(attempts.some(event => event.message.message_id === self.data!.message_id)).toBe(false);
    } finally { await watcher?.stop(); await new Promise<void>(resolve => sink.close(() => resolve())); }
  }, LONG_TIMEOUT);

  it('recovers a lost HTTP send acknowledgement through relay replay without a second POST', async () => {
    const created = await harness.alice.run(['group', 'create', 'Lost acknowledgement acceptance']);
    const id = String(created.data!.conversation_id);
    await harness.charlie.run(['group', 'join', '--', String(created.data!.invite_token)]);
    const relay = new URL(harness.relayUrl);
    let posts = 0;
    const sockets = new Set<Socket>();
    const proxy = createServer((req, res) => {
      const upstream = httpRequest(new URL(req.url!, relay), { method: req.method, headers: req.headers }, response => {
        if (req.method === 'POST') {
          posts++; response.resume(); response.on('end', () => res.destroy());
        } else { res.writeHead(response.statusCode!, response.headers); response.pipe(res); }
      });
      upstream.on('error', () => res.destroy()); req.pipe(upstream);
    });
    proxy.on('connection', socket => {
      sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    });
    proxy.on('upgrade', (req, socket, head) => {
      const upstream = connectTcp(Number(relay.port), relay.hostname, () => {
        upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n${Object.entries(req.headers).map(([key, value]) => `${key}: ${value}`).join('\r\n')}\r\n\r\n`);
        if (head.length) upstream.write(head);
        socket.pipe(upstream); upstream.pipe(socket);
      });
      sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
      upstream.on('close', () => socket.destroy()); socket.on('close', () => upstream.destroy());
    });
    proxy.listen(0, '127.0.0.1'); await once(proxy, 'listening');
    try {
      const url = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
      const sent = await harness.alice.run(['--dropbox-url', url, 'send', id, 'one message despite a lost response']);
      expect(sent.data!.acknowledgement).toBe('reconciled');
      await waitForCliHistory(harness.charlie, id, entry => entry.message_id === sent.data!.message_id, 'recovered message in TypeScript');
      expect(posts).toBe(1);
      expect(harness.charlie.readHistory(id).filter(entry => entry.message_id === sent.data!.message_id)).toHaveLength(1);
    } finally { for (const socket of sockets) socket.destroy(); proxy.closeAllConnections(); await new Promise<void>(resolve => proxy.close(() => resolve())); }
  }, LONG_TIMEOUT);
});
