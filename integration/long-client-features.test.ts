import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest } from 'node:http';
import { connect as connectTcp, type Socket } from 'node:net';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { matchesGatewayAcceptance, generateIdentity, DropboxClient, deserializeEnvelope, serializeEnvelope,
  isGroupWelcomeEnvelope, parseGroupLink, openGroupWelcome, groupSessionFromWelcome, checkGroupWelcomeReplay,
  assertGroupCanSend, groupSessionConversation, createMessage, decryptMessage } from '@corpollc/qntm';
import type { ReceiveEvent } from '@corpollc/qntm';
import { createLongHarness, waitForUiStoredHistory } from './src/runtime.js';
import type { LongHarness, ManagedProcess } from './src/runtime.js';
import { LONG_TIMEOUT, setupTwoPartyGovernedConversation, waitForCliHistory, requireUi, printDiagnostics } from './long-helpers.js';
import { recordingRelay } from './src/recording-relay.js';

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
    const before = harness.alice.readHistory(conversation).filter(entry => entry.body_type === 'gate.secret').length;
    await expect(harness.alice.run(['gate-secret', '-c', conversation, '--service', 'stripe',
      '--gateway-pubkey', harness.alice.readIdentity().public_key, '--value', 'must-not-leave-this-client'])).rejects.toThrow('does not match');
    await harness.alice.run(['recv', conversation]);
    expect(harness.alice.readHistory(conversation).filter(entry => entry.body_type === 'gate.secret')).toHaveLength(before);
  }, 30_000);

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

  for (const surface of ['CLI', 'MCP']) it(`renews an expired pending addition from a fresh ${surface} process without obsolete control POSTs`, async () => {
    const proxy = await recordingRelay(harness.relayUrl);
    let retryMcp: Client | undefined;
    const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
    try {
      const recipient = generateIdentity(), challenge = hex(crypto.getRandomValues(new Uint8Array(32)));
      const created = await harness.alice.run(['--dropbox-url', proxy.url, 'group', 'create', `${surface} pending admission`, '--contact']);
      const id = String(created.data!.conversation_id);
      const oldRoot = (harness.alice.readConversation(id).keys as { root: string }).root;
      await harness.alice.run(['--dropbox-url', proxy.url, 'send', id, 'before this recipient was admitted']);
      const beforeAdmission = deserializeEnvelope(Buffer.from(proxy.sends.at(-1)!.envelope_b64, 'base64'));
      const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
      const stage = await promisify(execFile)(join(dirname(harness.alice.qntmBin), 'python'), [
        join(repo, 'integration/src/stage-pending-addition.py'), harness.alice.configDir, proxy.url, id,
        hex(recipient.publicKey), challenge,
      ], { cwd: repo, timeout: 30_000, maxBuffer: 1024 * 1024 });
      const staged = JSON.parse(stage.stdout) as { expires_at: number; cursor: number; controls: string[]; welcome_id: string; admission: unknown };
      const saved = harness.alice.readConversation(id).group_operation as { kind: string; welcomes_sent: number; welcomes: string[] };
      expect(saved).toMatchObject({ kind: 'add', welcomes_sent: 0 });
      expect(saved.welcomes).toHaveLength(1);
      const postedIds = proxy.sends.map(send => hex(deserializeEnvelope(Buffer.from(send.envelope_b64, 'base64')).msg_id));
      for (const control of staged.controls) expect(postedIds.filter(id => id === control)).toHaveLength(1);
      expect(postedIds).not.toContain(staged.welcome_id);
      const beforeRetry = proxy.sends.length;
      const wait = Math.max(0, staged.expires_at * 1000 - Date.now() + 1100);
      expect(wait).toBeLessThanOrEqual(10_000);
      await delay(wait);
      expect(Math.floor(Date.now() / 1000)).toBeGreaterThan(staged.expires_at);
      let result: Record<string, unknown>;
      if (surface === 'CLI') {
        result = (await harness.alice.run(['--dropbox-url', proxy.url, 'group', 'retry', id])).data!;
      } else {
        retryMcp = new Client({ name: 'pending-admission-retry', version: '1' });
        await retryMcp.connect(new StdioClientTransport({
          command: join(dirname(harness.alice.qntmBin), 'qntm-mcp'),
          env: { QNTM_CONFIG_DIR: harness.alice.configDir, QNTM_RELAY_URL: proxy.url }, stderr: 'pipe',
        }));
        const retried = await retryMcp.callTool({ name: 'group_retry', arguments: { conversation: id } });
        expect(retried.isError).not.toBe(true);
        result = retried.structuredContent as Record<string, unknown> ?? JSON.parse((retried.content as Array<{ text: string }>)[0].text);
      }
      expect(harness.alice.readConversation(id).group_operation).toBeUndefined();
      const sent = proxy.sends.slice(beforeRetry);
      expect(sent).toHaveLength(1); // Includes attempts, so relay idempotency cannot hide obsolete POSTs.
      const renewedEnvelope = deserializeEnvelope(Buffer.from(sent[0].envelope_b64, 'base64'));
      expect(isGroupWelcomeEnvelope(renewedEnvelope)).toBe(true);
      expect(hex(renewedEnvelope.msg_id)).not.toBe(staged.welcome_id);
      const locator = parseGroupLink(String(result.group_link)), transport = new DropboxClient(locator.relayUrl);
      const batch = await transport.receiveMessages(locator.conversationId, 0);
      const row = batch.entries.find(row => hex(deserializeEnvelope(row.envelope).msg_id) === hex(renewedEnvelope.msg_id))!;
      expect(row).toBeDefined();
      const welcome = openGroupWelcome(recipient, row.envelope, locator);
      expect(welcome.purpose).toBe('renewal');
      expect(welcome.admissions[hex(recipient.keyID)]).toEqual(staged.admission);
      expect(hex(welcome.recoveryChallenge!)).toBe(challenge);
      expect(welcome.replayFromSequence).toBe(staged.cursor);
      const state = checkGroupWelcomeReplay(groupSessionFromWelcome(recipient, welcome, row.seq), welcome, batch.sequence, batch.entries);
      assertGroupCanSend(recipient, state);
      expect(state.rekeys).toEqual([]);
      expect(JSON.stringify(state)).not.toContain(oldRoot);
      expect(() => decryptMessage(beforeAdmission, groupSessionConversation(state))).toThrow();
      const reply = createMessage(recipient, groupSessionConversation(state), 'text', new TextEncoder().encode(`${surface} renewed contact reply`));
      await transport.postMessage(locator.conversationId, serializeEnvelope(reply));
      await harness.alice.run(['--dropbox-url', proxy.url, 'recv', id]);
      expect(harness.alice.readHistory(id).filter(message => message.unsafe_body === `${surface} renewed contact reply`)).toHaveLength(1);
    } finally { await retryMcp?.close(); await proxy.stop(); }
  }, LONG_TIMEOUT);
});
