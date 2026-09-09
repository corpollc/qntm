import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createLongHarness, type LongHarness } from './src/runtime.js';
import { waitForCliHistory } from './long-helpers.js';
const execute = promisify(execFile), repo = resolve('..');
const readme = readFileSync(join(repo, 'README.md'), 'utf8');
function block(section: string, language: string): string {
  const text = readme.slice(readme.indexOf(section));
  const found = new RegExp('```' + language + '\\n([\\s\\S]*?)```').exec(text);
  if (!found) throw Error(`Missing README example: ${section}`);
  return found[1];
}
describe.sequential('commands extracted from the README against real clients', () => {
  let harness: LongHarness, python: string, conv = '', invite = '', requestId = '', gatewayPublicKey = '';
  beforeAll(async () => {
    harness = await createLongHarness({ withUi: false });
    python = join(dirname(harness.alice.qntmBin), 'python');
    const catalog = JSON.parse(readFileSync(harness.recipeCatalogPath, 'utf8'));
    const starter = JSON.parse(readFileSync(join(repo, 'gate/recipes/starter.json'), 'utf8'));
    // Keep the real recipe schema; only its HTTP origin uses a local echo fixture.
    catalog.recipes['httpbin.echo'] = { ...starter.recipes['httpbin.echo'], target_url: `${harness.fixture.baseUrl}/post` };
    catalog.profiles.httpbin = { ...starter.profiles.httpbin, base_url: harness.fixture.baseUrl, hosts: ['127.0.0.1'] };
    writeFileSync(harness.recipeCatalogPath, JSON.stringify(catalog));
  }, 90_000);
  afterAll(async () => { await harness?.stop(); });
  async function runLine(line: string, actor: 'alice' | 'dave' = 'alice') {
    line = line.replaceAll('/tmp/alice', harness.alice.configDir).replaceAll('/tmp/bob', harness.dave.configDir)
      .replaceAll('<invite-token>', invite).replaceAll('<conversation-id>', conv).replaceAll('<conv-id>', conv)
      .replaceAll('<request-id>', requestId).replaceAll('<gateway-public-key>', gatewayPublicKey).replaceAll('https://gateway.corpo.llc', harness.gatewayUrl);
    const { stdout } = await execute(python, ['-c', 'import json,shlex,sys; print(json.dumps(shlex.split(sys.argv[1],comments=True)))', line]);
    const args = JSON.parse(stdout); expect(args.shift()).toBe('qntm');
    const result = await harness[actor].run(args);
    if (result.data?.invite_token) { conv = String(result.data.conversation_id); invite = String(result.data.invite_token); }
    if (result.data?.request_id) requestId = String(result.data.request_id);
    if (result.data?.gateway_public_key) gatewayPublicKey = String(result.data.gateway_public_key);
    return result;
  }
  it('runs the two-agent quick start from its actual command block', async () => {
    let last;
    for (const line of block('### Two agents talking', 'bash').split('\n').filter(line => line.startsWith('qntm '))) last = await runLine(line);
    expect((last!.data!.messages as any[]).some(m => m.unsafe_body === 'Ready for review')).toBe(true);
  }, 30_000);
  it('runs the inline Python example and both linked offline examples', async () => {
    const source = block('### Use from Python/LLM scripts', 'python');
    const command = JSON.stringify([harness.alice.qntmBin, '--config-dir', harness.alice.configDir, '--dropbox-url', harness.relayUrl]);
    await execute(python, ['-c', `CONV_ID=${JSON.stringify(conv)}\n${source.replace('["qntm"]', command)}`], { timeout: 30_000 });
    const received = await harness.dave.run(['recv', conv]);
    expect((received.data!.messages as any[]).some(m => m.unsafe_body === 'task complete: 3 files processed')).toBe(true);
    for (const match of block('## Examples', 'bash').matchAll(/^python (examples\/[\w_]+\.py)/gm)) await execute(python, [join(repo, match[1])], { timeout: 10_000 });
  }, 45_000);
  it('joins a Python re-share link from TypeScript and delivers an encrypted message', async () => {
    const created = await harness.alice.run(['convo', 'create', '--name', 'Re-share interoperability']);
    const id = String(created.data!.conversation_id);
    const shared = await harness.alice.run(['convo', 'invite', id]);
    const link = new URL(String(shared.data!.invite_link));
    expect(link.search).toBe('');
    expect(link.hash).toBe(`#${created.data!.invite_token}`);
    await harness.charlie.run(['identity', 'generate']);
    await harness.charlie.run(['group', 'join', '--', link.href]);
    await harness.charlie.run(['send', id, 'TypeScript joined the fragment link']);
    const received = await harness.alice.run(['recv', id]);
    expect((received.data!.messages as any[]).some(message => message.unsafe_body === 'TypeScript joined the fragment link')).toBe(true);
  }, 30_000);
  it('runs the gateway example and receives the exact approved echo payload', async () => {
    const lines = block('## API Gateway', 'bash').split('\n').filter(line => line.startsWith('qntm '));
    for (const line of lines.filter(line => !line.includes('--watch'))) await runLine(line);
    expect(requestId).not.toBe('');
    const result = await waitForCliHistory(harness.alice, conv, entry => entry.body_type === 'gate.result' && JSON.parse(String(entry.unsafe_body)).request_id === requestId, 'README gateway result', 30_000).catch(error => {
      console.error(harness.alice.readHistory(conv).map(entry => { let body: any = {}; try { body = JSON.parse(String(entry.unsafe_body)); } catch {} return { type: entry.body_type, gateway_kid: body.gateway_kid, signer_kid: body.signer_kid, eligible: body.eligible_signer_kids, required: body.required_approvals, request_id: body.request_id, reason: body.reason, status: body.status, error: body.error, approvals: body.approvals }; }));
      console.error(harness.processes.find(p => p.name.includes('gateway'))?.stdout.slice(-6000)); console.error(harness.processes.find(p => p.name.includes('gateway'))?.stderr.slice(-6000)); throw error;
    });
    const body = JSON.parse(String(result.unsafe_body));
    expect(JSON.stringify(body)).toContain('Hello');
    expect(JSON.stringify(body)).toContain('200');
  }, 45_000);
});
