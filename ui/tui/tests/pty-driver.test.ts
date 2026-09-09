import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { createGateRequestBody } from '@corpollc/qntm';
import { TuiAgent } from '../../../integration/src/tui-agent.js';
import { gatewayFixture } from './support/gateway.js';
import { TestRelayServer } from './support/relay.js';
import { waitFor } from './support/wait.js';

describe('acceptance PTY driver', () => {
  it('waits for the current POST acknowledgement despite older receipts in terminal redraws', { timeout: 30000 }, async () => {
    const dirs: string[] = [];
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), { service: 'demo', endpoint: '/check', verb: 'GET', targetUrl: 'https://example.test/check' });
    await f.deliver(f.bob, request.type, request);
    const relay = new TestRelayServer();
    await relay.start();
    const tui = new TuiAgent(f.dir, relay.url);
    let release!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    let received = false, finished = false;
    let action: Promise<string> | undefined;
    try {
      await tui.start();
      await tui.review(`/approve ${request.request_id}`);
      expect(tui.text()).toContain('gate.approval sent.');
      relay.beforeSendResponse = async () => { received = true; await blocked; };
      action = tui.review(`/disapprove ${request.request_id}`).then(result => { finished = true; return result; });
      await waitFor(() => received);
      await new Promise(resolve => setTimeout(resolve, 400));
      expect(finished).toBe(false);
      release();
      await action;
      expect(tui.history(f.convId).filter(message => message.direction === 'outgoing' && message.bodyType === 'gate.disapproval')).toHaveLength(1);
    } finally {
      release(); await action?.catch(() => {}); await tui.stop(); await relay.close();
      vi.restoreAllMocks(); for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    }
  });

  it('waits for a suspended terminal to render input before sending Return', { timeout: 30000 }, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'qntm-pty-driver-'));
    const tui = new TuiAgent(directory, 'http://127.0.0.1:1');
    let resume: ReturnType<typeof setTimeout> | undefined;
    try {
      await tui.start();
      expect(tui.childPid).toBeTypeOf('number');
      process.kill(tui.childPid!, 'SIGSTOP');
      let resumed = false;
      resume = setTimeout(() => { resumed = true; process.kill(tui.childPid!, 'SIGCONT'); }, 800);
      const from = await tui.command('/help gate');
      expect(resumed).toBe(true);
      await tui.waitFor('gateway', from);
      expect(tui.text(from)).not.toContain('/help gate\r ');
      // A second command also waits for the cleared composer, with no fixed delay.
      const next = await tui.command('/help approve');
      await tui.waitFor('Reviews a verified pending API request', next);
    } finally {
      if (resume) clearTimeout(resume);
      if (tui.childPid && tui.process?.exitCode === null) {
        try { process.kill(tui.childPid, 'SIGCONT'); } catch { /* already exited */ }
      }
      await tui.stop(); rmSync(directory, { recursive: true, force: true });
    }
  });
});
