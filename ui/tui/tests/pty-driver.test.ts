import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TuiAgent } from '../../../integration/src/tui-agent.js';

describe('acceptance PTY driver', () => {
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
