import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const TUI_DIR = resolve(TEST_DIR, '..');
const TSX_CLI = resolve(TUI_DIR, 'node_modules/tsx/dist/cli.mjs');

async function runExpectSession(expectBody: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  const scratchDir = mkdtempSync(join(tmpdir(), 'qntm-tui-expect-'));
  const scriptPath = join(scratchDir, 'session.exp');
  writeFileSync(scriptPath, expectBody, 'utf8');
  try {
    return await execFileAsync('expect', [scriptPath, ...args], {
      cwd: TUI_DIR,
      maxBuffer: 10 * 1024 * 1024,
      env: {
        ...process.env,
        FORCE_COLOR: '0',
      },
    });
  } finally {
    unlinkSync(scriptPath);
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

describe('TUI PTY smoke', () => {
  it('runs the real terminal entry point under a PTY and prints help text', async () => {
    const helpScript = `
      set timeout 10
      lassign $argv node tsx
      spawn $node $tsx src/index.tsx --help
      expect "qntm Messenger — Terminal client"
      expect -- "--relay-url <url>"
      expect "Slash commands (in chat):"
      expect eof
    `;

    const result = await runExpectSession(helpScript, [process.execPath, TSX_CLI]);

    expect(result.stdout).toContain('qntm Messenger — Terminal client');
    expect(result.stdout).toContain('--config-dir <path>');
    expect(result.stdout).toContain('/invite [name]');
  });
});
