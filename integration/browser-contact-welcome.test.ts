/** Native browser/TypeScript/Python CLI contacts against the actual relay worker. */
import { mkdtempSync, rmSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ManagedProcess, workerTestEnv } from './src/runtime.js'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
let state: string, relay: ManagedProcess | undefined, ui: ManagedProcess | undefined, relayUrl: string, uiUrl: string

describe('browser contact welcomes through the relay worker', () => {
  beforeAll(async () => {
    state = mkdtempSync(join(tmpdir(), 'qntm-browser-welcome-'))
    relay = new ManagedProcess('browser-contact-relay', ['npx', 'wrangler', 'dev', '--local', '--name', basename(state), '--port', '0', '--ip', '127.0.0.1', '--inspector-port', '0', '--persist-to', state, '--var', 'RATE_LIMIT_PER_MIN:5000'], join(root, 'worker'), workerTestEnv(state))
    relayUrl = await relay.waitForLocalUrl('worker', '/healthz')
    ui = new ManagedProcess('browser-contact-ui', [process.execPath, 'scripts/serve-tests.mjs', '--port', '0'], join(root, 'ui/aim-chat'), process.env)
    uiUrl = await ui.waitForLocalUrl('vite', '/')
  }, 60_000)
  afterAll(async () => {
    if (ui) await ui.stop()
    if (relay) await relay.stop()
    if (state) rmSync(state, { recursive: true, force: true })
  })
  it('runs real browser addition, reverse opening, replies, refresh, removal and readmission with TS and CLI peers', async () => {
    const result = await promisify(execFile)('npm', ['run', 'test:e2e', '--', 'contact-groups.spec.ts'], {
      cwd: join(root, 'ui/aim-chat'), timeout: 180_000, maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, QNTM_UI_BASE_URL: uiUrl, QNTM_BROWSER_RELAY_URL: relayUrl },
    })
    expect(result.stdout).toContain('6 passed')
    expect(result.stdout).toContain('1 skipped')
  }, 190_000)
})
