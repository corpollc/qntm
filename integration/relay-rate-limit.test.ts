import { describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ManagedProcess, workerTestEnv } from './src/runtime.js';
import { MAX_RATE_LIMIT_IPS, RATE_LIMIT_WINDOW_MS, RelayRateLimiter } from '../worker/src/rate-limit.js';

describe('bounded per-isolate relay rate limiting', () => {
  it('keeps independent fixed windows and does not extend them on rejected traffic', () => {
    let now = 100;
    const limiter = new RelayRateLimiter(() => now);
    expect(limiter.check('192.0.2.1', 2)).toBe(true);
    expect(limiter.check('192.0.2.1', 2)).toBe(true);
    now += 20_000;
    expect(limiter.check('192.0.2.1', 2)).toBe(false);
    expect(limiter.check('192.0.2.2', 2)).toBe(true);
    now = 100 + RATE_LIMIT_WINDOW_MS;
    expect(limiter.check('192.0.2.1', 2)).toBe(true);
    expect(limiter.check('192.0.2.2', 2)).toBe(true);
    expect(limiter.check('192.0.2.2', 2)).toBe(false);
  });

  it('purges expired idle IPs when a different IP next requests service', () => {
    let now = 0;
    const limiter = new RelayRateLimiter(() => now);
    limiter.check('192.0.2.1', 1);
    now = 1_000; limiter.check('192.0.2.2', 1);
    now = RATE_LIMIT_WINDOW_MS; limiter.check('192.0.2.3', 1);
    expect(limiter.size).toBe(2);
    now += RATE_LIMIT_WINDOW_MS; limiter.check('192.0.2.4', 1);
    expect(limiter.size).toBe(1);
  });

  it('bounds cardinality under churn without resetting an active exhausted counter', () => {
    let now = 0;
    const limiter = new RelayRateLimiter(() => now);
    for (let i = 0; i < MAX_RATE_LIMIT_IPS; i++) expect(limiter.check(`ip-${i}`, 2)).toBe(true);
    expect(limiter.check('ip-0', 2)).toBe(true);
    for (let i = 0; i < 1_000; i++) expect(limiter.check(`overflow-${i}`, 2)).toBe(false);
    expect(limiter.size).toBe(MAX_RATE_LIMIT_IPS);
    expect(limiter.check('ip-0', 2)).toBe(false);
    expect(limiter.check('ip-1', 2)).toBe(true);
    now = RATE_LIMIT_WINDOW_MS;
    expect(limiter.check('previously-unknown', 2)).toBe(true);
    expect(limiter.size).toBe(1);
  });

  it('does not reorder expiry or reset a quota if the wall clock moves backward', () => {
    let now = 30_000;
    const limiter = new RelayRateLimiter(() => now);
    limiter.check('192.0.2.1', 1);
    now = 0; limiter.check('192.0.2.2', 1);
    expect(limiter.check('192.0.2.1', 1)).toBe(false);
    now = 30_000 + RATE_LIMIT_WINDOW_MS;
    expect(limiter.check('192.0.2.3', 1)).toBe(true);
    expect(limiter.size).toBe(1);
  });

  it('bounds key size and keeps rejected malformed keys out of memory', () => {
    const limiter = new RelayRateLimiter();
    expect(limiter.check('', 10)).toBe(false);
    expect(limiter.check('x'.repeat(65), 10)).toBe(false);
    expect(limiter.size).toBe(0);
    expect(limiter.check('2001:db8:0:0:0:0:192.0.2.1', 10)).toBe(true);
  });

  it.each([0, -1, NaN, Infinity, 1.5])('rejects an invalid configured quota %s without allocating entries', quota => {
    const limiter = new RelayRateLimiter();
    expect(limiter.check('192.0.2.1', quota)).toBe(false);
    expect(limiter.size).toBe(0);
  });
});

it('enforces HTTP 429 in the real Worker while leaving CORS preflight available', async () => {
  const state = await mkdtemp(join(tmpdir(), 'qntm-rate-limit-'));
  const relay = new ManagedProcess('rate-limit', [process.platform === 'win32' ? 'npx.cmd' : 'npx',
    'wrangler', 'dev', '--local', '--ip', '127.0.0.1', '--port', '0', '--inspector-port', '0',
    '--name', basename(state).toLowerCase(),
    '--persist-to', state, '--var', 'RATE_LIMIT_PER_MIN:2'], fileURLToPath(new URL('../worker', import.meta.url)), workerTestEnv(state));
  try {
    // The successful readiness request uses the first of this IP's two slots.
    const url = `${await relay.waitForLocalUrl('worker', '/healthz')}/healthz`;
    expect((await fetch(url)).status).toBe(200);
    const limited = await fetch(url);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ error: 'rate limit exceeded' });
    expect((await fetch(url, { method: 'OPTIONS' })).status).toBe(204);
    expect((await fetch(url)).status).toBe(429);
  } finally {
    await relay.stop();
    await rm(state, { recursive: true, force: true });
  }
}, 60_000);
