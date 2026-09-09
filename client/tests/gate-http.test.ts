import { createServer, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GateClient } from '../src/gate/index.js';

describe('bounded gateway HTTP transport', () => {
  let server: Server, url: string;
  let mode: 'ok' | 'redirect' | 'headers-stall' | 'body-stall' | 'oversized' | 'error';
  let seen: string[], requestObserved: () => void, observed: Promise<void>;
  beforeEach(async () => {
    seen = []; mode = 'ok'; observed = new Promise(resolve => { requestObserved = resolve; });
    server = createServer(async (request, response) => {
      for await (const _chunk of request) { /* consume the small synthetic request */ }
      seen.push(request.url!); requestObserved();
      if (mode === 'headers-stall') return;
      if (mode === 'redirect') { response.writeHead(307, { Location: `${url}/redirect-target` }); response.end(); return; }
      if (mode === 'body-stall') { response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); return; }
      if (mode === 'oversized') { response.writeHead(200); response.end('x'.repeat(64 * 1024 + 1)); return; }
      response.writeHead(mode === 'error' ? 409 : 200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ status: mode === 'error' ? 'conflict' : 'waiting' }));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing test server address');
    url = `http://127.0.0.1:${address.port}`;
  });
  afterEach(async () => {
    await new Promise<void>((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); });
  });
  const bootstrap = { invitation_id: 'ab'.repeat(16), inviter_public_key: 'test-only-public-key', sealed: 'test-only-ciphertext' };
  it('retains advisory admission results and supports normal health checks', async () => {
    const client = new GateClient(url);
    expect(await client.promote(bootstrap)).toEqual({ status: 'waiting' });
    expect(await client.health()).toEqual({ status: 'waiting' });
    expect(seen).toEqual(['/v1/promote', '/health']);
  });
  it.each(['headers-stall', 'body-stall'] as const)('expires the complete request deadline during %s without retry', async stalled => {
    // Warm the local connection so the body-stall case observes response headers.
    await new GateClient(url).health(); seen = []; mode = stalled;
    await expect(new GateClient(url, { timeoutMs: 150 }).promote(bootstrap)).rejects.toMatchObject({ name: 'TimeoutError' });
    expect(seen).toEqual(['/v1/promote']);
  });
  it('propagates cancellation of an in-flight request without retrying', async () => {
    mode = 'body-stall'; const abort = new AbortController();
    const result = new GateClient(url, { signal: abort.signal }).promote(bootstrap);
    const rejected = expect(result).rejects.toMatchObject({ name: 'AbortError' });
    await observed; abort.abort(); await rejected;
    expect(seen).toEqual(['/v1/promote']);
  });
  it('rejects an already-aborted call before transmitting', async () => {
    const abort = new AbortController(); abort.abort();
    await expect(new GateClient(url, { signal: abort.signal }).createInvitation('public-key', 'ab'.repeat(16))).rejects.toMatchObject({ name: 'AbortError' });
    expect(seen).toHaveLength(0);
  });
  it('does not forward a setup POST to a redirect target', async () => {
    mode = 'redirect'; await expect(new GateClient(url).promote(bootstrap)).rejects.toThrow();
    expect(seen).toEqual(['/v1/promote']);
  });
  it('bounds streamed response data, including successful HTTP responses', async () => {
    mode = 'oversized'; await expect(new GateClient(url).promote(bootstrap)).rejects.toThrow('64 KiB');
    expect(seen).toEqual(['/v1/promote']);
  });
  it('preserves bounded API errors without retry', async () => {
    mode = 'error'; await expect(new GateClient(url).promote(bootstrap)).rejects.toMatchObject({ status: 409, body: '{"status":"conflict"}' });
    expect(seen).toEqual(['/v1/promote']);
  });
  it.each([0, -1, 1.5, Infinity, 300001])('rejects an invalid deadline %s', timeoutMs => {
    expect(() => new GateClient(url, { timeoutMs })).toThrow(RangeError);
  });
});
