import { createServer, type RequestListener, type Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { getFreePorts, ManagedProcess, waitForHttp } from './src/runtime.js';

const servers: Server[] = [];

async function listen(handler: RequestListener, port = 0): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing test listener');
  return `http://127.0.0.1:${address.port}`;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeAllConnections();
  })));
});

describe('local service readiness', () => {
  it('waits through routing and startup failures until a successful response', async () => {
    const statuses = [404, 503, 200];
    let requests = 0;
    const url = await listen((_request, response) => {
      response.writeHead(statuses[Math.min(requests++, 2)]).end();
    });
    await waitForHttp(url, undefined, 3_000);
    expect(requests).toBe(3);
  });

  it.each([404, 500, 302])('does not mistake HTTP %i for readiness or follow a redirect', async status => {
    let redirected = 0;
    const url = await listen((request, response) => {
      if (request.url === '/healthy') {
        redirected++;
        response.writeHead(200).end();
      } else response.writeHead(status, { Location: '/healthy' }).end();
    });
    await expect(waitForHttp(url, undefined, 200)).rejects.toThrow(`HTTP ${status}`);
    expect(redirected).toBe(0);
  });

  it('bounds a request that accepts a connection but never returns headers', async () => {
    let requests = 0;
    const url = await listen(() => { requests++; });
    const started = performance.now();
    await expect(waitForHttp(url, undefined, 200)).rejects.toThrow('Timed out waiting');
    expect(requests).toBe(1);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  it('honors caller cancellation during an in-flight request', async () => {
    const controller = new AbortController();
    const url = await listen(() => controller.abort(new Error('Readiness cancelled')));
    await expect(waitForHttp(url, { signal: controller.signal })).rejects.toThrow('Readiness cancelled');
  });

  it('includes the failed process output and last HTTP status in startup diagnostics', async () => {
    const url = await listen((_request, response) => response.writeHead(503).end());
    const child = new ManagedProcess('fixture-worker', [process.execPath, '-e',
      'console.log("fixture startup"); console.error("fixture bind failed");'], process.cwd(), { ...process.env });
    try {
      await new Promise<void>(resolve => child.child.once('exit', () => resolve()));
      await expect(child.waitForHttp(url, undefined, 200)).rejects.toThrow(
        /fixture-worker failed readiness:.*HTTP 503[\s\S]*fixture startup[\s\S]*fixture bind failed/,
      );
    } finally { await child.stop(); }
  });

  it('allocates distinct listener and inspector ports and releases the complete batch', async () => {
    const ports = await getFreePorts(16);
    expect(new Set(ports).size).toBe(16);
    const urls = await Promise.all(ports.map(port => listen((_request, response) => response.end('ready'), port)));
    await Promise.all(urls.map(url => waitForHttp(url)));
  });
});
