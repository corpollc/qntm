import { createServer, type RequestListener, type Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FixtureServer, getFreePorts, ManagedProcess, waitForHttp } from './src/runtime.js';

const servers: Server[] = [];
const children: ManagedProcess[] = [];

function child(script: string): ManagedProcess {
  const processFixture = new ManagedProcess('local-listener', [process.execPath, '-e', script, '--', '--port', '0'], process.cwd(), { ...process.env });
  children.push(processFixture);
  return processFixture;
}

function listenerScript(kind: 'worker' | 'vite', status = 200): string {
  return `const {createServer} = require('node:http');
    const server = createServer((req, res) => res.writeHead(${status}).end());
    server.listen(Number(process.argv[2]), '127.0.0.1', () => {
      const url = 'http://127.0.0.1:' + server.address().port;
      // Split the port across chunks and include real terminal color codes.
      process.stdout.write('\\x1b[32m${kind === 'worker' ? 'Ready on ' : 'Local:   '}' + url.slice(0, -2));
      setTimeout(() => process.stdout.write(url.slice(-2) + '\\x1b[0m\\n'), 75);
    });`;
}

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
  vi.restoreAllMocks();
  await Promise.all(children.splice(0).map(processFixture => processFixture.stop()));
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

  it.each(['worker', 'vite'] as const)('discovers concurrent bound %s listeners through split, colored output', async kind => {
    const workers = [child(listenerScript(kind)), child(listenerScript(kind))];
    const urls = await Promise.all(workers.map(worker => worker.waitForLocalUrl(kind, '/healthz', 3_000)));
    expect(new Set(urls).size).toBe(2);
    for (let index = 0; index < urls.length; index++) {
      expect(new URL(urls[index]).port).toBe(workers[index].command.at(-1));
      expect((await fetch(`${urls[index]}/healthz`)).status).toBe(200);
    }
  });

  it('does not treat a bound listener announcement as successful HTTP readiness', async () => {
    const worker = child(listenerScript('worker', 404));
    await expect(worker.waitForLocalUrl('worker', '/healthz', 1_500)).rejects.toThrow(/HTTP 404/);
  });

  it('fails promptly with process diagnostics when startup exits', async () => {
    const worker = child('console.error("fixture bind failed"); process.exit(7)');
    const started = performance.now();
    await expect(worker.waitForLocalUrl('worker', '/', 5_000)).rejects.toThrow(/Process exited before readiness[\s\S]*fixture bind failed/);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  it.skipIf(process.platform !== 'darwin')('verifies an exited group after Darwin reports EPERM', async () => {
    const worker = child(listenerScript('worker'));
    const url = await worker.waitForLocalUrl('worker', '/', 3_000);
    const group = -worker.child.pid!;
    const exited = new Promise<void>(resolve => worker.child.once('exit', () => resolve()));
    worker.child.kill('SIGTERM');
    await exited;
    const kill = process.kill.bind(process);
    const denied = Object.assign(new Error('synthetic Darwin zombie-group EPERM'), { code: 'EPERM' });
    const probe = vi.spyOn(process, 'kill').mockImplementation((pid, signal) => {
      if (pid === group) throw denied;
      return kill(pid, signal);
    });
    await expect(worker.stop()).resolves.toBeUndefined();
    expect(probe).toHaveBeenCalledWith(group, 'SIGTERM');
    await expect(fetch(url)).rejects.toThrow();
  });

  it.skipIf(process.platform !== 'darwin')('does not suppress EPERM while an owned listener is live', async () => {
    const worker = child(listenerScript('worker'));
    const url = await worker.waitForLocalUrl('worker', '/', 3_000);
    const group = -worker.child.pid!;
    const kill = process.kill.bind(process);
    const denied = Object.assign(new Error('synthetic live-group EPERM'), { code: 'EPERM' });
    const probe = vi.spyOn(process, 'kill').mockImplementation((pid, signal) => {
      if (pid === group) throw denied;
      return kill(pid, signal);
    });
    try {
      await expect(worker.stop()).rejects.toBe(denied);
      expect((await fetch(url)).status).toBe(200);
    } finally {
      probe.mockRestore();
      children.splice(children.indexOf(worker), 1); // stop() retains its rejected result.
      const exited = new Promise<void>(resolve => worker.child.once('exit', () => resolve()));
      worker.child.kill('SIGTERM');
      await exited;
    }
  });

  it('keeps the assigned service port through a process restart', async () => {
    const worker = child(listenerScript('worker'));
    const original = await worker.waitForLocalUrl('worker', '/healthz', 3_000);
    await worker.restart();
    expect(await worker.waitForLocalUrl('worker', '/healthz', 3_000)).toBe(original);
    // The previous process's forced-stop deadline must not kill its replacement.
    await new Promise(resolve => setTimeout(resolve, 5_200));
    expect((await fetch(`${original}/healthz`)).status).toBe(200);
  }, 10_000);

  it('ignores an earlier process announcement after restart', async () => {
    const url = await listen((_request, response) => response.end('ready'));
    const worker = child(`console.log('Ready on ${url}'); setInterval(() => {}, 1000)`);
    expect(await worker.waitForLocalUrl('worker', '/', 3_000)).toBe(url);
    worker.command[2] = 'setInterval(() => {}, 1000)';
    await worker.restart();
    await expect(worker.waitForLocalUrl('worker', '/', 200)).rejects.toThrow('Timed out waiting for the bound local listener');
  });

  it.skipIf(process.platform === 'win32')('stops an owned descendant listener after its wrapper exits', async () => {
    const script = listenerScript('worker');
    const wrapper = child(`const {spawn} = require('node:child_process');
      const nested = spawn(process.execPath, ['-e', ${JSON.stringify(script)}, '--', '--port', '0'], {stdio: 'inherit'});
      console.log('descendant-pid:' + nested.pid);
      setInterval(() => {}, 1000);`);
    let descendant: number | undefined;
    try {
      const url = await wrapper.waitForLocalUrl('worker', '/', 3_000);
      descendant = Number(/descendant-pid:(\d+)/.exec(wrapper.stdout)![1]);
      // Simulate npm exiting without forwarding termination to its child.
      const exited = new Promise<void>(resolve => wrapper.child.once('exit', () => resolve()));
      wrapper.child.kill('SIGTERM');
      await exited;
      expect((await fetch(url)).status).toBe(200);
      await wrapper.stop();
      await expect(fetch(url)).rejects.toThrow();
    } finally {
      if (descendant) {
        try { process.kill(descendant, 'SIGTERM'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      }
    }
  }, 10_000);

  it('uses the fixture server bound address without releasing a guessed port', async () => {
    const first = await FixtureServer.start(), second = await FixtureServer.start();
    servers.push(first.server, second.server);
    expect(first.baseUrl).not.toBe(second.baseUrl);
    expect(new URL(first.baseUrl).port).not.toBe('0');
    await Promise.all([waitForHttp(`${first.baseUrl}/topstories.json`), waitForHttp(`${second.baseUrl}/topstories.json`)]);
  });
});
