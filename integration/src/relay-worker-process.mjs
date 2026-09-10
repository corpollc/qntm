// Run the Wrangler-built relay in workerd without Wrangler's development
// ProxyWorker. Its inner HTTP keep-alive race can drop non-idempotent requests:
// https://github.com/cloudflare/workers-sdk/issues/14641
// This fixture never retries a POST or changes the production relay/client.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readdirSync } from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import { parseArgs } from 'node:util';

const require = createRequire(resolve('package.json'));
const { unstable_getMiniflareWorkerOptions } = require('wrangler');
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const { values } = parseArgs({ options: {
  port: { type: 'string', default: '0' },
  name: { type: 'string' },
  'persist-to': { type: 'string' },
  var: { type: 'string', multiple: true, default: [] },
} });
if (!values.name || !values['persist-to']) throw new Error('Relay fixture requires name and persist-to');
const stateDir = resolve(values['persist-to']);
const configPath = resolve('wrangler.toml');
const config = unstable_getMiniflareWorkerOptions(configPath);
if (!config.main) throw new Error('Relay fixture requires a Worker entrypoint');
const buildDir = join(stateDir, 'bundle');
const wranglerCli = join(dirname(require.resolve('wrangler/package.json')), 'bin', 'wrangler.js');
execFileSync(process.execPath, [wranglerCli, 'deploy', '--dry-run', '--config', configPath,
  '--outdir', buildDir, '--name', values.name], { stdio: 'inherit' });
const entrypoint = `${parse(config.main).name}.js`;
const unexpectedModules = readdirSync(buildDir).filter(name => name !== entrypoint && !name.endsWith('.map') && name !== 'README.md');
if (unexpectedModules.length) throw new Error(`Extend relay fixture for bundled modules: ${unexpectedModules.join(', ')}`);
// Wrangler already applied its source-module rules during the dry-run build.
// This relay currently emits one self-contained ES module; reject extra modules
// rather than silently ignoring a future binding or asset added to the bundle.
const { modulesRules: _sourceRules, ...workerOptions } = config.workerOptions;
const bindings = { ...workerOptions.bindings };
for (const value of values.var) {
  const separator = value.indexOf(':');
  if (separator < 1) throw new Error('Expected fixture var NAME:value');
  bindings[value.slice(0, separator)] = value.slice(separator + 1);
}
const runtime = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: Number(values.port),
  verbose: process.env.WRANGLER_LOG === 'debug',
  resourcePersistencePath: join(stateDir, 'v3'),
  workers: [{ ...workerOptions, name: values.name, bindings, modules: true, modulesRoot: buildDir,
    scriptPath: join(buildDir, entrypoint) }, ...config.externalWorkers],
}));
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await runtime.dispose();
}
process.once('SIGTERM', () => { void stop().then(() => process.exit(0)); });
process.once('SIGINT', () => { void stop().then(() => process.exit(0)); });
console.log(`Ready on ${(await runtime.ready).origin}`);
