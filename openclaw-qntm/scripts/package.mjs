import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, cp, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('../', import.meta.url));
async function npm(args, cwd) {
  return await new Promise((resolve, reject) => {
    const child = spawn('npm', args, {
      cwd, env: { ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH}` },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    const timeout = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => { clearTimeout(timeout); reject(error); });
    child.once('exit', (code) => {
      clearTimeout(timeout);
      if (code === 0) resolve(stdout);
      else reject(new Error(`npm ${args[0]} exited ${code}\n${stdout}\n${stderr}`));
    });
  });
}

// Compile a self-contained runtime from this checkout's built client. The host
// supplies its SDK; the optional cbor native addon falls back to bundled JS.
export async function stagePlugin(stage) {
  await mkdir(stage, { recursive: true });
  const result = await build({
    absWorkingDir: root, entryPoints: ['index.ts'], outfile: join(stage, 'index.mjs'),
    bundle: true, platform: 'node', format: 'esm', target: 'node24', metafile: true,
    external: ['openclaw/*', 'cbor-extract'], legalComments: 'eof',
    banner: { js: "import { createRequire as qntmCreateRequire } from 'node:module'; const require = qntmCreateRequire(import.meta.url);" },
  });
  for (const name of ['openclaw.plugin.json', 'README.md']) await cp(join(root, name), join(stage, name));
  await cp(join(root, '../LICENSE'), join(stage, 'LICENSE'));
  const licenses = join(stage, 'licenses');
  await mkdir(licenses);
  const visited = new Set();
  for (const input of Object.keys(result.metafile.inputs)) {
    let directory = dirname(resolve(root, input));
    while (directory !== dirname(directory)) {
      let metadata;
      try { metadata = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8')); } catch {}
      if (typeof metadata?.name === 'string') {
        if (!visited.has(directory)) {
          visited.add(directory);
          const prefix = metadata.name.replaceAll('/', '_');
          for (const name of await readdir(directory)) {
            if (/^(license|licence|copying|notice)(\.|$)/i.test(name)) {
              await cp(join(directory, name), join(licenses, `${prefix}-${name}`));
            }
          }
        }
        break;
      }
      directory = dirname(directory);
    }
  }
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  delete pkg.devDependencies;
  delete pkg.dependencies;
  delete pkg.scripts;
  pkg.openclaw.extensions = ['./index.mjs'];
  pkg.files = ['index.mjs', 'openclaw.plugin.json', 'README.md', 'LICENSE', 'licenses'];
  await writeFile(join(stage, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const temporary = await mkdtemp(join(tmpdir(), 'qntm-openclaw-pack-'));
  try {
    await stagePlugin(temporary);
    const output = join(root, 'dist');
    await mkdir(output, { recursive: true });
    const [packed] = JSON.parse(await npm(['pack', '--json', '--pack-destination', output], temporary));
    if (!packed.files.some((file) => file.path === 'index.mjs')) {
      throw new Error('Packaged plugin is missing its compiled runtime');
    }
    console.log(join(output, packed.filename));
  } finally { await rm(temporary, { recursive: true, force: true }); }
}
