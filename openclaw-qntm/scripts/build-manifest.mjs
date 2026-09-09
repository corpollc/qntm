// Export the channel's Zod schema for OpenClaw's pre-load configuration UI.
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { buildChannelConfigSchema } from 'openclaw/plugin-sdk/channel-core';

const root = new URL('../', import.meta.url);
const temporary = new URL(`.manifest-schema-${process.pid}.mjs`, root);
try {
  const source = await readFile(new URL('src/config-schema.ts', root), 'utf8');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2023 },
  });
  await writeFile(temporary, compiled.outputText, { flag: 'wx', mode: 0o600 });
  const { QntmConfigSchema } = await import(temporary.href);
  const schema = buildChannelConfigSchema(QntmConfigSchema).schema;
  const manifestPath = new URL('openclaw.plugin.json', root);
  const original = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(original);
  const uiHints = {};
  for (const prefix of ['', 'accounts.*.']) {
    uiHints[`${prefix}identity`] = { sensitive: true, help: 'Private signing identity. Prefer identityFile or identityDir.' };
    uiHints[`${prefix}conversations.*.invite`] = { sensitive: true, help: 'Contains conversation encryption keys.' };
    uiHints[`${prefix}conversations.*.gatewayActions`] = { help: 'Optional native gateway tool permissions for this conversation. Empty disables all actions. Also allow qntm_gateway in the host tool policy.' };
  }
  manifest.channelConfigs = { qntm: { schema, uiHints } };
  const generated = JSON.stringify(manifest, null, 2) + '\n';
  if (process.argv.includes('--check')) {
    if (generated !== original) throw new Error('Manifest is stale; run npm run build:manifest');
  } else {
    await writeFile(manifestPath, generated);
  }
  console.log(`Verified channel metadata: ${fileURLToPath(manifestPath)}`);
} finally {
  await unlink(temporary).catch(() => {});
}
