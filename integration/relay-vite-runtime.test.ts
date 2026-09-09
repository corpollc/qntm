import { fileURLToPath } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import { ManagedProcess } from './src/runtime.js';

const children: ManagedProcess[] = [];
afterEach(async () => { await Promise.all(children.splice(0).map(child => child.stop())); });

it('runs two actual Vite UI servers on distinct assigned ports and releases them on shutdown', async () => {
  const root = fileURLToPath(new URL('../ui/aim-chat', import.meta.url));
  const script = fileURLToPath(new URL('../ui/aim-chat/scripts/serve-tests.mjs', import.meta.url));
  for (let i = 0; i < 2; i++) children.push(new ManagedProcess(`vite-${i}`, [process.execPath, script, '--port', '0'], root, { ...process.env }));
  const urls = await Promise.all(children.map(child => child.waitForLocalUrl('vite', '/', 20_000)));
  expect(new Set(urls).size).toBe(2);
  for (const url of urls) {
    expect(await (await fetch(url)).text()).toContain('/src/main.tsx');
    expect((await fetch(`${url}/src/main.tsx`)).status).toBe(200);
  }
  await Promise.all(children.map(child => child.stop()));
  for (const url of urls) await expect(fetch(url)).rejects.toThrow();
}, 30_000);
