import { afterEach, expect, it, vi } from 'vitest';
import { executeRequest, MAX_RESULT_BODY_BYTES } from './execute.js';
import * as vault from './vault.js';
import type { GateRequestMessage, VaultEntry } from './types.js';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const request = { request_id: 'request', verb: 'GET', target_url: 'https://api.example.test/' } as GateRequestMessage;
const entry = { header_name: 'X-Api-Key', header_template: '{value}' } as VaultEntry;

it('bounds streamed response bytes and cancels excess data', async () => {
  vi.spyOn(vault, 'decryptVaultEntry').mockResolvedValue('synthetic-test-key');
  const cancel = vi.fn();
  vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(MAX_RESULT_BODY_BYTES + 1)); }, cancel,
  }))));
  const result = await executeRequest(request, entry, {} as CryptoKey);
  expect(result.body).toHaveLength(MAX_RESULT_BODY_BYTES + '\n[Response truncated]'.length);
  expect(cancel).toHaveBeenCalledOnce();
  expect(new TextEncoder().encode(JSON.stringify(result)).length).toBeLessThan(64 * 1024);
});

it('refuses redirects when sending any vault header', async () => {
  vi.spyOn(vault, 'decryptVaultEntry').mockResolvedValue('synthetic-test-key');
  const fetch = vi.fn(async (_url, options) => {
    expect(options.redirect).toBe('manual');
    return new Response('', { status: 302, headers: { Location: 'https://elsewhere.example/' } });
  });
  vi.stubGlobal('fetch', fetch);
  await expect(executeRequest(request, entry, {} as CryptoKey)).rejects.toThrow('redirects are not allowed');
  expect(fetch).toHaveBeenCalledOnce();
});
