import { afterEach, expect, it, vi } from 'vitest';
import { executeRequest, MAX_RESULT_BODY_BYTES } from './execute.js';
import * as vault from './vault.js';
import type { GateRequestMessage, VaultEntry } from './types.js';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const request = { request_id: 'request', verb: 'GET', target_endpoint: '/', target_url: 'https://api.example.test/' } as GateRequestMessage;
const entry = { service: 'example', allowed_origins: ['https://api.example.test'], header_name: 'X-Api-Key', header_template: '{value}' } as VaultEntry;

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

it('P0-2: fails closed before decrypting or fetching when target origin is not in vaultEntry.allowed_origins', async () => {
  const decryptSpy = vi.spyOn(vault, 'decryptVaultEntry').mockResolvedValue('sk_live_secret');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);

  const stripeEntry = {
    service: 'stripe',
    allowed_origins: ['https://api.stripe.com'],
    header_name: 'Authorization',
    header_template: 'Bearer {value}',
  } as VaultEntry;

  await expect(
    executeRequest(
      { request_id: 'r1', verb: 'GET', target_endpoint: '/echo', target_url: 'https://attacker.example/echo' } as GateRequestMessage,
      stripeEntry,
      {} as CryptoKey,
    ),
  ).rejects.toThrow('not authorized');

  await expect(
    executeRequest(
      { request_id: 'r2', verb: 'GET', target_endpoint: '/echo', target_url: 'http://localhost:9090/echo' } as GateRequestMessage,
      stripeEntry,
      {} as CryptoKey,
    ),
  ).rejects.toThrow('not authorized');

  expect(decryptSpy).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
});

it('P0-2 & P0-2b: blocks SSRF IPs, dot-segments, and unbound target_endpoint while allowing explicit localhost HTTP', async () => {
  const decryptSpy = vi.spyOn(vault, 'decryptVaultEntry').mockResolvedValue('local-dev-token');
  const fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
  vi.stubGlobal('fetch', fetchSpy);

  for (const badUrl of [
    'https://169.254.169.254/latest/meta-data/',
    'https://10.0.0.1/internal',
    'https://172.16.0.1/internal',
    'https://192.168.1.1/internal',
    'https://100.64.0.1/internal',
    'https://127.0.0.1/internal',
    'https://[::1]/internal',
    'https://[fc00::1]/internal',
    'https://[fe80::1]/internal',
    'https://api.example.test/v1/../admin',
    'https://api.example.test/v1/%2e%2e/admin',
    'https://user:pass@api.example.test/',
    'https://api.example.test/#frag',
  ]) {
    await expect(
      executeRequest({ request_id: 'ssrf', verb: 'GET', target_url: badUrl } as GateRequestMessage, entry, {} as CryptoKey),
    ).rejects.toThrow();
  }
  await expect(
    executeRequest(
      { request_id: 'unbound', verb: 'POST', target_endpoint: '/safe', target_url: 'https://api.example.test/v1/charges' } as GateRequestMessage,
      entry,
      {} as CryptoKey,
    ),
  ).rejects.toThrow('endpoint does not match');
  expect(fetchSpy).not.toHaveBeenCalled();

  const localEntry = {
    service: 'fun',
    allowed_origins: ['http://localhost:9090'],
    header_name: 'Authorization',
    header_template: 'Bearer {value}',
  } as VaultEntry;
  const ok = await executeRequest(
    { request_id: 'local', verb: 'GET', target_endpoint: '/joke', target_url: 'http://localhost:9090/joke' } as GateRequestMessage,
    localEntry,
    {} as CryptoKey,
  );
  expect(ok.status_code).toBe(200);
  expect(decryptSpy).toHaveBeenCalledOnce();
});

it('P2-6: preserves dollar signs in vault secrets when substituting {value} in header_template', async () => {
  const dollarSecret = 'p@ss$$word$&$1$`$\'end';
  vi.spyOn(vault, 'decryptVaultEntry').mockResolvedValue(dollarSecret);
  let capturedAuth = '';
  vi.stubGlobal('fetch', vi.fn(async (_url, init) => {
    capturedAuth = (init?.headers as Record<string, string>).Authorization;
    return new Response('ok', { status: 200 });
  }));
  await executeRequest(
    request,
    { ...entry, header_name: 'Authorization', header_template: 'Bearer {value}' },
    {} as CryptoKey,
  );
  expect(capturedAuth).toBe(`Bearer ${dollarSecret}`);
});
