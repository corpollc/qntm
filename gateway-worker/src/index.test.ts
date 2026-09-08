import { describe, expect, it, vi } from 'vitest';
import { base64UrlEncode } from '@corpollc/qntm';
import worker from './index.js';
import type { Env } from './types.js';

const promotionToken = 'test-promotion-token';
const key = base64UrlEncode(new Uint8Array(32));

function makeEnv(token = promotionToken) {
  const doFetch = vi.fn(async (_request: Request) => Response.json({ created: true }, { status: 201 }));
  const stub = { fetch: doFetch };
  const namespace = {
    idFromName: vi.fn(() => ({ id: 'test' })),
    get: vi.fn(() => stub),
  };
  return {
    env: {
      GATEWAY_CONVO_DO: namespace,
      GATE_VAULT_KEY: '00'.repeat(32),
      DROPBOX_URL: 'https://relay.example',
      POLL_INTERVAL_MS: '60000',
      GATEWAY_PROMOTION_TOKEN: token,
    } as unknown as Env,
    doFetch,
    namespace,
  };
}

function promotionRequest(options: { token?: string; body?: Record<string, unknown> } = {}): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (options.token !== undefined) headers.Authorization = `Bearer ${options.token}`;
  return new Request('https://gateway.example/v1/promote', {
    method: 'POST',
    headers,
    body: JSON.stringify(options.body ?? {
      conv_id: 'A'.repeat(32),
      conv_aead_key: key,
      conv_nonce_key: key,
      conv_epoch: 0,
    }),
  });
}

describe('promotion bootstrap authentication', () => {
  it('rejects an unauthenticated first writer before routing to the durable object', async () => {
    const { env, doFetch } = makeEnv();

    const response = await worker.fetch(promotionRequest(), env);

    expect(response.status).toBe(401);
    expect(doFetch).not.toHaveBeenCalled();
  });

  it('fails closed when the promotion secret is not configured', async () => {
    const { env, doFetch } = makeEnv('');

    const response = await worker.fetch(promotionRequest({ token: promotionToken }), env);

    expect(response.status).toBe(503);
    expect(doFetch).not.toHaveBeenCalled();
  });

  it('rejects malformed key material and epochs', async () => {
    const { env, doFetch } = makeEnv();
    const response = await worker.fetch(promotionRequest({
      token: promotionToken,
      body: {
        conv_id: 'a'.repeat(32),
        conv_aead_key: 'not-a-key',
        conv_nonce_key: key,
        conv_epoch: -1,
      },
    }), env);

    expect(response.status).toBe(400);
    expect(doFetch).not.toHaveBeenCalled();
  });

  it('routes a valid authenticated request using the canonical conversation ID', async () => {
    const { env, doFetch, namespace } = makeEnv();

    const response = await worker.fetch(promotionRequest({ token: promotionToken }), env);

    expect(response.status).toBe(201);
    expect(namespace.idFromName).toHaveBeenCalledWith('a'.repeat(32));
    const forwarded = doFetch.mock.calls[0]![0] as Request;
    const body = await forwarded.json() as { conv_id: string };
    expect(body.conv_id).toBe('a'.repeat(32));
    expect(forwarded.headers.get('Authorization')).toBeNull();
  });
});
