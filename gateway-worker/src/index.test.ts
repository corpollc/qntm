import { describe, expect, it, vi } from 'vitest';
import { base64UrlEncode, generateIdentity } from '@corpollc/qntm';
import worker from './index.js';
import type { Env } from './types.js';

function makeEnv() {
  const doFetch = vi.fn(async (_request: Request) => Response.json({ status: 'waiting' }));
  const namespace = { idFromName: vi.fn(() => ({ id: 'test' })), get: vi.fn(() => ({ fetch: doFetch })) };
  return { env: { GATEWAY_CONVO_DO: namespace } as unknown as Env, doFetch, namespace };
}
const request = (path: string, body: unknown) => new Request(`https://gateway.test/v1/${path}`, { method: 'POST', body: JSON.stringify(body) });
const invitation = { invitation_id: 'a'.repeat(32), inviter_public_key: base64UrlEncode(generateIdentity().publicKey) };
describe('participant invitation routing', () => {
  it('offers discovery without an operator token or conversation registration', async () => {
    const { env, namespace, doFetch } = makeEnv();
    expect((await worker.fetch(request('invitations', invitation), env)).status).toBe(200);
    expect(namespace.idFromName).toHaveBeenCalledWith(`invite:${invitation.inviter_public_key}:${invitation.invitation_id}`);
    expect(doFetch).toHaveBeenCalledOnce();
  });
  it('rejects the old unsealed setup request before routing', async () => {
    const { env, doFetch } = makeEnv();
    expect((await worker.fetch(request('promote', { conv_id: 'b'.repeat(32), conv_aead_key: 'key' }), env)).status).toBe(400);
    expect(doFetch).not.toHaveBeenCalled();
  });
  it.each([null, {}, { ...invitation, invitation_id: '../bad' }, { ...invitation, inviter_public_key: 'bad' }])('rejects malformed invitations', async body => {
    const { env, doFetch } = makeEnv();
    expect((await worker.fetch(request('invitations', body), env)).status).toBe(400);
    expect(doFetch).not.toHaveBeenCalled();
  });
  it('routes sealed material by inviter and invitation, preventing conversation-ID squatting', async () => {
    const { env, namespace, doFetch } = makeEnv();
    expect((await worker.fetch(request('promote', { ...invitation, sealed: 'capsule' }), env)).status).toBe(200);
    expect(namespace.idFromName).toHaveBeenCalledWith(`invite:${invitation.inviter_public_key}:${invitation.invitation_id}`);
    expect(await doFetch.mock.calls[0][0].json()).toEqual({ ...invitation, sealed: 'capsule' });
  });
});
