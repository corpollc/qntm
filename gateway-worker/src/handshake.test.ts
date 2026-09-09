import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  generateIdentity, base64UrlEncode, createGatewayInviteBody, createMessage, serializeEnvelope,
  sealGatewayBootstrap, DropboxClient, deserializeEnvelope, decryptMessage, matchesGatewayAcceptance,
} from '@corpollc/qntm';
import type { Conversation, GatewayInvitation } from '@corpollc/qntm';
import { createInvitation, acceptInvitation, finishAcceptance } from './handshake.js';
import type { ConversationState } from './types.js';

class MemoryStorage {
  data = new Map<string, unknown>();
  get = async <T>(key: string): Promise<T | undefined> => structuredClone(this.data.get(key)) as T | undefined;
  put = async (key: string, value: unknown) => { this.data.set(key, structuredClone(value)); };
  delete = async (key: string) => this.data.delete(key);
  setAlarm = vi.fn(async () => {});
}
const hex = (b: Uint8Array) => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });
async function setup(mutate?: (body: Record<string, unknown>) => void) {
  const memory = new MemoryStorage();
  const storage = memory as unknown as DurableObjectStorage;
  const alice = generateIdentity();
  const bob = generateIdentity();
  const challenge = { invitation_id: 'a'.repeat(32), inviter_public_key: base64UrlEncode(alice.publicKey) };
  const invitation = await (await createInvitation(storage, challenge)).json() as GatewayInvitation;
  const conv: Conversation = { id: new Uint8Array(16).fill(8), type: 'group', keys: { root: new Uint8Array(32), aeadKey: new Uint8Array(32).fill(1), nonceKey: new Uint8Array(32).fill(2) }, participants: [alice.keyID, bob.keyID], currentEpoch: 3, createdAt: new Date() };
  const body = createGatewayInviteBody(invitation, conv, { [base64UrlEncode(alice.keyID)]: base64UrlEncode(alice.publicKey), [base64UrlEncode(bob.keyID)]: base64UrlEncode(bob.publicKey) }, 2);
  mutate?.(body as unknown as Record<string, unknown>);
  const text = JSON.stringify(body);
  const envelope = createMessage(alice, conv, 'gate.promote', new TextEncoder().encode(text), undefined, 3600);
  const receive = vi.spyOn(DropboxClient.prototype, 'receiveMessages').mockResolvedValue({ messages: [serializeEnvelope(envelope)], sequence: 7 });
  const post = vi.spyOn(DropboxClient.prototype, 'postMessage').mockResolvedValue(8);
  const request = sealGatewayBootstrap(alice, invitation, conv, hex(envelope.msg_id), 7);
  return { storage, memory, alice, bob, challenge, invitation, conv, envelope, text, receive, post, request };
}
describe('signed gateway invitation and acceptance', () => {
  it('discovers an idempotent gateway identity without storing any conversation', async () => {
    const f = await setup();
    expect(await (await createInvitation(f.storage, f.challenge)).json()).toEqual(f.invitation);
    expect(await f.storage.get('conv_state')).toBeUndefined();
    expect(f.post).not.toHaveBeenCalled();
  });
  it('verifies the real relay invitation and posts a matching signed acceptance before activation', async () => {
    const f = await setup();
    f.post.mockImplementation(async (_id, envelopeBytes) => {
      expect(await f.storage.get('conv_state')).toBeUndefined();
      const accepted = decryptMessage(deserializeEnvelope(envelopeBytes), f.conv);
      expect(accepted.inner.body_type).toBe('gate.accept');
      expect(matchesGatewayAcceptance(JSON.parse(new TextDecoder().decode(accepted.inner.body)), base64UrlEncode(accepted.inner.sender_kid), hex(f.envelope.msg_id), f.text)).toBe(true);
      return 8;
    });
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(200);
    expect(await f.storage.get('conv_state')).toMatchObject({ gate_promoted: true, invitation_id: f.invitation.invitation_id, conv_epoch: 3, promotion_floor: 2 });
    expect(f.receive).toHaveBeenCalledWith(f.conv.id, 6);
  });
  it('persists one acceptance for retries after relay failure or process eviction', async () => {
    const f = await setup();
    f.post.mockRejectedValueOnce(new Error('offline'));
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(202);
    expect(await f.storage.get('conv_state')).toBeUndefined();
    expect(await finishAcceptance(f.storage, 'https://relay.test')).toBe(true);
    expect(f.post.mock.calls[0][1]).toEqual(f.post.mock.calls[1][1]);
    expect(f.receive).toHaveBeenCalledOnce();
  });
  it('accepts an original sealed retry after a rekey without overwriting active keys or repeating acceptance', async () => {
    const f = await setup();
    await acceptInvitation(f.storage, 'https://relay.test', f.request);
    const state = (await f.storage.get<ConversationState>('conv_state'))!;
    state.conv_epoch = 4; state.conv_aead_key = base64UrlEncode(new Uint8Array(32).fill(9));
    await f.storage.put('conv_state', state);
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(200);
    expect(await f.storage.get('conv_state')).toEqual(state);
    expect(f.post).toHaveBeenCalledOnce();
    const changed = sealGatewayBootstrap(f.alice, f.invitation, { ...f.conv, currentEpoch: 4 }, hex(f.envelope.msg_id), 7);
    expect((await acceptInvitation(f.storage, 'https://relay.test', changed)).status).toBe(409);
  });
  it.each([
    ['wrong conversation', (b: Record<string, unknown>) => { b.conv_id = 'f'.repeat(32); }],
    ['wrong epoch', (b: Record<string, unknown>) => { b.conv_epoch = 4; }],
    ['different keys', (b: Record<string, unknown>) => { b.keys_hash = '0'.repeat(64); }],
    ['different invitation', (b: Record<string, unknown>) => { b.invitation_id = 'b'.repeat(32); }],
    ['invalid floor', (b: Record<string, unknown>) => { b.floor = 0; }],
    ['missing inviter', (b: Record<string, unknown>) => { b.participants = {}; }],
  ])('rejects %s in the signed invitation without activating', async (_label, mutate) => {
    const f = await setup(mutate);
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(403);
    expect(await f.storage.get('conv_state')).toBeUndefined();
    expect(f.post).not.toHaveBeenCalled();
  });
  it('rejects an authenticated capsule when its invitation was never posted', async () => {
    const f = await setup();
    f.receive.mockResolvedValue({ messages: [], sequence: 0 });
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(403);
  });
  it('rejects a capsule sealed by someone other than the signed inviter', async () => {
    const f = await setup();
    const forged = sealGatewayBootstrap(f.bob, f.invitation, f.conv, hex(f.envelope.msg_id), 7);
    forged.inviter_public_key = f.request.inviter_public_key;
    expect((await acceptInvitation(f.storage, 'https://relay.test', forged)).status).toBe(400);
    expect(f.receive).not.toHaveBeenCalled();
  });
  it('expires abandoned candidates without leaving a conversation reservation', async () => {
    const f = await setup();
    vi.useFakeTimers(); vi.setSystemTime((f.invitation.expires_at + 1) * 1000);
    expect((await acceptInvitation(f.storage, 'https://relay.test', f.request)).status).toBe(410);
    await finishAcceptance(f.storage, 'https://relay.test');
    expect(await f.storage.get('handshake')).toBeUndefined();
    expect(await f.storage.get('conv_state')).toBeUndefined();
  });
});
