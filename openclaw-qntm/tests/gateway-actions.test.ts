import { mkdtempSync, rmSync, statSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  generateIdentity, createMessage, serializeEnvelope, deserializeEnvelope, decryptMessage,
  createGatewayInviteBody, gatewayInvitationHash, sessionGatewayContext, base64UrlEncode, base64UrlDecode,
  createGateRequestBody, createGatewayProposalBody, createGroupRekeyBody, createGroupRemoveBody, openSecret,
  type Identity, type GatewayInvitation,
} from '@corpollc/qntm';
import { createConfig, createConversationFixture, createIdentityFixture } from './helpers.js';
import { resolveQntmAccount } from '../src/accounts.js';
import { QntmCheckpointStore } from '../src/checkpoint.js';
import { QntmGatewayActions, type GatewayScope } from '../src/gateway-actions.js';
import { receiveQntmEnvelope } from '../src/receive.js';
import { toHex } from '../src/qntm.js';
import type { QntmGatewayAction } from '../src/types.js';
import { createQntmGatewayTool, resolveGatewayToolScope } from '../src/gateway-tool.js';
import type { OpenClawPluginToolContext } from 'openclaw/plugin-sdk/core';

export const allActions: QntmGatewayAction[] = ['invite', 'request', 'approve', 'disapprove', 'secret', 'propose', 'gov-approve', 'gov-disapprove'];
const directories: string[] = [];
afterEach(() => { vi.useRealTimers(); for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
const requestOptions = { service: 'demo', endpoint: '/records', verb: 'POST', targetUrl: 'https://example.test/records', payload: { text: 'review me' } };
type Review = { status: string; reviewToken: string; reviewHash: string; review: any };
export function fixture(accepted = true) {
  const stateDir = mkdtempSync(join(tmpdir(), 'qntm-gateway-actions-')); directories.push(stateDir);
  const identity = createIdentityFixture(), group = createConversationFixture('group'), gateway = generateIdentity();
  const cfg = createConfig({ identity: identity.serialized, conversations: { group: { invite: group.token, gatewayActions: [...allActions] } } });
  const account = resolveQntmAccount({ cfg }), binding = account.bindings[0];
  const store = new QntmCheckpointStore(account, { stateDir });
  const scope: GatewayScope = { key: 'trusted-host-session', account, binding, store };
  const state = () => store.load(binding);
  const deliver = (sender: Identity, type: string, body: unknown) => {
    const bytes = serializeEnvelope(createMessage(sender, state().conversation, type, body instanceof Uint8Array ? body : new TextEncoder().encode(JSON.stringify(body))));
    expect(receiveQntmEnvelope(store, binding, state().cursor + 1, bytes)).toBe('accepted');
    return bytes;
  };
  const invitation = (inviter = group.inviter, invitationId = 'ab'.repeat(16)): GatewayInvitation => ({
    invitation_id: invitationId, inviter_public_key: base64UrlEncode(inviter.publicKey),
    gateway_public_key: base64UrlEncode(gateway.publicKey), gateway_kid: base64UrlEncode(gateway.keyID), expires_at: Math.floor(Date.now() / 1000) + 600,
  });
  const accept = () => {
    const pending = state().session.gateway!.invitation, body = pending.body;
    deliver(gateway, 'gate.accept', { type: 'gate.accept', invitation_id: body.invitation_id, invitation_msg_id: pending.messageId,
      invitation_hash: gatewayInvitationHash(pending.text), conv_id: binding.conversationId, conv_epoch: body.conv_epoch,
      gateway_kid: body.gateway_kid, gateway_public_key: body.gateway_public_key });
  };
  if (accepted) {
    const body = createGatewayInviteBody(invitation(), state().conversation, state().session.participants, 2);
    deliver(group.inviter, 'gate.promote', body); accept();
  }
  const posts: Uint8Array[] = [];
  const postMessage = vi.fn(async (_id: Uint8Array, bytes: Uint8Array) => { posts.push(bytes); return state().cursor + 1; });
  const createInvitation = vi.fn(async (inviterKey: string, id: string) => ({ ...invitation(identity.identity, id), inviter_public_key: inviterKey }));
  const promote = vi.fn(async (body: { invitation_id: string }) => ({ status: 'joined' as const, gateway_public_key: base64UrlEncode(gateway.publicKey), gateway_kid: base64UrlEncode(gateway.keyID), invitation_id: body.invitation_id }));
  const deps = { client: () => ({ postMessage }), gate: () => ({ createInvitation, promote }) };
  const service = new QntmGatewayActions(deps);
  const receivePosted = () => receiveQntmEnvelope(store, binding, state().cursor + 1, posts.at(-1)!);
  const decodePosted = () => JSON.parse(new TextDecoder().decode(decryptMessage(deserializeEnvelope(posts.at(-1)!), state().conversation).inner.body));
  const request = (id?: string) => {
    const body = createGateRequestBody(group.inviter, sessionGatewayContext(state().session), { ...requestOptions, requestId: id });
    deliver(group.inviter, body.type, body); return body;
  };
  const proposal = () => {
    const body = createGatewayProposalBody(group.inviter, sessionGatewayContext(state().session), { proposalType: 'floor_change', proposedFloor: 1 });
    deliver(group.inviter, body.type, body); return body;
  };
  const rekey = () => deliver(gateway, 'group_rekey', createGroupRekeyBody(new Uint8Array(32).fill(42), state().conversation.currentEpoch + 1,
    [identity.identity, group.inviter].map(i => ({ kid: i.keyID, publicKey: i.publicKey })), state().conversation.id));
  const prepare = (action: Parameters<QntmGatewayActions['prepare']>[1], options?: Record<string, unknown>) => service.prepare(scope, action, options) as Promise<Review>;
  const commit = (review: Review) => service.commit(scope, review.reviewToken, review.reviewHash) as Promise<any>;
  return { stateDir, cfg, scope, state, deliver, accept, gateway, identity: identity.identity, group, service, deps, prepare, commit,
    posts, postMessage, createInvitation, promote, receivePosted, decodePosted, request, proposal, rekey,
    bootstrapPath: `${store.path(binding)}.gateway-bootstrap` };
}

describe('reviewed native gateway actions', () => {
  test('holds immutable complete content, sends only on commit and leaves receive state to the subscription', async () => {
    const f = fixture(), payload = { nested: { amount: 42 } };
    const review = await f.prepare('request', { ...requestOptions, payload });
    payload.nested.amount = 1000;
    expect(review.review.body.payload).toEqual({ nested: { amount: 42 } });
    expect(review.review.context.floor).toBe(2);
    expect(f.postMessage).not.toHaveBeenCalled();
    const before = f.state(), receipt = await f.commit(review);
    expect(receipt).toMatchObject({ status: 'submitted', bodyType: 'gate.request', sequence: before.cursor + 1 });
    expect(receipt.messageId).toBe(toHex(deserializeEnvelope(f.posts[0]).msg_id));
    expect(f.decodePosted().payload).toEqual({ nested: { amount: 42 } });
    expect(f.state()).toEqual(before);
    expect(f.receivePosted()).toBe('accepted');
    expect(f.service.status(f.scope)).toMatchObject({ entries: [{ status: 'pending', approvals: 1, threshold: 2 }] });
    await expect(f.commit(review)).rejects.toMatchObject({ code: 'review_unavailable' });
    expect(f.postMessage).toHaveBeenCalledTimes(1);
  });
  test('requires the same host scope and exact review hash; cancel and restart invalidate reviews', async () => {
    const f = fixture(), review = await f.prepare('request', requestOptions);
    await expect(f.service.commit({ ...f.scope, key: 'other-session' }, review.reviewToken, review.reviewHash)).rejects.toMatchObject({ code: 'review_unavailable' });
    await expect(f.service.commit(f.scope, review.reviewToken, '00'.repeat(32))).rejects.toMatchObject({ code: 'review_mismatch' });
    await expect(new QntmGatewayActions(f.deps).commit(f.scope, review.reviewToken, review.reviewHash)).rejects.toMatchObject({ code: 'review_unavailable' });
    expect(f.service.cancel(f.scope, review.reviewToken)).toEqual({ status: 'cancelled' });
    await expect(f.commit(review)).rejects.toMatchObject({ code: 'review_unavailable' });
    expect(f.posts).toHaveLength(0);
  });
  test('returned review objects cannot mutate the stored signed action', async () => {
    const f = fixture(), review = await f.prepare('request', requestOptions);
    review.review.body.payload.text = 'changed after review';
    review.review.context.floor = 1;
    await f.commit(review);
    expect(f.decodePosted()).toMatchObject({ required_approvals: 2, payload: { text: 'review me' } });
  });
  test.each(['permission', 'rekey', 'removal', 'expiry'] as const)('rejects a review after %s changes', async change => {
    const f = fixture(), review = await f.prepare('request', requestOptions);
    if (change === 'permission') f.scope.binding.gatewayActions = ['invite'];
    if (change === 'rekey') f.rekey();
    if (change === 'removal') f.deliver(f.gateway, 'group_remove', createGroupRemoveBody([f.identity.keyID]));
    if (change === 'expiry') { vi.useFakeTimers(); vi.setSystemTime(review.review.expiresAt + 1); }
    await expect(f.commit(review)).rejects.toThrow(); expect(f.posts).toHaveLength(0);
  });
  test('cannot overwrite a rekey received while a POST is awaiting its acknowledgement', async () => {
    const f = fixture(), review = await f.prepare('request', requestOptions);
    let acknowledge!: (sequence: number) => void;
    f.postMessage.mockImplementationOnce(() => new Promise(resolve => { acknowledge = resolve; }));
    const pending = f.commit(review); f.rekey();
    const afterRekey = f.state(); acknowledge(3); await pending;
    expect(f.state()).toEqual(afterRekey); expect(afterRekey.conversation.currentEpoch).toBe(1);
  });
  test('returns an exact message ID on ambiguous delivery without retrying', async () => {
    const f = fixture(), review = await f.prepare('request', requestOptions);
    f.postMessage.mockImplementationOnce(async (_id, bytes) => { f.posts.push(bytes); throw new Error('response lost'); });
    expect(await f.commit(review)).toMatchObject({ status: 'delivery_unknown', messageId: expect.stringMatching(/^[0-9a-f]{32}$/) });
    await expect(f.commit(review)).rejects.toMatchObject({ code: 'review_unavailable' });
    expect(f.posts).toHaveLength(1); expect(f.state().cursor).toBe(2);
  });
  test.each(['approve', 'disapprove', 'gov-approve', 'gov-disapprove'] as const)('reviews and sends %s using verified subjects', async action => {
    const f = fixture(), subject = action.startsWith('gov-') ? f.proposal() : f.request('vendor:request:2026');
    const id = 'request_id' in subject ? subject.request_id : subject.proposal_id;
    const review = await f.prepare(action, { id });
    expect(review.review.subject.subject).toMatchObject({ type: subject.type });
    expect(review.review.subject.subject.signature).toBeUndefined();
    expect(review.review.body.signature).toBeUndefined();
    await f.commit(review); expect(f.receivePosted()).toBe('accepted');
    const status = f.service.status(f.scope) as any;
    expect(status.entries[0].id).toBe(id);
    expect(status.entries[0].approvals).toBe(action.endsWith('disapprove') ? 1 : 2);
  });
  test('rechecks terminal execution and rejects forged terminal or request input', async () => {
    const f = fixture(), body = f.request(), review = await f.prepare('approve', { id: body.request_id });
    const terminal = { type: 'gate.executed', request_id: body.request_id, executed_at: new Date().toISOString(), execution_status_code: 200 };
    const forged = serializeEnvelope(createMessage(f.group.inviter, f.state().conversation, terminal.type, new TextEncoder().encode(JSON.stringify(terminal))));
    expect(receiveQntmEnvelope(f.scope.store, f.scope.binding, f.state().cursor + 1, forged)).toBe('invalid');
    f.deliver(f.gateway, terminal.type, terminal);
    await expect(f.commit(review)).rejects.toMatchObject({ code: 'subject_unavailable' });
    await expect(f.prepare('approve', { id: 'untrusted-message-claim' })).rejects.toMatchObject({ code: 'subject_unavailable' });
    expect(f.posts).toHaveLength(0);
  });
  test('seals credentials to the accepted gateway and excludes plaintext from the review', async () => {
    const f = fixture(), secret = 'sample-test-only-secret';
    const review = await f.prepare('secret', { service: 'demo', value: secret });
    expect(JSON.stringify(review)).not.toContain(secret);
    expect(review.review.subject).toMatchObject({ secretBytes: Buffer.byteLength(secret), secretSha256: expect.any(String) });
    expect(review.review.body.encrypted_blob).toBeUndefined();
    await f.commit(review); const body = f.decodePosted();
    expect(new TextDecoder().decode(openSecret(f.gateway.privateKey, f.identity.publicKey, base64UrlDecode(body.encrypted_blob)))).toBe(secret);
    expect(() => openSecret(f.group.inviter.privateKey, f.identity.publicKey, base64UrlDecode(body.encrypted_blob))).toThrow();
    expect(f.receivePosted()).toBe('accepted');
  });
  test('creates a governance proposal with majority requirements', async () => {
    const f = fixture(), review = await f.prepare('propose', { proposalType: 'floor_change', proposedFloor: 1 });
    expect(review.review.body).toMatchObject({ proposed_floor: 1, required_approvals: 2 });
    await f.commit(review); expect(f.receivePosted()).toBe('accepted');
  });
  test('bounds pending reviews and rejects unsupported or oversized options before sending', async () => {
    const f = fixture();
    await expect(f.prepare('request', { ...requestOptions, identity: 'override' })).rejects.toMatchObject({ code: 'invalid_options' });
    await expect(f.prepare('request', { ...requestOptions, payload: 'x'.repeat(65536) })).rejects.toMatchObject({ code: 'options_too_large' });
    const reviews = await Promise.all(Array.from({ length: 64 }, () => f.prepare('request', requestOptions)));
    await expect(f.prepare('request', requestOptions)).rejects.toMatchObject({ code: 'review_capacity' });
    for (const review of reviews) f.service.cancel(f.scope, review.reviewToken);
    f.service.cancel(f.scope, (await f.prepare('request', requestOptions)).reviewToken);
    expect(f.posts).toHaveLength(0);
  });
});

describe('participant initiated gateway admission', () => {
  test('bounds concurrent invitation preparation before awaiting the gateway', async () => {
    const f = fixture(false), abort = new AbortController();
    let release!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    const original = f.createInvitation.getMockImplementation()!;
    f.createInvitation.mockImplementation(async (...args) => { await blocked; return original(...args); });
    const pending = Array.from({ length: 64 }, () => f.service.prepare(f.scope, 'invite', { gatewayUrl: 'https://gateway.example.test' }, abort.signal));
    await expect(f.prepare('invite', { gatewayUrl: 'https://gateway.example.test' })).rejects.toMatchObject({ code: 'review_capacity' });
    abort.abort(); release();
    const outcomes = await Promise.allSettled(pending);
    expect(outcomes.every(result => result.status === 'rejected' && result.reason.code === 'cancelled')).toBe(true);
    f.service.cancel(f.scope, (await f.prepare('invite', { gatewayUrl: 'https://gateway.example.test' })).reviewToken);
    expect(f.posts).toHaveLength(0);
  });
  test('persists only sealed bootstrap, requires chat acceptance, and retries after process restart without another POST', async () => {
    const f = fixture(false); f.promote.mockRejectedValueOnce(new Error('HTTP response lost'));
    const review = await f.prepare('invite', { gatewayUrl: 'https://gateway.example.test', floor: 2 });
    expect(f.posts).toHaveLength(0); expect(f.promote).not.toHaveBeenCalled();
    expect(review.review.context.gateway.publicKey).toBe(base64UrlEncode(f.gateway.publicKey));
    expect(await f.commit(review)).toMatchObject({ status: 'invitation_posted_bootstrap_pending' });
    const saved = JSON.parse(readFileSync(f.bootstrapPath, 'utf8'));
    expect(statSync(f.bootstrapPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(f.bootstrapPath, 'utf8')).not.toContain(base64UrlEncode(f.state().conversation.keys.aeadKey));
    const unsealed = JSON.parse(new TextDecoder().decode(openSecret(f.gateway.privateKey, f.identity.publicKey, base64UrlDecode(saved.request.sealed))));
    expect(unsealed).toMatchObject({ conv_id: f.scope.binding.conversationId, conv_epoch: 0, invitation_msg_id: saved.messageId });
    expect(f.service.status(f.scope)).toMatchObject({ status: 'no_invitation' });
    await expect(f.prepare('retry-bootstrap')).rejects.toMatchObject({ code: 'bootstrap_stale' });
    expect(f.receivePosted()).toBe('accepted');
    const resumed = new QntmGatewayActions(f.deps);
    const retry = await resumed.prepare(f.scope, 'retry-bootstrap') as Review;
    expect(await resumed.commit(f.scope, retry.reviewToken, retry.reviewHash)).toMatchObject({ status: 'awaiting_signed_acceptance' });
    expect(f.posts).toHaveLength(1); expect(f.promote).toHaveBeenCalledTimes(2);
    expect(f.promote.mock.calls[0][0]).toEqual(f.promote.mock.calls[1][0]);
    expect(f.service.status(f.scope)).toMatchObject({ status: 'awaiting_signed_acceptance' });
    await expect(f.prepare('request', requestOptions)).rejects.toThrow('accepted gateway');
    f.accept(); expect(f.service.status(f.scope)).toMatchObject({ status: 'accepted' });
    expect(existsSync(f.bootstrapPath)).toBe(false);
  });
  test('does not deliver bootstrap when private persistence fails', async () => {
    const f = fixture(false), service = new QntmGatewayActions({ ...f.deps, saveBootstrap: () => { throw new Error('disk full'); } });
    const review = await service.prepare(f.scope, 'invite', { gatewayUrl: 'https://gateway.example.test' }) as Review;
    expect(await service.commit(f.scope, review.reviewToken, review.reviewHash)).toMatchObject({ status: 'invitation_posted_bootstrap_not_saved' });
    expect(f.posts).toHaveLength(1); expect(f.promote).not.toHaveBeenCalled();
  });
  test('rejects changed saved bootstrap, mismatched invitations and insecure gateway URLs', async () => {
    const f = fixture(false);
    for (const gatewayUrl of ['http://public.example.test', 'https://user:password@example.test', 'https://example.test/?secret=1']) {
      await expect(f.prepare('invite', { gatewayUrl })).rejects.toMatchObject({ code: 'invalid_gateway_url' });
    }
    f.createInvitation.mockImplementationOnce(async () => ({ invitation_id: 'bad' } as GatewayInvitation));
    await expect(f.prepare('invite', { gatewayUrl: 'https://gateway.example.test' })).rejects.toMatchObject({ code: 'invalid_invitation' });
    const review = await f.prepare('invite', { gatewayUrl: 'https://gateway.example.test' }); await f.commit(review); f.receivePosted();
    const retry = await f.prepare('retry-bootstrap');
    const saved = JSON.parse(readFileSync(f.bootstrapPath, 'utf8')); saved.url = 'https://different.example.test';
    writeFileSync(f.bootstrapPath, JSON.stringify(saved));
    await expect(f.commit(retry)).rejects.toMatchObject({ code: 'bootstrap_stale' });
    expect(f.posts).toHaveLength(1); expect(f.promote).toHaveBeenCalledTimes(1);
  });
});

describe('native tool permissions and routing', () => {
  function native(f: ReturnType<typeof fixture>): OpenClawPluginToolContext {
    return { agentId: 'main', sessionId: 'host-session', messageChannel: 'qntm', agentAccountId: 'default',
      nativeChannelId: f.scope.binding.conversationId, requesterSenderId: toHex(f.group.inviter.keyID), getRuntimeConfig: () => f.cfg };
  }
  test.each([
    { messageChannel: 'webchat' }, { agentAccountId: 'unknown' }, { sessionId: undefined },
    { nativeChannelId: 'ff'.repeat(16) }, { deliveryContext: { channel: 'other' } },
    { deliveryContext: { channel: 'qntm', accountId: 'other' } },
  ])('does not expose the optional tool without an unambiguous native route: %j', override => {
    const f = fixture();
    expect(createQntmGatewayTool({ ...native(f), ...override }, f.cfg, f.service, { stateDir: f.stateDir })).toBeNull();
  });
  test('requires explicit local actions; arguments cannot override the trusted route or identity', async () => {
    const f = fixture(), ctx = native(f), options = { stateDir: f.stateDir };
    const tool = createQntmGatewayTool(ctx, f.cfg, f.service, options)!;
    const result = await tool.execute('a', { operation: 'prepare', action: 'request', options: requestOptions, accountId: 'override-secret-marker' });
    expect(result.details).toMatchObject({ status: 'error', code: 'invalid_arguments' });
    expect(JSON.stringify(result)).not.toContain('override-secret-marker');
    f.cfg.channels!.qntm!.conversations!.group!.gatewayActions = [];
    expect(createQntmGatewayTool(ctx, f.cfg, f.service, options)).toBeNull();
    expect((await tool.execute('b', { operation: 'status' })).details).toMatchObject({ status: 'error', code: 'disabled' });
    expect(f.posts).toHaveLength(0);
  });
  test('rechecks runtime config on every invocation and binds reviews to requester and session', async () => {
    const f = fixture(), ctx = native(f), options = { stateDir: f.stateDir };
    const tool = createQntmGatewayTool(ctx, f.cfg, f.service, options)!;
    const review = (await tool.execute('a', { operation: 'prepare', action: 'request', options: requestOptions })).details as Review;
    expect(review.status).toBe('review_required');
    for (const override of [{ sessionId: 'reset-session' }, { requesterSenderId: 'other-peer' }]) {
      const other = createQntmGatewayTool({ ...ctx, ...override }, f.cfg, f.service, options)!;
      expect((await other.execute('b', { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).details)
        .toMatchObject({ status: 'error', code: 'review_unavailable' });
    }
    f.cfg.channels!.qntm!.conversations!.group!.gatewayActions = ['invite'];
    expect((await tool.execute('c', { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash })).details)
      .toMatchObject({ status: 'error', code: 'action_denied' });
    expect(f.posts).toHaveLength(0);
  });
  test('uses the host account and session without letting a qntm peer select them', () => {
    const f = fixture(), scope = resolveGatewayToolScope(native(f), f.cfg, { stateDir: f.stateDir });
    expect(scope.binding.conversationId).toBe(f.scope.binding.conversationId);
    expect(scope.account.identity!.publicKey).toEqual(f.identity.publicKey);
    expect(scope.key).not.toContain(toHex(f.group.inviter.keyID));
  });
  test('honors cancellation before sending and during asynchronous invitation preparation', async () => {
    const f = fixture(false), ctx = native(f), tool = createQntmGatewayTool(ctx, f.cfg, f.service, { stateDir: f.stateDir })!;
    const abort = new AbortController(); abort.abort();
    expect((await tool.execute('a', { operation: 'prepare', action: 'invite', options: { gatewayUrl: 'https://gateway.example.test' } }, abort.signal)).details)
      .toMatchObject({ code: 'cancelled' });
    expect(f.createInvitation).not.toHaveBeenCalled();
    const active = new AbortController();
    const original = f.createInvitation.getMockImplementation()!;
    f.createInvitation.mockImplementationOnce(async (...args) => { active.abort(); return original(...args); });
    expect((await tool.execute('b', { operation: 'prepare', action: 'invite', options: { gatewayUrl: 'https://gateway.example.test' } }, active.signal)).details)
      .toMatchObject({ code: 'cancelled' });
    const review = (await tool.execute('c', { operation: 'prepare', action: 'invite', options: { gatewayUrl: 'https://gateway.example.test' } })).details as Review;
    expect((await tool.execute('d', { operation: 'commit', reviewToken: review.reviewToken, reviewHash: review.reviewHash }, abort.signal)).details)
      .toMatchObject({ code: 'cancelled' });
    expect(f.posts).toHaveLength(0); expect(f.promote).not.toHaveBeenCalled();
  });
});
