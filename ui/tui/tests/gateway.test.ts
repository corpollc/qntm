import { rmSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createGateRequestBody, createGatewayProposalBody, createGroupRekeyBody, createGroupRemoveBody,
  QSP1Suite, deserializeEnvelope, decryptGatewayMessage, createMessage, serializeEnvelope,
  base64UrlEncode, GateClient,
} from '@corpollc/qntm';
import { Store } from '../src/lib/store.js';
import { GatewayActions } from '../src/lib/gateway.js';
import { applyIncomingEnvelope } from '../src/lib/poller.js';
import { gatewayFixture } from './support/gateway.js';

const requestOptions = { service: 'demo', endpoint: '/check', verb: 'POST', targetUrl: 'https://api.example.test/check', payload: { action: 'test' } };
describe('terminal gateway actions and durable receive state', () => {
  const dirs: string[] = [];
  afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

  it('reviews exact peer requests, posts canonical approval and withdrawal, and never advances a receive cursor on send', async () => {
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), requestOptions);
    await f.deliver(f.bob, request.type, request);
    const review = await f.actions.prepare(f.convId, 'approve', request.request_id.slice(0, 8));
    expect(review.details).toContain(request.target_url);
    expect(review.details).toContain('"action": "test"');
    expect(review.details).toContain(base64UrlEncode(f.gateway.publicKey));
    expect(f.dropbox.postMessage).not.toHaveBeenCalled();
    const cursor = f.store.loadCursor(f.convId);
    const receipt = await f.actions.confirm(f.convId);
    expect(f.store.loadCursor(f.convId)).toBe(cursor);
    const envelope = deserializeEnvelope(vi.mocked(f.dropbox.postMessage).mock.calls[0][1]);
    expect(receipt).toContain(`Message ${Buffer.from(envelope.msg_id).toString('hex')}.`);
    const verified = decryptGatewayMessage(envelope, f.store.getConversationCrypto(f.convId)!, f.context(), { request });
    expect(verified.body.type).toBe('gate.approval');
    expect(f.store.gatewaySession(f.convId, f.alice).events.some(e => e.body.type === 'gate.approval')).toBe(false);
    await applyIncomingEnvelope(f.store, f.dropbox, f.alice, f.convId, serializeEnvelope(envelope), cursor + 1);
    expect(f.actions.status(f.convId)).toContain('2/2 approvals');
    await f.actions.prepare(f.convId, 'disapprove', request.request_id);
    await f.actions.confirm(f.convId);
    const withdrawal = deserializeEnvelope(vi.mocked(f.dropbox.postMessage).mock.calls[1][1]);
    expect(decryptGatewayMessage(withdrawal, f.store.getConversationCrypto(f.convId)!, f.context(), { request }).body.type).toBe('gate.disapproval');
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('No reviewed action');
  });

  it('cancels without posting and rejects a terminal request that changed after review', async () => {
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), requestOptions);
    await f.deliver(f.bob, request.type, request);
    await f.actions.prepare(f.convId, 'approve', request.request_id); f.actions.cancel();
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('No reviewed action');
    await f.actions.prepare(f.convId, 'approve', request.request_id);
    await f.deliver(f.gateway, 'gate.executed', { type: 'gate.executed', request_id: request.request_id, executed_at: new Date().toISOString(), execution_status_code: 200 });
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('no longer pending');
    expect(f.dropbox.postMessage).not.toHaveBeenCalled();
  });

  it('rejects expiry at confirmation without posting a previously reviewed vote', async () => {
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), { ...requestOptions, expiresInSeconds: 5 });
    await f.deliver(f.bob, request.type, request);
    await f.actions.prepare(f.convId, 'approve', request.request_id);
    vi.spyOn(Date, 'now').mockReturnValue(Date.parse(request.expires_at));
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('no longer pending');
    expect(f.dropbox.postMessage).not.toHaveBeenCalled();
  });

  it('blocks forged events, ambiguous IDs, stale rekeys and removed signers', async () => {
    const f = await gatewayFixture(dirs);
    const request = createGateRequestBody(f.bob, f.context(), { ...requestOptions, requestId: 'same-first' });
    const other = createGateRequestBody(f.bob, f.context(), { ...requestOptions, requestId: 'same-second' });
    await f.deliver(f.bob, request.type, request); await f.deliver(f.bob, other.type, other);
    await expect(f.actions.prepare(f.convId, 'approve', 'same')).rejects.toThrow('ambiguous');
    const forged = await f.deliver(f.bob, 'gate.executed', { type: 'gate.executed', request_id: request.request_id, executed_at: new Date().toISOString(), execution_status_code: 200 });
    expect(forged.message).toBeNull();
    await f.actions.prepare(f.convId, 'approve', request.request_id);
    const root = new QSP1Suite().generateGroupKey();
    const rekey = createGroupRekeyBody(root, 1, [f.alice, f.bob].map(i => ({ kid: i.keyID, publicKey: i.publicKey })), f.store.getConversationCrypto(f.convId)!.id);
    await f.deliver(f.gateway, 'group_rekey', rekey);
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('changed since review');
    await f.deliver(f.gateway, 'group_remove', createGroupRemoveBody([f.alice.keyID]));
    await expect(f.actions.prepare(f.convId, 'approve', request.request_id)).rejects.toThrow('removed');
    expect(f.dropbox.postMessage).not.toHaveBeenCalled();
  });

  it('commits keys, protocol state, history and cursor together across restart and exact replay', async () => {
    const f = await gatewayFixture(dirs);
    const root = new QSP1Suite().generateGroupKey();
    const rekey = createGroupRekeyBody(root, 1, [f.alice, f.bob].map(i => ({ kid: i.keyID, publicKey: i.publicKey })), f.store.getConversationCrypto(f.convId)!.id);
    const received = await f.deliver(f.gateway, 'group_rekey', rekey);
    const restarted = new Store(f.dir, f.store.dropboxUrl);
    expect(restarted.getConversationCrypto(f.convId)!.keys.root).toEqual(root);
    expect(restarted.gatewaySession(f.convId, f.alice).gateway!.context.epoch).toBe(1);
    expect(restarted.loadCursor(f.convId)).toBe(f.seq);
    expect(restarted.loadHistory(f.convId).at(-1)!.bodyType).toBe('group_rekey');
    await applyIncomingEnvelope(restarted, f.dropbox, f.alice, f.convId, serializeEnvelope(received.envelope), f.seq + 1);
    expect(restarted.loadHistory(f.convId).filter(m => m.bodyType === 'group_rekey')).toHaveLength(1);
    const message = createMessage(f.bob, restarted.getConversationCrypto(f.convId)!, 'text', new TextEncoder().encode('after restart'));
    expect((await applyIncomingEnvelope(restarted, f.dropbox, f.alice, f.convId, serializeEnvelope(message), f.seq + 2))!.text).toBe('after restart');
    expect(statSync(join(f.dir, 'conversations.json')).mode & 0o777).toBe(0o600);
    expect(statSync(f.dir).mode & 0o777).toBe(0o700);
  });

  it('preserves the previous checkpoint and throws when persistence fails after decryption', async () => {
    const f = await gatewayFixture(dirs);
    const before = readFileSync(join(f.dir, 'conversations.json'), 'utf8');
    vi.spyOn(f.store, 'saveConversations').mockImplementation(() => { throw new Error('disk full'); });
    await expect(f.deliver(f.bob, 'text', 'must replay')).rejects.toThrow('disk full');
    expect(readFileSync(join(f.dir, 'conversations.json'), 'utf8')).toBe(before);
  });

  it('creates requests, sealed credentials and governance changes from strict files without leaking credentials', async () => {
    const f = await gatewayFixture(dirs);
    const filename = join(f.dir, 'action.json');
    writeFileSync(filename, JSON.stringify(requestOptions), { mode: 0o600 });
    await f.actions.prepare(f.convId, 'request', filename); await f.actions.confirm(f.convId);
    writeFileSync(filename, JSON.stringify({ service: 'demo', value: 'disposable-credential-value', ttl: 60 }));
    const review = await f.actions.prepare(f.convId, 'secret', filename);
    expect(review.details).not.toContain('disposable-credential-value');
    expect(review.details).toContain('secret_sha256'); expect(review.details).toContain('Authorization');
    await f.actions.confirm(f.convId);
    writeFileSync(filename, JSON.stringify({ proposalType: 'floor_change', proposedFloor: 1 }));
    const proposalReview = await f.actions.prepare(f.convId, 'propose', filename);
    expect(proposalReview.details).toContain('"proposed_floor": 1'); await f.actions.confirm(f.convId);
    for (const [, bytes] of vi.mocked(f.dropbox.postMessage).mock.calls) {
      const event = decryptGatewayMessage(deserializeEnvelope(bytes), f.store.getConversationCrypto(f.convId)!, f.context());
      expect(['gate.request', 'gate.secret', 'gov.propose']).toContain(event.body.type);
    }
    writeFileSync(filename, '{"value":"disposable-credential-value",INVALID');
    await expect(f.actions.prepare(f.convId, 'secret', filename)).rejects.toThrow('Options file is not valid JSON');
    writeFileSync(filename, JSON.stringify({ ...requestOptions, unknown: 'x' }));
    await expect(f.actions.prepare(f.convId, 'request', filename)).rejects.toThrow('unsupported fields');
  });

  it('reviews and verifies governance approval and withdrawal', async () => {
    const f = await gatewayFixture(dirs);
    const proposal = createGatewayProposalBody(f.bob, f.context(), { proposalType: 'floor_change', proposedFloor: 1 });
    await f.deliver(f.bob, proposal.type, proposal);
    for (const command of ['gov-approve', 'gov-disapprove']) {
      const review = await f.actions.prepare(f.convId, command, proposal.proposal_id);
      expect(review.details).toContain('"proposed_floor": 1');
      await f.actions.confirm(f.convId);
      const bytes = vi.mocked(f.dropbox.postMessage).mock.lastCall![1];
      expect(decryptGatewayMessage(deserializeEnvelope(bytes), f.store.getConversationCrypto(f.convId)!, f.context(), { proposal }).body.type).toBe(command === 'gov-approve' ? 'gov.approve' : 'gov.disapprove');
    }
  });

  it('reviews an invitation before disclosing keys and keeps an HTTP retry separate from chat acceptance', async () => {
    const f = await gatewayFixture(dirs, false);
    vi.spyOn(GateClient.prototype, 'createInvitation').mockImplementation(async (pk, id) => ({ ...f.invitation, invitation_id: id, inviter_public_key: pk }));
    const promote = vi.spyOn(GateClient.prototype, 'promote').mockRejectedValue(new Error('network down'));
    const review = await f.actions.prepare(f.convId, 'gate', 'invite https://gateway.example.test 2');
    expect(review.details).toContain('receive the current conversation keys');
    expect(review.details).toContain('https://gateway.example.test');
    expect(promote).not.toHaveBeenCalled(); expect(f.dropbox.postMessage).not.toHaveBeenCalled();
    await expect(f.actions.confirm(f.convId)).rejects.toThrow('/gate retry');
    expect(f.store.findConversation(f.convId)!.pendingGatewayBootstrap).toBeDefined();
    promote.mockResolvedValue({ status: 'joined', gateway_public_key: f.invitation.gateway_public_key, gateway_kid: f.invitation.gateway_kid, invitation_id: 'test' });
    const restarted = new GatewayActions(new Store(f.dir, f.store.dropboxUrl), f.dropbox, f.alice);
    await restarted.retry(f.convId);
    expect(f.store.gatewaySession(f.convId, f.alice).gateway?.accepted).not.toBe(true);
    expect(f.dropbox.postMessage).toHaveBeenCalledTimes(1);
    expect(promote.mock.calls[0][0]).toEqual(promote.mock.calls[1][0]);
  });
});
