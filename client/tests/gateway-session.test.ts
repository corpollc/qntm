import { describe, expect, it } from 'vitest';
import {
  generateIdentity, createInvite, deriveConversationKeys, createConversation, addParticipant,
  createGatewaySession, receiveConversationEvent, sessionGatewayContext, createMessage,
  createGatewayInviteBody, gatewayInvitationHash, base64UrlEncode,
  createGateRequestBody, createGateApprovalBody, createGateDisapprovalBody, scanGateRequest,
  createGroupRemoveBody, createGroupRekeyBody, QSP1Suite,
} from '../src/index.js';
import type { GatewaySessionState, Identity, Conversation, OuterEnvelope } from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const encode = (body: unknown) => new TextEncoder().encode(JSON.stringify(body));
function setup(local?: Identity) {
  const alice = generateIdentity(), bob = local ?? generateIdentity(), gateway = generateIdentity();
  const invite = createInvite(alice, 'group');
  let conversation = createConversation(invite, deriveConversationKeys(invite));
  addParticipant(conversation, bob.publicKey);
  let state = createGatewaySession(conversation, [alice.publicKey, bob.publicKey]);
  const participants = Object.fromEntries([alice, bob].map(i => [base64UrlEncode(i.keyID), base64UrlEncode(i.publicKey)]));
  const invitation = { invitation_id: 'ab'.repeat(16), inviter_public_key: base64UrlEncode(alice.publicKey),
    gateway_public_key: base64UrlEncode(gateway.publicKey), gateway_kid: base64UrlEncode(gateway.keyID), expires_at: Math.floor(Date.now() / 1000) + 600 };
  const invitationBody = createGatewayInviteBody(invitation, conversation, participants, 2);
  const invitationEnvelope = createMessage(alice, conversation, 'gate.promote', encode(invitationBody));
  const acceptance = { type: 'gate.accept', invitation_id: invitation.invitation_id, invitation_msg_id: hex(invitationEnvelope.msg_id),
    invitation_hash: gatewayInvitationHash(JSON.stringify(invitationBody)), conv_id: hex(conversation.id), conv_epoch: 0,
    gateway_kid: invitation.gateway_kid, gateway_public_key: invitation.gateway_public_key };
  function receive(envelope: OuterEnvelope) {
    const result = receiveConversationEvent(envelope, conversation, alice, state);
    conversation = result.conversation; state = result.state;
    return result;
  }
  function deliver(sender: Identity, type: string, body: unknown) {
    const envelope = createMessage(sender, conversation, type, body instanceof Uint8Array ? body : encode(body));
    return receive(envelope);
  }
  function accept() { receive(invitationEnvelope); deliver(gateway, 'gate.accept', acceptance); }
  return { alice, bob, gateway, receive, deliver, accept, invitationBody, invitationEnvelope, acceptance,
    get state() { return state; }, get conversation() { return conversation; } };
}

describe('portable authenticated gateway session', () => {
  it('requires a signed invitation and the matching gateway acceptance before actions', () => {
    const f = setup();
    expect(() => sessionGatewayContext(f.state)).toThrow('accepted gateway');
    f.receive(f.invitationEnvelope);
    expect(() => sessionGatewayContext(f.state)).toThrow('accepted gateway');
    const before = JSON.stringify(f.state);
    expect(() => f.deliver(f.bob, 'gate.accept', f.acceptance)).toThrow('configured gateway');
    expect(() => f.deliver(f.gateway, 'gate.accept', { ...f.acceptance, invitation_msg_id: 'cd'.repeat(16) })).toThrow('verified invitation');
    expect(JSON.stringify(f.state)).toBe(before);
    f.deliver(f.gateway, 'gate.accept', f.acceptance);
    expect(sessionGatewayContext(f.state).gateway.kid).toBe(base64UrlEncode(f.gateway.keyID));
    expect(() => f.deliver(f.alice, 'gate.promote', f.invitationBody)).toThrow('already accepted');
  });

  it('rejects a stranger, different keys, and omission of a known member from an invitation', () => {
    const f = setup(), stranger = generateIdentity();
    expect(() => f.deliver(stranger, 'gate.promote', f.invitationBody)).toThrow('known participant');
    expect(() => f.deliver(f.alice, 'gate.promote', { ...f.invitationBody, keys_hash: '00'.repeat(32) })).toThrow('keys differ');
    const participants = { [base64UrlEncode(f.alice.keyID)]: base64UrlEncode(f.alice.publicKey) };
    expect(() => f.deliver(f.alice, 'gate.promote', { ...f.invitationBody, participants, floor: 1 })).toThrow('known participant');
    expect(f.state.gateway).toBeUndefined();
  });

  it('preserves unknown public-key IDs until their authenticated sender is learned', () => {
    const f = setup();
    const state = createGatewaySession(f.conversation, [f.alice.publicKey]);
    const result = receiveConversationEvent(createMessage(f.bob, f.conversation, 'text', encode('Hello')), f.conversation, f.alice, state);
    expect(result.state.participants[base64UrlEncode(f.bob.keyID)]).toBe(base64UrlEncode(f.bob.publicKey));
    expect(result.conversation.participants.map(hex).sort()).toEqual(f.conversation.participants.map(hex).sort());
  });

  it('verifies request/vote signatures and retains relay-order votes across a saved checkpoint', () => {
    const f = setup(); f.accept();
    const context = sessionGatewayContext(f.state);
    const request = createGateRequestBody(f.alice, context, { service: 'demo', endpoint: '/', verb: 'GET', targetUrl: 'https://example.test/' });
    f.deliver(f.alice, 'gate.request', request);
    const vote = createGateApprovalBody(f.bob, context, request);
    expect(() => f.deliver(f.bob, 'gate.approval', { ...vote, signature: base64UrlEncode(new Uint8Array(64)) })).toThrow('approval signature');
    f.deliver(f.bob, 'gate.approval', vote);
    expect(scanGateRequest(f.state.events, context, request.request_id)?.status).toBe('approved');
    const saved = JSON.parse(JSON.stringify(f.state)) as GatewaySessionState;
    const disapproval = createGateDisapprovalBody(f.bob, context, request);
    const result = receiveConversationEvent(createMessage(f.bob, f.conversation, disapproval.type, encode(disapproval)), f.conversation, f.alice, saved);
    expect(scanGateRequest(result.state.events, context, request.request_id)?.approvals).toBe(1);
    expect(saved.events).toHaveLength(f.state.events.length);
  });

  it('trusts membership and rekey controls only from the accepted gateway, excluding removed identities', () => {
    const f = setup(); f.accept();
    let bobState = structuredClone(f.state), bobConversation = structuredClone(f.conversation);
    const oldConversation = structuredClone(f.conversation);
    const remove = createGroupRemoveBody([f.bob.keyID]);
    const before = JSON.stringify(f.state);
    expect(() => f.deliver(f.alice, 'group_remove', remove)).toThrow('configured authority');
    expect(JSON.stringify(f.state)).toBe(before);
    const removal = createMessage(f.gateway, oldConversation, 'group_remove', remove);
    f.receive(removal);
    let bobResult = receiveConversationEvent(removal, bobConversation, f.bob, bobState);
    bobState = bobResult.state; bobConversation = bobResult.conversation;
    const root = new QSP1Suite().generateGroupKey();
    const body = createGroupRekeyBody(root, 1, [{ kid: f.alice.keyID, publicKey: f.alice.publicKey }], oldConversation.id);
    const rekey = createMessage(f.gateway, oldConversation, 'group_rekey', body);
    f.receive(rekey);
    bobResult = receiveConversationEvent(rekey, bobConversation, f.bob, bobState);
    expect(f.conversation.currentEpoch).toBe(1);
    expect(sessionGatewayContext(f.state).epoch).toBe(1);
    expect(bobResult.state.removed).toBe(true);
    expect(() => sessionGatewayContext(bobResult.state)).toThrow('removed');
    expect(hex(f.conversation.keys.root)).toBe(hex(root));
    // A crash between state and cursor persistence replays the same old-epoch
    // rekey. Its exact authenticated digest is sufficient to skip it safely.
    expect(f.receive(rekey).duplicate).toBe(true);
    const fresh = createMessage(f.alice, f.conversation, 'text', encode('new epoch'));
    expect(() => receiveConversationEvent(fresh, bobConversation, f.bob, bobResult.state)).toThrow('epoch');
    expect(f.receive(fresh).duplicate).toBe(false);
  });

  it('fails closed on a forged terminal marker, future epoch or conflicting envelope ID', () => {
    const f = setup(); f.accept();
    expect(() => f.deliver(f.bob, 'gate.executed', { type: 'gate.executed', request_id: 'demo', executed_at: new Date().toISOString(), execution_status_code: 200 })).toThrow('configured gateway');
    const future: Conversation = { ...f.conversation, currentEpoch: 3 };
    expect(() => f.receive(createMessage(f.alice, future, 'text', encode('future')))).toThrow('epoch');
    const modified = structuredClone(f.invitationEnvelope); modified.ciphertext[0] ^= 1;
    expect(() => f.receive(modified)).toThrow('Conflicting message ID');
  });
});
