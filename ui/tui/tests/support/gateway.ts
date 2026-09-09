import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { vi } from 'vitest';
import {
  generateIdentity, base64UrlEncode, createMessage, serializeEnvelope,
  createGatewayInviteBody, gatewayInvitationHash, sessionGatewayContext,
  DropboxClient, type Identity,
} from '@corpollc/qntm';
import { Store, bytesToHex } from '../../src/lib/store.js';
import { applyIncomingEnvelope } from '../../src/lib/poller.js';
import { GatewayActions } from '../../src/lib/gateway.js';

export async function gatewayFixture(dirs: string[], accepted = true) {
  const dir = mkdtempSync(join(tmpdir(), 'qntm-tui-gateway-')); dirs.push(dir);
  const store = new Store(dir, 'https://relay.example.test');
  const alice = store.generateIdentity(), bob = generateIdentity(), gateway = generateIdentity();
  const { convId } = store.createInvite(alice, 'Gateway test');
  const dropbox = new DropboxClient(store.dropboxUrl);
  vi.spyOn(dropbox, 'submitReceipt').mockResolvedValue({ recorded: true, deleted: false, receipts: 1, required_acks: 2 });
  vi.spyOn(dropbox, 'postMessage').mockResolvedValue(100);
  let seq = 0;
  async function deliver(sender: Identity, type: string, body: unknown) {
    const conversation = store.getConversationCrypto(convId)!;
    const envelope = createMessage(sender, conversation, type, body instanceof Uint8Array ? body : new TextEncoder().encode(JSON.stringify(body)));
    const message = await applyIncomingEnvelope(store, dropbox, alice, convId, serializeEnvelope(envelope), ++seq);
    return { message, envelope };
  }
  await deliver(bob, 'text', 'Hello from Bob');
  const conversation = store.getConversationCrypto(convId)!;
  const participants = store.gatewaySession(convId, alice).participants;
  const invitation = { invitation_id: 'ab'.repeat(16), inviter_public_key: base64UrlEncode(alice.publicKey), gateway_public_key: base64UrlEncode(gateway.publicKey), gateway_kid: base64UrlEncode(gateway.keyID), expires_at: Math.floor(Date.now() / 1000) + 600 };
  if (accepted) {
    const body = createGatewayInviteBody(invitation, conversation, participants, 2);
    const promoted = await deliver(alice, body.type, body);
    await deliver(gateway, 'gate.accept', { type: 'gate.accept', invitation_id: invitation.invitation_id, invitation_msg_id: bytesToHex(promoted.envelope.msg_id), invitation_hash: gatewayInvitationHash(JSON.stringify(body)), conv_id: convId, conv_epoch: 0, gateway_kid: invitation.gateway_kid, gateway_public_key: invitation.gateway_public_key });
  }
  return { dir, store, alice, bob, gateway, dropbox, convId, invitation, deliver,
    actions: new GatewayActions(store, dropbox, alice),
    context: () => sessionGatewayContext(store.gatewaySession(convId, alice)),
    get seq() { return seq; },
  };
}
