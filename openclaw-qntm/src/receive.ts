import { base64UrlEncode, deserializeEnvelope, receiveConversationEvent } from '@corpollc/qntm';
import { QntmCheckpointStore, MAX_PENDING_DISPATCHES, validateInbound, type QntmInbound } from './checkpoint.js';
import { toHex } from './qntm.js';
import { clearGatewayBootstrap } from './gateway-actions.js';
import type { ResolvedQntmBinding } from './types.js';

/** The relay cursor, updated keys and pending host dispatch are one local commit. */
export function receiveQntmEnvelope(store: QntmCheckpointStore, binding: ResolvedQntmBinding,
  sequence: number, bytes: Uint8Array): 'duplicate' | 'invalid' | 'accepted' {
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error('Invalid qntm relay sequence');
  const previous = store.load(binding);
  if (sequence <= previous.cursor) return 'duplicate';
  let event;
  try {
    event = receiveConversationEvent(deserializeEnvelope(bytes), previous.conversation, store.account.identity!, previous.session);
  } catch {
    store.commit(binding, { ...previous, cursor: sequence });
    return 'invalid';
  }
  let inbound: QntmInbound | undefined;
  let rejectedBody = false;
  if (!event.duplicate && !event.state.removed && sequence > previous.suppressThrough) {
    const senderKid = toHex(event.message.inner.sender_kid);
    const sender = base64UrlEncode(event.message.inner.sender_kid);
    const member = !event.state.gateway?.accepted || Boolean(event.state.participants[sender])
      || sender === event.state.gateway.context.gateway.kid;
    const mentioned = binding.trigger !== 'mention' || binding.triggerNames.some(name => event.text.toLowerCase().includes(name.toLowerCase()));
    if (senderKid !== toHex(store.account.identity!.keyID) && member && mentioned) {
      try { inbound = validateInbound({
        conversationId: binding.conversationId, messageId: toHex(event.message.envelope.msg_id),
        senderKid, senderPublicKey: base64UrlEncode(event.message.inner.sender_ik_pk),
        epoch: event.message.envelope.conv_epoch, createdAt: event.message.envelope.created_ts * 1000,
        bodyType: event.message.inner.body_type, text: event.text,
        gatewayVerified: Boolean(event.gatewayEvent),
      }); } catch { rejectedBody = true; }
    }
  }
  if (inbound && previous.outbox.length >= MAX_PENDING_DISPATCHES) throw new Error('qntm pending dispatch queue is full');
  store.commit(binding, {
    ...previous, cursor: sequence, conversation: event.conversation, session: event.state,
    outbox: inbound ? [...previous.outbox, inbound] : previous.outbox,
  });
  if (event.state.gateway?.accepted) {
    // Cleanup failure must not undo committed receive state. A later event retries.
    try { clearGatewayBootstrap(store, binding); } catch { /* private sealed file remains */ }
  }
  return rejectedBody ? 'invalid' : event.duplicate ? 'duplicate' : 'accepted';
}
