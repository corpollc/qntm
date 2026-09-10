/**
 * Message receive helpers for the TUI.
 */

import {
  DropboxClient,
  buildSignedReceipt,
  receiveConversationEvent,
  deserializeEnvelope,
  serializeEnvelope,
  createMessage,
  defaultTTL,
  type Identity,
} from '@corpollc/qntm';
import { Store, bytesToHex, type StoredMessage } from './store.js';

export interface PollResult {
  messages: StoredMessage[];
  newCursor: number;
}

// Creators only know themselves until another participant is learned locally.
const MIN_RECEIPT_ACKS = 2;

function submitReceiptBestEffort(
  dropbox: DropboxClient,
  identity: Identity,
  convId: Uint8Array,
  msgId: Uint8Array,
  requiredAcks: number,
): void {
  try {
    const receipt = buildSignedReceipt(identity, convId, msgId, requiredAcks);
    dropbox.submitReceipt(receipt).catch(() => {});
  } catch {
    // Receipt emission is best-effort
  }
}

export async function applyIncomingEnvelope(
  store: Store,
  dropbox: DropboxClient,
  identity: Identity,
  convId: string,
  envelopeBytes: Uint8Array,
  seq?: number,
): Promise<StoredMessage | null> {
  if (store.findConversation(convId)?.managedGroup) throw new Error('Contact groups must use their durable receive subscription.');
  const convCrypto = store.getConversationCrypto(convId);
  if (!convCrypto) return null;
  if (seq !== undefined && (!Number.isSafeInteger(seq) || seq < 1)) throw new Error('Invalid receive sequence');
  if (seq !== undefined && seq <= store.loadCursor(convId)) return null;

  let envelope;
  try {
    envelope = deserializeEnvelope(envelopeBytes);
  } catch {
    if (seq !== undefined) store.saveCursor(convId, seq);
    return null;
  }

  const session = store.gatewaySession(convId, identity);
  let event;
  try {
    event = receiveConversationEvent(envelope, convCrypto, identity, session);
  } catch {
    // Invalid protocol input is ignored. Persistence failures below must escape
    // so the subscription retries without moving past an uncommitted rekey.
    if (seq !== undefined) store.saveCursor(convId, seq);
    return null;
  }
  if (event.duplicate) {
    if (seq !== undefined) store.saveCursor(convId, seq);
    return null;
  }
  const decrypted = event.message;
  const senderKidHex = bytesToHex(decrypted.inner.sender_kid).toLowerCase();
  const bodyText = event.text;
  const bodyType = decrypted.inner.body_type;
  const createdAt = new Date(envelope.created_ts * 1000).toISOString();
  const isSelf = senderKidHex === bytesToHex(identity.keyID).toLowerCase();
  const alreadyDisplayed = store.loadHistory(convId).some(message => message.id === bytesToHex(envelope.msg_id));

  const message: StoredMessage = {
    id: bytesToHex(envelope.msg_id),
    conversationId: convId,
    direction: isSelf ? 'outgoing' : 'incoming',
    sender: isSelf ? 'You' : senderKidHex,
    senderKey: senderKidHex,
    bodyType,
    text: bodyText,
    createdAt,
    gatewayVerified: !!event.gatewayEvent,
  };

  store.commitReceived(convId, event, message, seq);
  submitReceiptBestEffort(
    dropbox,
    identity,
    convCrypto.id,
    envelope.msg_id,
    Math.max(MIN_RECEIPT_ACKS, convCrypto.participants.length),
  );
  return alreadyDisplayed ? null : message;
}

export async function pollConversation(
  store: Store,
  dropbox: DropboxClient,
  identity: Identity,
  convId: string,
): Promise<PollResult> {
  if (store.findConversation(convId)?.managedGroup) {
    const received = await store.groups.run(['recv', convId]);
    // Local history retains superseded plaintext for inspection. Only the
    // receiver's filtered result is eligible to be reported as new delivery.
    const accepted = new Set((received.messages || []).map((message: { message_id: string }) => message.message_id));
    return { messages: store.loadHistory(convId).filter(message => accepted.has(message.id)), newCursor: store.loadCursor(convId) };
  }
  const convCrypto = store.getConversationCrypto(convId);
  if (!convCrypto) return { messages: [], newCursor: 0 };

  const fromSeq = store.loadCursor(convId);
  const result = await dropbox.receiveMessages(convCrypto.id, fromSeq, 200);
  const accepted: StoredMessage[] = [];

  for (const envelopeBytes of result.messages) {
    const message = await applyIncomingEnvelope(store, dropbox, identity, convId, envelopeBytes);
    if (message) {
      accepted.push(message);
    }
  }

  if (result.sequence > fromSeq) {
    store.saveCursor(convId, result.sequence);
  }

  return { messages: accepted, newCursor: result.sequence };
}

export async function sendMessage(
  store: Store,
  dropbox: DropboxClient,
  identity: Identity,
  convId: string,
  text: string,
  bodyType = 'text',
): Promise<StoredMessage | null> {
  if (store.findConversation(convId)?.managedGroup) {
    if (bodyType !== 'text') throw new Error('Use the group commands for membership actions.');
    if (!store.findConversation(convId)?.groupSession) throw new Error('Group setup is incomplete; use /group retry.');
    const result = await store.groups.run(['send', '--', convId, text]);
    return store.loadHistory(convId).find(message => message.id === result.message_id) || store.loadHistory(convId).at(-1) || null;
  }
  const convCrypto = store.getConversationCrypto(convId);
  if (!convCrypto) return null;

  if (store.gatewaySession(convId, identity).removed) throw new Error('You have been removed from this conversation');
  const bodyBytes = new TextEncoder().encode(text);
  const envelope = createMessage(identity, convCrypto, bodyType, bodyBytes, undefined, defaultTTL());
  const serialized = serializeEnvelope(envelope);

  await dropbox.postMessage(convCrypto.id, serialized);
  submitReceiptBestEffort(
    dropbox,
    identity,
    convCrypto.id,
    envelope.msg_id,
    Math.max(MIN_RECEIPT_ACKS, convCrypto.participants.length),
  );

  const message: StoredMessage = {
    id: bytesToHex(envelope.msg_id),
    conversationId: convId,
    direction: 'outgoing',
    sender: 'You',
    senderKey: bytesToHex(identity.keyID),
    bodyType,
    text,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  };

  store.appendHistory(convId, message);
  return message;
}
