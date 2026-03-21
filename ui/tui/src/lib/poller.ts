/**
 * Message receive helpers for the TUI.
 */

import {
  DropboxClient,
  buildSignedReceipt,
  decryptMessage,
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
): Promise<StoredMessage | null> {
  const convCrypto = store.getConversationCrypto(convId);
  if (!convCrypto) return null;

  let envelope;
  try {
    envelope = deserializeEnvelope(envelopeBytes);
  } catch {
    return null;
  }

  let decrypted;
  try {
    decrypted = decryptMessage(envelope, convCrypto);
  } catch {
    return null;
  }

  const senderKidHex = bytesToHex(new Uint8Array(decrypted.inner.sender_kid)).toLowerCase();
  const bodyText = new TextDecoder().decode(new Uint8Array(decrypted.inner.body));
  const bodyType = decrypted.inner.body_type || 'text';
  const createdAt = new Date(envelope.created_ts * 1000).toISOString();

  const isSelf = senderKidHex === bytesToHex(identity.keyID).toLowerCase();
  if (isSelf) {
    const history = store.loadHistory(convId);
    const hasRecent = history.some(
      (message) =>
        message.direction === 'outgoing' &&
        message.bodyType === bodyType &&
        message.text === bodyText &&
        Math.abs(Date.parse(message.createdAt) - Date.parse(createdAt)) < 60000,
    );
    if (hasRecent) {
      return null;
    }
  }

  const message: StoredMessage = {
    id: bytesToHex(envelope.msg_id),
    conversationId: convId,
    direction: isSelf ? 'outgoing' : 'incoming',
    sender: isSelf ? 'You' : senderKidHex,
    senderKey: senderKidHex,
    bodyType,
    text: bodyText,
    createdAt,
  };

  store.appendHistory(convId, message);
  submitReceiptBestEffort(
    dropbox,
    identity,
    convCrypto.id,
    envelope.msg_id,
    Math.max(MIN_RECEIPT_ACKS, convCrypto.participants.length),
  );
  return message;
}

export async function pollConversation(
  store: Store,
  dropbox: DropboxClient,
  identity: Identity,
  convId: string,
): Promise<PollResult> {
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
  const convCrypto = store.getConversationCrypto(convId);
  if (!convCrypto) return null;

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
    senderKey: '',
    bodyType,
    text,
    createdAt: new Date(envelope.created_ts * 1000).toISOString(),
  };

  store.appendHistory(convId, message);
  return message;
}
