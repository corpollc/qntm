/**
 * Message polling — uses DropboxClient to fetch new messages and decrypt them.
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
  type Conversation,
} from '@corpollc/qntm';
import { Store, bytesToHex, type StoredMessage } from './store.js';

export interface PollResult {
  messages: StoredMessage[];
  newCursor: number;
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

  const selfKidHex = bytesToHex(identity.keyID).toLowerCase();
  const accepted: StoredMessage[] = [];
  const processedMsgIds: Uint8Array[] = [];

  for (const envelopeBytes of result.messages) {
    let envelope;
    try {
      envelope = deserializeEnvelope(envelopeBytes);
    } catch {
      continue;
    }

    let decrypted;
    try {
      decrypted = decryptMessage(envelope, convCrypto);
    } catch {
      continue;
    }

    const senderKidHex = bytesToHex(new Uint8Array(decrypted.inner.sender_kid)).toLowerCase();
    const bodyText = new TextDecoder().decode(new Uint8Array(decrypted.inner.body));
    const bodyType = decrypted.inner.body_type || 'text';
    const createdAt = new Date(envelope.created_ts * 1000).toISOString();
    const msgIdHex = bytesToHex(envelope.msg_id);

    const isSelf = senderKidHex === selfKidHex;

    // Check for self-echo suppression
    if (isSelf) {
      const history = store.loadHistory(convId);
      const hasRecent = history.some(
        (m) =>
          m.direction === 'outgoing' &&
          m.bodyType === bodyType &&
          m.text === bodyText &&
          Math.abs(Date.parse(m.createdAt) - Date.parse(createdAt)) < 60000,
      );
      if (hasRecent) continue;
    }

    processedMsgIds.push(envelope.msg_id);

    const message: StoredMessage = {
      id: msgIdHex,
      conversationId: convId,
      direction: isSelf ? 'outgoing' : 'incoming',
      sender: isSelf ? 'You' : senderKidHex,
      senderKey: senderKidHex,
      bodyType,
      text: bodyText,
      createdAt,
    };

    store.appendHistory(convId, message);
    accepted.push(message);
  }

  if (result.sequence > fromSeq) {
    store.saveCursor(convId, result.sequence);
  }

  // Emit read receipts for all successfully processed messages (fire-and-forget)
  if (processedMsgIds.length > 0) {
    const requiredAcks = convCrypto.participants.length;
    for (const msgId of processedMsgIds) {
      try {
        const receipt = buildSignedReceipt(identity, convCrypto.id, msgId, requiredAcks);
        dropbox.submitReceipt(receipt).catch(() => {});
      } catch {
        // Receipt emission is best-effort
      }
    }
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
