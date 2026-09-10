/** Native-host fixture: run real receive and durable admission while host is stopped. */
import { QntmGroupStore } from '../../src/group-store.js';
import { QntmIngressQueue } from '../../src/ingress-queue.js';
import { resolveQntmAccount } from '../../src/accounts.js';
import { inboundId } from '../../src/checkpoint.js';
import { base64UrlDecode, deserializeEnvelope } from '@corpollc/qntm';

export async function stageGroupDelivery(config, stateDir, messageId) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  await ordinary.exclusive(() => ordinary.sync());
  const pending = ordinary.load().outbox.find(row => row.messageId === messageId);
  if (!pending?.groupDispatch) throw new Error('Fixture message was not cryptographically received');
  const queue = new QntmIngressQueue(account.accountId, { stateDir });
  try {
    if ((await queue.enqueue(inboundId(pending), { version: 1, body: pending })).kind !== 'accepted') throw new Error('Fixture delivery already exists');
  } finally { queue.close(); }
  await ordinary.removeOutbox(inboundId(pending));
  return { messageId, queueId: inboundId(pending), generation: pending.groupDispatch.generation };
}

/** Leave the same durable state as a process killed after its text POST commits
 * but before its delivery journal is finalized. Uses the actual relay. */
export async function stageAcceptedGroupSend(config, stateDir) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    let operation = ordinary.load().operation;
    if (operation) {
      if (operation.action !== 'send' || operation.controls.length !== 1) throw new Error('Fixture found an unexpected membership operation');
    } else {
      operation = ordinary.prepare('send', { text: 'native text accepted before journal completion' });
      ordinary.saveOperation(operation);
      await ordinary.client.postMessage(ordinary.binding.conversation.id, base64UrlDecode(operation.controls[0]));
    }
    return { messageId: Buffer.from(deserializeEnvelope(base64UrlDecode(operation.controls[0])).msg_id).toString('hex') };
  });
}
