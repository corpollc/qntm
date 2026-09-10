/** Native-host fixture: run real receive and durable admission while host is stopped. */
import { QntmGroupStore } from '../../src/group-store.js';
import { QntmIngressQueue } from '../../src/ingress-queue.js';
import { resolveQntmAccount } from '../../src/accounts.js';
import { inboundId } from '../../src/checkpoint.js';

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
