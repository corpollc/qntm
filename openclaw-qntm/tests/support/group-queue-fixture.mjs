/** Native-host fixture: run real receive and durable admission while host is stopped. */
import { QntmGroupStore } from '../../src/group-store.js';
import { QntmIngressQueue } from '../../src/ingress-queue.js';
import { resolveQntmAccount } from '../../src/accounts.js';
import { inboundId } from '../../src/checkpoint.js';
import { randomBytes } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, deserializeEnvelope, serializeEnvelope, prepareGroupSessionAddition, prepareGroupWelcomeRefresh, prepareGroupSessionRekey, receiveGroupEvent, createGroupSession, restoreGroupSession } from '@corpollc/qntm';

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

/** Pause an already admitted real model turn, then leave a durable completed ADD
 * whose welcome was never acknowledged. No monitor or transport is mocked. */
export async function stageCompletedGroupAddition(config, stateDir, contact, ttl = 1, partial = false) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    const before = ordinary.load(), operation = ordinary.prepare('add', { contact });
    const prepared = prepareGroupSessionAddition(account.identity, before.session, [base64UrlDecode(operation.publicKey)], ttl,
      undefined, before.cursor);
    operation.controls = [prepared.addition, prepared.rekey].map(value => base64UrlEncode(serializeEnvelope(value)));
    operation.welcomes = prepared.welcomes.map(value => base64UrlEncode(serializeEnvelope(value)));
    operation.expected = createGroupSession(account.identity, prepared.conversation, prepared.state);
    ordinary.saveOperation(operation);
    for (const wire of operation.controls.slice(0, partial ? 1 : 2)) await ordinary.client.postMessage(ordinary.binding.conversation.id, base64UrlDecode(wire));
    await ordinary.sync();
    if (ordinary.load().session.needsRekey !== partial || ordinary.load().session.epoch !== (partial ? before.session.epoch : prepared.conversation.currentEpoch)) throw new Error('Staged native admission did not complete');
    return { expiry: prepared.welcomes[0].expiry_ts, original: operation, currentRoot: ordinary.load().session.root };
  });
}

/** Leave a durable rotation that the real relay accepted and production
 * receive authenticated, but whose POST acknowledgement was lost. The bounded
 * replay cache is then filled to its legal limit with that rotation's marker
 * oldest, so the next real authenticated messages evict it through the shared
 * reducer's own eviction rather than by deleting replay state. */
export async function stageAcceptedGroupRotation(config, stateDir) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    if (ordinary.load().operation) throw new Error('Fixture found an unexpected pending operation');
    const operation = ordinary.prepare('rekey', {});
    ordinary.saveOperation(operation);
    await ordinary.client.postMessage(ordinary.binding.conversation.id, base64UrlDecode(operation.controls[0]));
    await ordinary.sync();
    const state = ordinary.load(), expected = restoreGroupSession(account.identity, operation.expected);
    const messageId = Buffer.from(deserializeEnvelope(base64UrlDecode(operation.controls[0])).msg_id).toString('hex');
    const receipt = state.controlReceipts.find(entry => entry.messageId === messageId);
    if (!receipt?.valid || state.session.epoch !== expected.epoch || state.session.root !== expected.root) throw new Error('Staged rotation was not authenticated in replay');
    const seen = { [messageId]: state.session.seen[messageId] };
    for (const [id, marker] of Object.entries(state.session.seen)) if (id !== messageId) seen[id] = marker;
    while (Object.keys(seen).length < 8192) seen[randomBytes(16).toString('hex')] = { digest: randomBytes(32).toString('hex'), epoch: 0 };
    state.session.seen = seen;
    ordinary.save(state);
    return { messageId, control: operation.controls[0], sequence: receipt.sequence, epoch: state.session.epoch, expectedRoot: expected.root };
  });
}

/** Leave the durable state of a host that removed a pinned contact, had the
 * removal accepted through production receive, and died before publishing its
 * short-lived completing rotation. Host stopped; only the crash window and
 * the rotation lifetime are chosen here. */
export async function stagePendingGroupRemoval(config, stateDir, contact, ttl = 8) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    if (ordinary.load().operation) throw new Error('Fixture found an unexpected pending operation');
    const state = ordinary.load(), operation = ordinary.prepare('remove', { contact });
    const removal = deserializeEnvelope(base64UrlDecode(operation.controls[0]));
    const removed = receiveGroupEvent(account.identity, removal, state.session).state;
    const rotation = prepareGroupSessionRekey(account.identity, removed, ttl).rekey;
    operation.controls[1] = base64UrlEncode(serializeEnvelope(rotation));
    operation.expected = receiveGroupEvent(account.identity, rotation, removed).state;
    if (operation.target?.keyId !== Buffer.from(removal.msg_id).toString('hex') && !operation.target) throw new Error('Fixture removal lacks its target pin');
    ordinary.saveOperation(operation);
    await ordinary.client.postMessage(ordinary.binding.conversation.id, base64UrlDecode(operation.controls[0]));
    await ordinary.sync();
    const accepted = ordinary.load();
    if (!accepted.session.needsRekey || !ordinary.controlAccepted(accepted, operation.controls[0]) || ordinary.controlAccepted(accepted, operation.controls[1])) throw new Error('Staged removal was not accepted in replay');
    return { cursor: accepted.cursor, epoch: accepted.session.epoch, removalId: Buffer.from(removal.msg_id).toString('hex'),
      rekeyId: Buffer.from(rotation.msg_id).toString('hex'), expiry: rotation.expiry_ts, controls: operation.controls, target: operation.target };
  });
}

/** With the host stopped, leave the state of a host that saved its reviewed
 * repair rotation and died after the relay accepted the POST but before the
 * journal was finalized. The plan comes from production prepareRetry. */
export async function stageUncertainRemovalRepair(config, stateDir) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    const repair = ordinary.prepareRetry();
    if (repair.phase !== 'removal_rekey' || repair.controls.length !== 1) throw new Error('Fixture expected a removal repair plan');
    ordinary.saveRetry(repair);
    await ordinary.client.postMessage(ordinary.binding.conversation.id, base64UrlDecode(repair.controls[0]));
    return { rotation: repair.controls[0], rotationId: Buffer.from(deserializeEnvelope(base64UrlDecode(repair.controls[0])).msg_id).toString('hex') };
  });
}

/** Leave the durable state of a host that saved an exact rotation and died
 * before its first POST, with the host stopped. Production prepare and journal
 * code only; nothing is posted, so the later reviewed retry must publish once. */
export async function stagePendingGroupRotation(config, stateDir) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    if (ordinary.load().operation) throw new Error('Fixture found an unexpected pending operation');
    const operation = ordinary.prepare('rekey', {});
    ordinary.saveOperation(operation);
    const outer = deserializeEnvelope(base64UrlDecode(operation.controls[0]));
    return { messageId: Buffer.from(outer.msg_id).toString('hex'), control: operation.controls[0], epoch: outer.conv_epoch,
      expectedRoot: restoreGroupSession(account.identity, operation.expected).root, cursor: ordinary.load().cursor };
  });
}

/** Stage an old generic delivery during an already admitted native model turn. */
export async function stageGenericGroupRefresh(config, stateDir, contact, ttl = 1, challenge) {
  const account = resolveQntmAccount({ cfg: config });
  const ordinary = new QntmGroupStore(account, account.bindings[0], { stateDir });
  return ordinary.exclusive(async () => {
    await ordinary.sync();
    const state = ordinary.load(), operation = ordinary.prepare('refresh', { contact, challenge });
    if (operation.welcomePurpose !== 'refresh') throw new Error('Generic fixture requires founding or unknown admission');
    const prepared = prepareGroupWelcomeRefresh(account.identity, state.session, [base64UrlDecode(operation.publicKey)], ttl,
      challenge ? new Uint8Array(Buffer.from(challenge, 'hex')) : undefined, state.cursor);
    operation.welcomes = prepared.welcomes.map(value => base64UrlEncode(serializeEnvelope(value)));
    operation.expected = createGroupSession(account.identity, prepared.conversation, prepared.state,
      { signedEpoch: state.session.signedEpoch, admissions: state.session.admissions });
    // Older native drafts kept the challenge only in their signed box.
    delete operation.welcomePurpose; delete operation.recoveryChallenge;
    ordinary.saveOperation(operation);
    return { expiry: prepared.welcomes[0].expiry_ts, original: operation, cursor: state.cursor, currentRoot: state.session.root };
  });
}
