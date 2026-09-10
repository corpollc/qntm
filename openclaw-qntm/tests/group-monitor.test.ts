import { afterEach, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DropboxClient, generateIdentity, createInvite, createConversation, deriveConversationKeys, GroupState,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupSession, base64UrlEncode, base64UrlDecode, createGroupLink,
  requireGroupRecovery, prepareGroupWelcomeRefresh, serializeEnvelope, createMessage,
} from '@corpollc/qntm';
import { QntmGroupStore } from '../src/group-store.js';
import { monitorQntmAccount, type QntmMonitor } from '../src/monitor.js';
import { toHex } from '../src/qntm.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding } from '../src/types.js';

let directory: string, monitor: QntmMonitor | undefined;
afterEach(async () => { await monitor?.stop(); monitor = undefined; vi.restoreAllMocks(); vi.unstubAllEnvs(); if (directory) rmSync(directory, { recursive: true, force: true }); });
function fixture(cursor = 0) {
  directory = mkdtempSync(join(tmpdir(), 'qntm-group-monitor-'));
  vi.stubEnv('OPENCLAW_STATE_DIR', directory);
  const owner = generateIdentity(), member = generateIdentity(), invite = createInvite(owner, 'group');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const roster = new GroupState(); roster.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Replay', '', owner, [member.publicKey])));
  conversation.participants = roster.listMembers();
  const ownerState = createGroupSession(owner, conversation, roster), memberState = createGroupSession(member, conversation, roster);
  const relayUrl = 'https://relay.test';
  const binding: ResolvedQntmBinding = { key: 'team', target: 'team', label: 'Team', enabled: true, conversationId: toHex(conversation.id),
    conversation, chatType: 'group', trigger: 'all', triggerNames: [], ordinaryGroup: true, groupActions: ['open', 'send'],
    groupLink: createGroupLink({ conversationId: conversation.id, inviterPublicKey: owner.publicKey, relayUrl }),
    groupSeed: { session: memberState, cursor } };
  const account: ResolvedQntmAccount = { accountId: 'default', enabled: true, configured: true, relayUrl, identity: member, identitySource: 'config',
    bindings: [binding], configErrors: [], config: { contacts: { Owner: base64UrlEncode(owner.publicKey) } } };
  const store = new QntmGroupStore(account, binding);
  const entries: Array<{ seq: number; envelope: Uint8Array }> = [];
  const head = () => entries.at(-1)?.seq ?? cursor;
  vi.spyOn(DropboxClient.prototype, 'receiveMessages').mockImplementation(async (_id, after = 0) => {
    const rows = entries.filter(row => row.seq > after);
    return { entries: rows, messages: rows.map(row => row.envelope), sequence: head() };
  });
  const post = vi.spyOn(DropboxClient.prototype, 'postMessage').mockRejectedValue(new Error('monitor must not automatically POST'));
  let handlers!: Parameters<DropboxClient['subscribeMessages']>[2];
  const admit = vi.fn();
  const start = async () => {
    monitor = await monitorQntmAccount({ account, cfg: {} as never, channelRuntime: {} as never, abortSignal: new AbortController().signal,
      deps: { createClient: () => ({ postMessage: post, subscribeMessages: (_id, _cursor, options) => { handlers = options; return { close() {}, closed: Promise.resolve() }; } }),
        createIngress: () => ({ start() {}, async stop() {}, admit }) } });
    return handlers;
  };
  return { owner, member, conversation, ownerState, memberState, store, entries, head, start, post, admit };
}

it('opens a challenged welcome received in reconnect backlog before unpausing dispatch', async () => {
  const f = fixture(1), initial = f.store.load();
  initial.session = requireGroupRecovery(f.memberState, 1, 'missing_history'); f.store.save(initial);
  const handlers = await f.start();
  expect(f.store.load().session!.recovery).not.toBeNull();
  const refreshed = prepareGroupWelcomeRefresh(f.owner, f.ownerState, [f.member.publicKey], undefined,
    new Uint8Array(Buffer.from(initial.session.recovery!.challenge, 'hex')), 1);
  const envelope = serializeEnvelope(refreshed.welcomes[0]);
  f.entries.push({ seq: 2, envelope });
  handlers.onOpen?.();
  await handlers.onMessage?.({ seq: 2, envelope });
  expect(f.store.load().session!.recovery).not.toBeNull();
  await handlers.onReady?.(2);
  expect(f.store.load().session!.recovery).toBeNull();
  expect(f.store.load().cursor).toBe(2);
  expect(f.admit).not.toHaveBeenCalled();
  expect(f.post).not.toHaveBeenCalled();
});

it.each([true, false])('releases a restarted send barrier only with exact replay acceptance: %s', async accepted => {
  const f = fixture(), operation = f.store.prepare('send', { text: 'reply committed before process death' });
  f.store.saveOperation(operation);
  if (accepted) f.entries.push({ seq: 1, envelope: base64UrlDecode(operation.controls[0]) });
  const incoming = serializeEnvelope(createMessage(f.owner, f.conversation, 'text', new TextEncoder().encode('next agent request')));
  f.entries.push({ seq: f.head() + 1, envelope: incoming });
  const handlers = await f.start();
  await handlers.onReady?.(f.head());
  expect(f.store.load().operation).toEqual(accepted ? null : operation);
  expect(f.admit).toHaveBeenCalledTimes(accepted ? 1 : 0);
  expect(f.post).not.toHaveBeenCalled();
});
