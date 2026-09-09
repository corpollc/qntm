import {
  createMessage,
  defaultTTL,
  generateIdentity,
  keyIDFromPublicKey,
  createGroupRekeyBody, createGroupRemoveBody, deserializeEnvelope, decryptMessage, QSP1Suite,
  serializeEnvelope,
} from "@corpollc/qntm";
import { afterEach, describe, expect, test, vi } from "vitest";
import { resolveQntmAccount } from "../src/accounts.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QntmCheckpointStore, inboundId, type QntmInbound } from "../src/checkpoint.js";
import { writePrivateJSON } from "../src/storage.js";
import type { QntmIngress, QntmMonitorDeps, QntmMonitor } from "../src/monitor.js";
import { monitorQntmAccount } from "../src/monitor.js";
import { toHex } from "../src/qntm.js";
import type { QntmRootConfig } from "../src/types.js";
import {
  createConfig,
  createConversationFixture,
  createIdentityDirFixture,
  createIdentityFixture,
} from "./helpers.js";

function resolveMockRoute(params: {
  cfg: QntmRootConfig;
  accountId?: string | null;
  peer?: { kind?: string; id?: string };
}) {
  const agentId = "main";
  const accountId = params.accountId ?? "default";
  const mainSessionKey = "agent:main:main";
  const peerKind = params.peer?.kind ?? "direct";
  const peerId = params.peer?.id ?? "peer";
  let sessionKey = mainSessionKey;

  if (peerKind !== "direct") {
    sessionKey = `agent:${agentId}:qntm:${peerKind}:${peerId}`;
  } else {
    switch (params.cfg.session?.dmScope ?? "main") {
      case "main":
        sessionKey = mainSessionKey;
        break;
      case "per-peer":
        sessionKey = `agent:${agentId}:direct:${peerId}`;
        break;
      case "per-channel-peer":
        sessionKey = `agent:${agentId}:qntm:direct:${peerId}`;
        break;
      case "per-account-channel-peer":
        sessionKey = `agent:${agentId}:qntm:${accountId}:direct:${peerId}`;
        break;
    }
  }

  return {
    agentId,
    channel: "qntm",
    accountId,
    sessionKey,
    mainSessionKey,
    lastRoutePolicy: sessionKey === mainSessionKey ? "main" : "session",
    matchedBy: "default",
  };
}

function createChannelRuntimeMock() {
  const recordInboundSession = vi.fn(
    async (_params: {
      sessionKey: string;
      ctx?: Record<string, unknown>;
      updateLastRoute?: Record<string, unknown>;
    }) => undefined,
  );
  const dispatchReplyWithBufferedBlockDispatcher = vi.fn(async ({ dispatcherOptions, replyOptions }) => {
    await replyOptions.turnAdoptionLifecycle.onAdopted();
    await dispatcherOptions.deliver({ text: "auto reply" });
    return {};
  });
  return {
    runtime: {
      routing: {
        resolveAgentRoute: vi.fn((params) => resolveMockRoute(params as Parameters<typeof resolveMockRoute>[0])),
      },
      session: {
        resolveStorePath: vi.fn(() => "/tmp/openclaw-qntm-session-store.json"),
        readSessionUpdatedAt: vi.fn(() => undefined),
        recordInboundSession,
      },
      reply: {
        resolveEnvelopeFormatOptions: vi.fn(() => ({})),
        formatAgentEnvelope: vi.fn(({ body }) => body),
        finalizeInboundContext: vi.fn((ctx) => ctx),
        dispatchReplyWithBufferedBlockDispatcher,
      },
    },
    recordInboundSession,
    dispatchReplyWithBufferedBlockDispatcher,
  };
}

function createClientMock() {
  const subscriptions = new Map<
    string,
    {
      close: ReturnType<typeof vi.fn>;
      handlers: {
        getCursor?: () => Promise<number> | number;
        onMessage: (message: { seq: number; envelope: Uint8Array }) => Promise<void> | void;
      };
    }
  >();
  const sent: Array<{ conversationId: string; envelope: Uint8Array }> = [];

  const client = {
    subscribeMessages: vi.fn((conversationId, _fromSequence, handlers) => {
      const key = toHex(conversationId);
      const close = vi.fn();
      subscriptions.set(key, { close, handlers });
      return {
        close,
        closed: Promise.resolve(),
      };
    }),
    postMessage: vi.fn(async (conversationId, envelope) => {
      sent.push({
        conversationId: toHex(conversationId),
        envelope,
      });
      return sent.length;
    }),
  };

  return {
    client,
    subscriptions,
    sent,
    async emit(conversationId: string, seq: number, envelope: Uint8Array) {
      const entry = subscriptions.get(conversationId);
      if (!entry) {
        throw new Error(`missing subscription for ${conversationId}`);
      }
      await entry.handlers.onMessage({ seq, envelope });
    },
  };
}

type Deliver = Parameters<NonNullable<QntmMonitorDeps['createIngress']>>[0];
function createIngressMock() {
  const pending = new Map<string, QntmInbound>();
  const completed = new Set<string>();
  const errors: unknown[] = [];
  let deliver: Deliver;
  const queue = {
    pending, completed, errors, unavailable: false,
    create: ((handler) => {
      deliver = handler;
      return {
        async admit(message) {
          if (queue.unavailable) throw new Error('queue disk unavailable');
          if (!completed.has(inboundId(message))) pending.set(inboundId(message), message);
        },
        start() {}, async stop() {},
      } satisfies QntmIngress;
    }) satisfies NonNullable<QntmMonitorDeps['createIngress']>,
    async drain() {
      for (const [id, message] of [...pending]) {
        const finish = async () => { pending.delete(id); completed.add(id); };
        try {
          const result = await deliver(message, {
            admission: 'exclusive', abortSignal: new AbortController().signal,
            onAdopted: finish, onDeferred() {}, onAdoptionFinalizing() {}, async onAbandoned() {},
          });
          if (result.kind === 'completed') await finish();
        } catch (error) { errors.push(error); }
      }
    },
  };
  return queue;
}
const directories: string[] = [];
const monitors: QntmMonitor[] = [];
afterEach(async () => {
  for (const monitor of monitors.splice(0)) await monitor.stop();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
  vi.restoreAllMocks();
});
async function fixture(options: { write?: typeof writePrivateJSON; dmScope?: 'per-account-channel-peer' } = {}) {
  const identity = createIdentityFixture(), direct = createConversationFixture('direct'), group = createConversationFixture('group');
  const cfg = createConfig({ identity: identity.serialized, sessionDmScope: options.dmScope,
    conversations: { direct: { invite: direct.token }, group: { invite: group.token } } });
  const account = resolveQntmAccount({ cfg });
  const stateDir = mkdtempSync(join(tmpdir(), 'qntm-monitor-')); directories.push(stateDir);
  const store = new QntmCheckpointStore(account, { stateDir, write: options.write });
  const runtime = createChannelRuntimeMock();
  const client = createClientMock(), queue = createIngressMock();
  const log = { error: vi.fn() };
  const start = async () => {
    const monitor = await monitorQntmAccount({ account, cfg, channelRuntime: runtime.runtime as never,
      abortSignal: new AbortController().signal, log,
      deps: { checkpointStore: store, createClient: () => client.client, createIngress: queue.create } });
    monitors.push(monitor); return monitor;
  };
  const monitor = await start();
  return { identity: identity.identity, direct, group, cfg, account, stateDir, store, runtime, client, queue, log, start, monitor,
    binding: (id: string) => account.bindings.find(binding => binding.conversationId === id)!,
    async text(conversationId: string, sequence: number, text: string, sender = direct.inviter) {
      const binding = account.bindings.find(binding => binding.conversationId === conversationId)!;
      const envelope = serializeEnvelope(createMessage(sender, store.load(binding).conversation, 'text', new TextEncoder().encode(text)));
      await client.emit(conversationId, sequence, envelope); return envelope;
    },
  };
}

describe('monitorQntmAccount durable dispatch', () => {
  test('routes two conversations and preserves command distrust and direct-session isolation', async () => {
    const f = await fixture({ dmScope: 'per-account-channel-peer' });
    await f.text(f.direct.conversationId, 1, 'hello direct');
    await f.text(f.group.conversationId, 1, 'hello group', f.group.inviter);
    expect(f.queue.pending.size).toBe(2);
    expect(f.store.load(f.binding(f.direct.conversationId)).outbox).toHaveLength(0);
    await f.queue.drain();
    expect(f.client.sent.map(message => message.conversationId)).toEqual([f.direct.conversationId, f.group.conversationId]);
    const ctx = f.runtime.recordInboundSession.mock.calls[0][0].ctx;
    expect(ctx?.CommandAuthorized).toBe(false);
    expect(ctx?.NativeChannelId).toBe(f.direct.conversationId);
    expect(ctx?.SessionKey).toBe(`agent:main:qntm:default:direct:${f.direct.conversationId}`);
    expect(ctx?.SenderId).toBe(toHex(f.direct.inviter.keyID));
  });
  test('self-authored messages update the checkpoint without waking the agent', async () => {
    const f = await fixture();
    await f.text(f.direct.conversationId, 5, 'self echo', f.identity);
    expect(f.store.load(f.binding(f.direct.conversationId)).cursor).toBe(5);
    expect(f.queue.pending.size).toBe(0);
  });
  test('retains dispatch after an admission failure and retries it on restart', async () => {
    const f = await fixture(); f.queue.unavailable = true;
    await f.text(f.direct.conversationId, 1, 'do not lose this wakeup');
    const binding = f.binding(f.direct.conversationId);
    expect(f.store.load(binding).cursor).toBe(1);
    expect(f.store.load(binding).outbox).toHaveLength(1);
    expect(f.log.error).toHaveBeenCalledWith('qntm pending host delivery failed; retained for retry');
    await f.monitor.stop(); f.queue.unavailable = false; await f.start(); await f.queue.drain();
    expect(f.runtime.dispatchReplyWithBufferedBlockDispatcher).toHaveBeenCalledTimes(1);
    expect(f.store.load(binding).outbox).toHaveLength(0);
    expect(f.store.load(binding).cursor).toBe(1);
  });
  test('host dispatch failure keeps the admitted record retryable', async () => {
    const f = await fixture();
    f.runtime.recordInboundSession.mockRejectedValueOnce(new Error('host session store unavailable'));
    await f.text(f.direct.conversationId, 1, 'retry host dispatch');
    await f.queue.drain();
    expect(f.queue.pending.size).toBe(1);
    expect(f.client.sent).toHaveLength(0);
    await f.queue.drain();
    expect(f.client.sent).toHaveLength(1);
    expect(f.queue.pending.size).toBe(0);
  });
  test('duplicate admission after a failed outbox cleanup does not dispatch twice', async () => {
    let writes = 0;
    const f = await fixture({ write: (...args) => { if (++writes === 2) throw new Error('disk full after host enqueue'); writePrivateJSON(...args); } });
    await f.text(f.direct.conversationId, 1, 'exactly one local admission');
    const binding = f.binding(f.direct.conversationId);
    expect(f.store.load(binding).outbox).toHaveLength(1);
    await f.queue.drain(); await f.monitor.stop(); await f.start(); await f.queue.drain();
    expect(f.runtime.dispatchReplyWithBufferedBlockDispatcher).toHaveBeenCalledTimes(1);
    expect(f.store.load(binding).outbox).toHaveLength(0);
  });
  test('failed checkpoint persistence keeps relay progress unchanged', async () => {
    let failed = true;
    const f = await fixture({ write: (...args) => { if (failed) throw new Error('disk full'); writePrivateJSON(...args); } });
    await expect(f.text(f.direct.conversationId, 1, 'retry me')).rejects.toThrow('disk full');
    expect(f.store.load(f.binding(f.direct.conversationId)).cursor).toBe(0);
    expect(f.queue.pending.size).toBe(0);
    failed = false; await f.text(f.direct.conversationId, 1, 'retry me'); await f.queue.drain();
    expect(f.client.sent).toHaveLength(1);
  });
  test('a delayed reply uses the latest rekey and refuses delivery after removal', async () => {
    const f = await fixture();
    const binding = f.binding(f.group.conversationId);
    binding.trigger = 'mention'; binding.triggerNames = ['wake'];
    let release!: () => void;
    f.runtime.dispatchReplyWithBufferedBlockDispatcher.mockImplementation(async ({ dispatcherOptions, replyOptions }) => {
      await replyOptions.turnAdoptionLifecycle.onAdopted();
      await new Promise<void>(resolve => { release = resolve; });
      await dispatcherOptions.deliver({ text: 'late reply' }); return {};
    });
    await f.text(f.group.conversationId, 1, 'wake before rotation', f.group.inviter);
    let draining = f.queue.drain(); await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    const root = new Uint8Array(32).fill(7);
    const rekey = createGroupRekeyBody(root, 1, [f.identity, f.group.inviter].map(identity => ({ kid: identity.keyID, publicKey: identity.publicKey })), f.group.conversation.id);
    await f.client.emit(f.group.conversationId, 2, serializeEnvelope(createMessage(f.group.inviter, f.group.conversation, 'group_rekey', rekey)));
    release(); await draining;
    const reply = deserializeEnvelope(f.client.sent[0].envelope);
    expect(reply.conv_epoch).toBe(1);
    expect(new TextDecoder().decode(decryptMessage(reply, f.store.load(binding).conversation).inner.body)).toBe('late reply');
    release = undefined as never;
    await f.text(f.group.conversationId, 3, 'wake before removal', f.group.inviter);
    draining = f.queue.drain(); await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    const remove = createMessage(f.group.inviter, f.store.load(binding).conversation, 'group_remove', createGroupRemoveBody([f.identity.keyID]));
    await f.client.emit(f.group.conversationId, 4, serializeEnvelope(remove));
    release(); await draining;
    expect(f.client.sent).toHaveLength(1);
    expect(f.store.load(binding).session.removed).toBe(true);
  });
  test('refuses a malformed signing identity before opening subscriptions', async () => {
    const identity = generateIdentity(), conversation = createConversationFixture('direct');
    const files = createIdentityDirFixture({ identity, storedKeyId: keyIDFromPublicKey(generateIdentity().publicKey), conversations: [conversation] });
    try {
      const cfg = createConfig({ identityDir: files.dir, conversations: { chat: { convId: conversation.conversationId } } });
      const account = resolveQntmAccount({ cfg });
      expect(account.configured).toBe(false);
      await expect(monitorQntmAccount({ account, cfg, channelRuntime: {} as never, abortSignal: new AbortController().signal })).rejects.toThrow('not configured');
    } finally { files.cleanup(); }
  });
});
