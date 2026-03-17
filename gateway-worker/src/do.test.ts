/**
 * Regression tests for gateway-worker DO security invariants.
 *
 * These tests exercise the handler-level validation that guards against:
 *  - Forged gate.executed terminal markers (qntm-iv57)
 *  - Direct gate.config policy takeover (qntm-d9qb)
 *  - Unverified request/approval signatures (qntm-3gde)
 *  - Promotion invariant violations (qntm-qko0)
 *  - Pre-promotion message acceptance (qntm-qko0)
 *  - Write-ahead execution recovery (qntm-qtw2)
 *
 * Strategy: mock DurableObjectState storage and call the private
 * processGateMessage() directly via type cast.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateIdentity, keyIDFromPublicKey, base64UrlEncode,
  signRequest, signApproval, hashRequest, computePayloadHash,
} from '@corpollc/qntm';
import { GatewayConversationDO } from './do.js';
import type { ConversationState, StoredGateMessage } from './types.js';

// ---- Mock Durable Object storage ----

class MockStorage {
  private data = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> {
    return this.data.get(key) as T | undefined;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.data.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.data.delete(key);
  }

  async list<T>(opts: { prefix: string }): Promise<Map<string, T>> {
    const result = new Map<string, T>();
    for (const [k, v] of this.data) {
      if (k.startsWith(opts.prefix)) {
        result.set(k, v as T);
      }
    }
    return result;
  }

  async setAlarm(): Promise<void> {}

  /** Test helper: raw access to backing map */
  _raw(): Map<string, unknown> { return this.data; }
}

class MockState {
  storage: MockStorage;
  constructor() { this.storage = new MockStorage(); }
}

const dummyEnv = {
  GATEWAY_KV: {} as never,
  GATEWAY_CONVO_DO: {} as never,
  GATE_VAULT_KEY: '00'.repeat(32),
  DROPBOX_URL: 'https://localhost:9999',
  POLL_INTERVAL_MS: '60000',
};

// ---- Test identities ----

const gateway = generateIdentity();
const gatewayKid = base64UrlEncode(keyIDFromPublicKey(gateway.publicKey));

const alice = generateIdentity();
const aliceKid = base64UrlEncode(keyIDFromPublicKey(alice.publicKey));

const bob = generateIdentity();
const bobKid = base64UrlEncode(keyIDFromPublicKey(bob.publicKey));

const mallory = generateIdentity();
const malloryKid = base64UrlEncode(keyIDFromPublicKey(mallory.publicKey));

// ---- Helpers ----

function promotedState(overrides?: Partial<ConversationState>): ConversationState {
  return {
    conv_id: 'a'.repeat(32),
    private_key: base64UrlEncode(gateway.privateKey),
    public_key: base64UrlEncode(gateway.publicKey),
    kid: gatewayKid,
    conv_aead_key: base64UrlEncode(new Uint8Array(32)),
    conv_nonce_key: base64UrlEncode(new Uint8Array(32)),
    conv_epoch: 0,
    poll_cursor: 0,
    polling: false,
    promoted_at: new Date().toISOString(),
    gate_promoted: true,
    rules: [{ service: '*', endpoint: '', verb: '', m: 2 }],
    participants: {
      [aliceKid]: base64UrlEncode(alice.publicKey),
      [bobKid]: base64UrlEncode(bob.publicKey),
    },
    promotion_floor: 2,
    ...overrides,
  };
}

function encode(obj: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj));
}

type ProcessFn = (bodyType: string, body: Uint8Array, senderKid: Uint8Array, senderPk: Uint8Array) => Promise<void>;

function makeProcessFn(doInstance: GatewayConversationDO): ProcessFn {
  // Access private method for testing
  return (doInstance as unknown as { processGateMessage: ProcessFn }).processGateMessage.bind(doInstance);
}

function makeDO(): { doInstance: GatewayConversationDO; storage: MockStorage; process: ProcessFn } {
  const mockState = new MockState();
  const doInstance = new GatewayConversationDO(mockState as unknown as DurableObjectState, dummyEnv);
  return { doInstance, storage: mockState.storage, process: makeProcessFn(doInstance) };
}

function buildSignedRequest(signer: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: Record<string, unknown>) {
  const signerKid = base64UrlEncode(keyIDFromPublicKey(signer.publicKey));
  const convId = 'a'.repeat(32);
  const requestId = 'req-' + Math.random().toString(36).slice(2, 8);
  const expiresAt = new Date(Date.now() + 3600000).toISOString();

  const signable = {
    conv_id: convId,
    request_id: requestId,
    verb: 'GET',
    target_endpoint: '/api/test',
    target_service: 'test-svc',
    target_url: 'https://api.example.com/test',
    expires_at_unix: Math.floor(new Date(expiresAt).getTime() / 1000),
    payload_hash: computePayloadHash(null),
    eligible_signer_kids: [aliceKid, bobKid],
    required_approvals: 2,
    ...overrides,
  };
  const sig = signRequest(signer.privateKey, signable);

  const body = {
    type: 'gate.request',
    conv_id: convId,
    request_id: requestId,
    verb: 'GET',
    target_endpoint: '/api/test',
    target_service: 'test-svc',
    target_url: 'https://api.example.com/test',
    expires_at: expiresAt,
    signer_kid: signerKid,
    signature: base64UrlEncode(sig),
    eligible_signer_kids: signable.eligible_signer_kids,
    required_approvals: signable.required_approvals,
    ...overrides,
  };

  return { body, signable, requestId, signerKid };
}

function buildSignedApproval(
  signer: { privateKey: Uint8Array; publicKey: Uint8Array },
  requestSignable: Record<string, unknown>,
  requestId: string,
  convId: string,
) {
  const signerKid = base64UrlEncode(keyIDFromPublicKey(signer.publicKey));
  const reqHash = hashRequest(requestSignable as never);
  const approvalSignable = { conv_id: convId, request_id: requestId, request_hash: reqHash };
  const sig = signApproval(signer.privateKey, approvalSignable);
  return {
    body: {
      type: 'gate.approval',
      conv_id: convId,
      request_id: requestId,
      signer_kid: signerKid,
      signature: base64UrlEncode(sig),
    },
    signerKid,
  };
}

// =====================================================================
// Tests
// =====================================================================

describe('qntm-d9qb: gate.config rejection', () => {
  it('rejects gate.config from any participant', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const configBody = encode({ type: 'gate.config', rules: [{ service: '*', endpoint: '', verb: '', m: 1 }] });
    await expect(
      process('gate.config', configBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('gate.config rejected');
  });

  it('rejects gate.config even from a participant who could lower thresholds', async () => {
    const { storage, process } = makeDO();
    // Conversation has floor=3 and strict rules
    await storage.put('conv_state', promotedState({
      promotion_floor: 3,
      rules: [{ service: 'stripe', endpoint: '/charges', verb: 'POST', m: 3 }],
    }));

    // Attacker tries to replace with m=1 wildcard
    const configBody = encode({ type: 'gate.config', rules: [{ service: '*', endpoint: '', verb: '', m: 1 }] });
    await expect(
      process('gate.config', configBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('gate.config rejected');
  });
});

describe('qntm-iv57: gate.executed authentication', () => {
  it('rejects gate.executed from a non-gateway participant', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const executedBody = encode({ type: 'gate.executed', request_id: 'req-target' });
    await expect(
      process('gate.executed', executedBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('only gateway-authored terminal markers are accepted');
  });

  it('accepts gate.executed from the gateway itself', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const executedBody = encode({ type: 'gate.executed', request_id: 'req-ok' });
    await expect(
      process('gate.executed', executedBody, keyIDFromPublicKey(gateway.publicKey), gateway.publicKey),
    ).resolves.toBeUndefined();

    // Verify it was stored
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const stored = [...messages.values()].find(m => m.type === 'gate.executed');
    expect(stored).toBeDefined();
    expect(stored!.request_id).toBe('req-ok');
    expect(stored!.signer_kid).toBe(gatewayKid);
  });

  it('rejects gate.executed before promotion', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const executedBody = encode({ type: 'gate.executed', request_id: 'req-1' });
    await expect(
      process('gate.executed', executedBody, keyIDFromPublicKey(gateway.publicKey), gateway.publicKey),
    ).rejects.toThrow('conversation not yet promoted');
  });

  it('forged gate.executed cannot suppress a real request', async () => {
    const { storage, process } = makeDO();
    const state = promotedState();
    await storage.put('conv_state', state);

    // Mallory tries to forge gate.executed for a request she wants to block
    const executedBody = encode({ type: 'gate.executed', request_id: 'req-important' });
    await expect(
      process('gate.executed', executedBody, keyIDFromPublicKey(mallory.publicKey), mallory.publicKey),
    ).rejects.toThrow('only gateway-authored terminal markers are accepted');

    // Verify nothing was stored
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    expect(messages.size).toBe(0);
  });
});

describe('qntm-3gde: signature verification', () => {
  it('accepts a validly signed gate.request', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const { body } = buildSignedRequest(alice);
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).resolves.toBeUndefined();
  });

  it('rejects gate.request with tampered signature', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const { body } = buildSignedRequest(alice);
    // Tamper the signature
    body.signature = base64UrlEncode(new Uint8Array(64));
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('invalid request signature');
  });

  it('rejects gate.request signed by wrong key (envelope sender mismatch)', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Alice signs the request but Mallory sends it
    // (JSON signer_kid says alice, envelope says mallory — signer_kid check fires first)
    const { body } = buildSignedRequest(alice);
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(mallory.publicKey), mallory.publicKey),
    ).rejects.toThrow('signer_kid does not match authenticated sender');
  });

  it('rejects gate.request from non-participant', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Mallory signs with her own key and sends with matching envelope
    const { body } = buildSignedRequest(mallory, {
      signer_kid: malloryKid,
      eligible_signer_kids: [aliceKid, bobKid],
    });
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(mallory.publicKey), mallory.publicKey),
    ).rejects.toThrow('sender is not a participant');
  });

  it('accepts a validly signed gate.approval', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // First store a valid request from Alice
    const { body: reqBody, signable, requestId } = buildSignedRequest(alice);
    await process('gate.request', encode(reqBody), keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Bob sends a valid approval
    const { body: approvalBody } = buildSignedApproval(bob, signable, requestId, 'a'.repeat(32));
    await expect(
      process('gate.approval', encode(approvalBody), keyIDFromPublicKey(bob.publicKey), bob.publicKey),
    ).resolves.toBeUndefined();
  });

  it('rejects gate.approval with invalid signature', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Store a valid request
    const { body: reqBody, requestId } = buildSignedRequest(alice);
    await process('gate.request', encode(reqBody), keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Bob sends approval with garbage signature
    const approvalBody = {
      type: 'gate.approval',
      conv_id: 'a'.repeat(32),
      request_id: requestId,
      signer_kid: bobKid,
      signature: base64UrlEncode(new Uint8Array(64)),
    };
    await expect(
      process('gate.approval', encode(approvalBody), keyIDFromPublicKey(bob.publicKey), bob.publicKey),
    ).rejects.toThrow('invalid approval signature');
  });

  it('rejects gate.approval for nonexistent request', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    const approvalBody = {
      type: 'gate.approval',
      conv_id: 'a'.repeat(32),
      request_id: 'req-nonexistent',
      signer_kid: bobKid,
      signature: base64UrlEncode(new Uint8Array(64)),
    };
    await expect(
      process('gate.approval', encode(approvalBody), keyIDFromPublicKey(bob.publicKey), bob.publicKey),
    ).rejects.toThrow('referenced request not found');
  });

  it('rejects gate.approval from signer not in eligible roster', async () => {
    const { storage, process } = makeDO();
    // Add mallory as participant so she can send messages
    const threeParticipants = {
      [aliceKid]: base64UrlEncode(alice.publicKey),
      [bobKid]: base64UrlEncode(bob.publicKey),
      [malloryKid]: base64UrlEncode(mallory.publicKey),
    };
    await storage.put('conv_state', promotedState({
      participants: threeParticipants,
      promotion_floor: 2,
    }));

    // Alice creates a request with all 3 participants eligible (to pass validation)
    const { body: reqBody } = buildSignedRequest(alice, {
      eligible_signer_kids: [aliceKid, bobKid, malloryKid],
      required_approvals: 2,
    });
    await process('gate.request', encode(reqBody), keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Now create a second request with only alice+bob eligible
    // This must list all current participants per the handler check,
    // so we need to re-promote to remove mallory first
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: { [aliceKid]: base64UrlEncode(alice.publicKey), [bobKid]: base64UrlEncode(bob.publicKey) },
      rules: [{ service: '*', endpoint: '', verb: '', m: 2 }],
      floor: 2,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Alice creates request with alice+bob only (matches new participant set)
    const { body: reqBody2, signable: signable2, requestId: requestId2 } = buildSignedRequest(alice);
    await process('gate.request', encode(reqBody2), keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Mallory (now removed) tries to approve — rejected as non-participant
    const { body: approvalBody } = buildSignedApproval(mallory, signable2, requestId2, 'a'.repeat(32));
    await expect(
      process('gate.approval', encode(approvalBody), keyIDFromPublicKey(mallory.publicKey), mallory.publicKey),
    ).rejects.toThrow('sender is not a participant');
  });
});

describe('qntm-qko0: promotion and membership invariants', () => {
  it('rejects gate.promote with gateway KID in participants', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
        [gatewayKid]: base64UrlEncode(gateway.publicKey), // WRONG
      },
      rules: [],
      floor: 1,
    });
    await expect(
      process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('gateway KID must not be included in participants');
  });

  it('rejects gate.promote with floor < 1', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: { [aliceKid]: base64UrlEncode(alice.publicKey) },
      rules: [],
      floor: 0,
    });
    await expect(
      process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('floor must be >= 1');
  });

  it('rejects gate.request before promotion', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const { body } = buildSignedRequest(alice);
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('conversation not yet promoted');
  });

  it('rejects gate.approval before promotion', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const approvalBody = encode({
      type: 'gate.approval', conv_id: 'a'.repeat(32),
      request_id: 'req-1', signer_kid: aliceKid, signature: 'x',
    });
    await expect(
      process('gate.approval', approvalBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('conversation not yet promoted');
  });

  it('rejects gate.secret before promotion', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ gate_promoted: false }));

    const secretBody = encode({
      type: 'gate.secret', secret_id: 's1', service: 'stripe',
      header_name: 'Authorization', header_template: 'Bearer {value}',
      encrypted_blob: 'aaaa', sender_kid: aliceKid,
    });
    await expect(
      process('gate.secret', secretBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('conversation not yet promoted');
  });

  it('rejects gate.request with required_approvals below floor', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState({ promotion_floor: 2 }));

    // Alice tries to create a request with required_approvals=1 (below floor=2)
    const { body } = buildSignedRequest(alice, { required_approvals: 1 });
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('below promotion floor');
  });

  it('rejects gate.request with eligible_signer_kids not matching participants', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Request lists only alice (missing bob who is a participant)
    const { body } = buildSignedRequest(alice, { eligible_signer_kids: [aliceKid] });
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('missing from eligible_signer_kids');
  });

  it('rejects gate.request with unknown signer in eligible list', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Request includes mallory who is not a participant
    const { body } = buildSignedRequest(alice, { eligible_signer_kids: [aliceKid, bobKid, malloryKid] });
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(alice.publicKey), alice.publicKey),
    ).rejects.toThrow('is not a current participant');
  });

  it('invalidates pending requests when participants change on re-promotion', async () => {
    const { storage, process } = makeDO();
    const state = promotedState();
    await storage.put('conv_state', state);

    // Store a pending request
    await storage.put('msg:00000001', {
      seq: 1, type: 'gate.request', request_id: 'req-pending',
      signer_kid: aliceKid, body: '{}',
    } satisfies StoredGateMessage);

    // Re-promote with different participants (add mallory)
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
        [malloryKid]: base64UrlEncode(mallory.publicKey),
      },
      rules: [],
      floor: 1,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Verify the pending request was invalidated
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const invalidated = [...messages.values()].find(m => m.type === 'gate.invalidated');
    expect(invalidated).toBeDefined();
    expect(invalidated!.request_id).toBe('req-pending');
  });
});

describe('qntm-qtw2: write-ahead execution recovery', () => {
  it('recover() creates executed marker for WAL entries without gate.executed', async () => {
    const { doInstance, storage } = makeDO();
    await storage.put('conv_state', promotedState());

    // Simulate a crashed execution: WAL entry exists but no gate.executed
    await storage.put('wal:req-crashed', { request_id: 'req-crashed', started_at: new Date().toISOString() });

    // Trigger recovery via the private method
    const recover = (doInstance as unknown as { recover: () => Promise<void> }).recover.bind(doInstance);
    await recover();

    // WAL should be cleaned up
    const walEntries = await storage.list({ prefix: 'wal:' });
    expect(walEntries.size).toBe(0);

    // An executed marker should exist
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const executed = [...messages.values()].find(m => m.type === 'gate.executed' && m.request_id === 'req-crashed');
    expect(executed).toBeDefined();
  });

  it('recover() does not duplicate executed marker if gate.executed already exists', async () => {
    const { doInstance, storage } = makeDO();
    await storage.put('conv_state', promotedState());

    // Both WAL and gate.executed exist (normal completion, WAL cleanup failed)
    await storage.put('wal:req-ok', { request_id: 'req-ok', started_at: new Date().toISOString() });
    await storage.put('msg:00000001', {
      seq: 1, type: 'gate.executed', request_id: 'req-ok',
    } satisfies StoredGateMessage);

    const recover = (doInstance as unknown as { recover: () => Promise<void> }).recover.bind(doInstance);
    await recover();

    // WAL cleaned up
    const walEntries = await storage.list({ prefix: 'wal:' });
    expect(walEntries.size).toBe(0);

    // Only one gate.executed marker (the original)
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const executed = [...messages.values()].filter(m => m.type === 'gate.executed');
    expect(executed).toHaveLength(1);
  });
});

describe('participant addition/removal governance', () => {
  it('re-promotion with removed participant invalidates their pending requests', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Bob has a pending request
    await storage.put('msg:00000001', {
      seq: 1, type: 'gate.request', request_id: 'req-bobs',
      signer_kid: bobKid, body: '{}',
    } satisfies StoredGateMessage);

    // Re-promote without Bob (removal)
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
      },
      rules: [{ service: '*', endpoint: '', verb: '', m: 1 }],
      floor: 1,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Bob's request should be invalidated
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const invalidated = [...messages.values()].find(m => m.type === 'gate.invalidated');
    expect(invalidated).toBeDefined();
    expect(invalidated!.request_id).toBe('req-bobs');

    // Verify Bob is no longer a participant
    const state = await storage.get<ConversationState>('conv_state');
    expect(state!.participants).not.toHaveProperty(bobKid);
  });

  it('re-promotion with added participant invalidates pending requests', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Alice has a pending request with eligible=[alice, bob]
    await storage.put('msg:00000001', {
      seq: 1, type: 'gate.request', request_id: 'req-stale',
      signer_kid: aliceKid, body: JSON.stringify({
        eligible_signer_kids: [aliceKid, bobKid],
        required_approvals: 2,
      }),
    } satisfies StoredGateMessage);

    // Re-promote adding mallory — roster changed, pending requests stale
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
        [bobKid]: base64UrlEncode(bob.publicKey),
        [malloryKid]: base64UrlEncode(mallory.publicKey),
      },
      rules: [{ service: '*', endpoint: '', verb: '', m: 2 }],
      floor: 2,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Pending request should be invalidated because participant set changed
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const invalidated = [...messages.values()].find(m => m.type === 'gate.invalidated');
    expect(invalidated).toBeDefined();
    expect(invalidated!.request_id).toBe('req-stale');
  });

  it('removed participant cannot submit new requests after re-promotion', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Re-promote without Bob
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
      },
      rules: [{ service: '*', endpoint: '', verb: '', m: 1 }],
      floor: 1,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Bob tries to submit a request
    const { body } = buildSignedRequest(bob, {
      signer_kid: bobKid,
      eligible_signer_kids: [aliceKid],
      required_approvals: 1,
    });
    await expect(
      process('gate.request', encode(body), keyIDFromPublicKey(bob.publicKey), bob.publicKey),
    ).rejects.toThrow('sender is not a participant');
  });

  it('removed participant cannot approve pending requests', async () => {
    const { storage, process } = makeDO();
    // Only alice is a participant (bob was removed), floor=1, rule m=1
    await storage.put('conv_state', promotedState({
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
      },
      promotion_floor: 1,
      rules: [{ service: '*', endpoint: '', verb: '', m: 1 }],
    }));

    // Alice has a pending request with only herself eligible
    const { body: reqBody, signable, requestId } = buildSignedRequest(alice, {
      eligible_signer_kids: [aliceKid],
      required_approvals: 1,
    });
    await process('gate.request', encode(reqBody), keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Bob tries to approve
    const approvalBody = {
      type: 'gate.approval',
      conv_id: 'a'.repeat(32),
      request_id: requestId,
      signer_kid: bobKid,
      signature: base64UrlEncode(new Uint8Array(64)),
    };
    await expect(
      process('gate.approval', encode(approvalBody), keyIDFromPublicKey(bob.publicKey), bob.publicKey),
    ).rejects.toThrow('sender is not a participant');
  });

  it('re-promotion without participant changes does NOT invalidate pending requests', async () => {
    const { storage, process } = makeDO();
    await storage.put('conv_state', promotedState());

    // Store a pending request
    await storage.put('msg:00000001', {
      seq: 1, type: 'gate.request', request_id: 'req-active',
      signer_kid: aliceKid, body: '{}',
    } satisfies StoredGateMessage);

    // Re-promote with SAME participants but different rules
    const promoteBody = encode({
      type: 'gate.promote',
      conv_id: 'a'.repeat(32),
      gateway_kid: gatewayKid,
      participants: {
        [aliceKid]: base64UrlEncode(alice.publicKey),
        [bobKid]: base64UrlEncode(bob.publicKey),
      },
      rules: [{ service: '*', endpoint: '', verb: '', m: 1 }],
      floor: 1,
    });
    await process('gate.promote', promoteBody, keyIDFromPublicKey(alice.publicKey), alice.publicKey);

    // Pending request should NOT be invalidated
    const messages = await storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const invalidated = [...messages.values()].find(m => m.type === 'gate.invalidated');
    expect(invalidated).toBeUndefined();
  });
});
