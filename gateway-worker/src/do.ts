import {
  generateIdentity, keyIDFromPublicKey, base64UrlEncode, base64UrlDecode,
  DropboxClient, deserializeEnvelope, decryptMessage,
  createMessage, serializeEnvelope, defaultTTL, lookupThreshold,
} from '@corpollc/qntm';
import type { Conversation, ConversationKeys, Identity } from '@corpollc/qntm';
import type {
  Env, ConversationState, PromoteRequest, PromoteResponse,
  GatePromoteMessage, GateRequestMessage, GateApprovalMessage,
  GateDisapprovalMessage, GateSecretMessage, GateConfigMessage,
  StoredGateMessage, VaultEntry,
} from './types.js';
import { scanRequestApprovals, findExecutableRequests } from './scan.js';
import { processSecret, importVaultKey, isExpired } from './vault.js';
import { executeRequest } from './execute.js';

/**
 * GatewayConversationDO — one Durable Object instance per gateway-managed conversation.
 */
export class GatewayConversationDO implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private messageSeq = 0;
  private recovered = false;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  /**
   * Recovery: reconstruct messageSeq from stored gate messages.
   * Called lazily on first alarm or fetch after DO eviction/restart.
   * Durable Object storage persists across evictions, so we only
   * need to recover the in-memory sequence counter.
   */
  private async recover(): Promise<void> {
    if (this.recovered) return;
    const entries = await this.state.storage.list<StoredGateMessage>({ prefix: 'msg:' });
    let maxSeq = 0;
    for (const [, msg] of entries) {
      if (msg.seq > maxSeq) maxSeq = msg.seq;
    }
    this.messageSeq = maxSeq;
    this.recovered = true;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/promote') {
      return this.handlePromote(request);
    }

    if (request.method === 'GET' && url.pathname === '/status') {
      return this.handleStatus();
    }

    return new Response('Not Found', { status: 404 });
  }

  /**
   * Bootstrap: create or return the per-conversation keypair.
   * Idempotent.
   */
  private async handlePromote(request: Request): Promise<Response> {
    const body = await request.json() as PromoteRequest;

    const existing = await this.state.storage.get<ConversationState>('conv_state');
    if (existing) {
      if (existing.conv_id !== body.conv_id) {
        return Response.json(
          { error: 'conv_id mismatch: this DO instance is already bootstrapped for a different conversation' },
          { status: 409 },
        );
      }
      return Response.json({
        conv_id: existing.conv_id,
        gateway_public_key: existing.public_key,
        gateway_kid: existing.kid,
        created: false,
      } satisfies PromoteResponse);
    }

    const identity = generateIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(identity.publicKey));

    const convState: ConversationState = {
      conv_id: body.conv_id,
      private_key: base64UrlEncode(identity.privateKey),
      public_key: base64UrlEncode(identity.publicKey),
      kid,
      conv_aead_key: body.conv_aead_key,
      conv_nonce_key: body.conv_nonce_key,
      conv_epoch: body.conv_epoch,
      poll_cursor: 0,
      polling: false,
      promoted_at: new Date().toISOString(),
      gate_promoted: false,
      rules: [],
      participants: {},
      promotion_floor: 1,
    };

    await this.state.storage.put('conv_state', convState);
    await this.state.storage.setAlarm(Date.now() + this.pollIntervalMs());

    return Response.json({
      conv_id: convState.conv_id,
      gateway_public_key: convState.public_key,
      gateway_kid: convState.kid,
      created: true,
    } satisfies PromoteResponse, { status: 201 });
  }

  private async handleStatus(): Promise<Response> {
    const existing = await this.state.storage.get<ConversationState>('conv_state');
    if (!existing) {
      return Response.json({ promoted: false });
    }
    return Response.json({
      promoted: true,
      gate_promoted: existing.gate_promoted,
      conv_id: existing.conv_id,
      gateway_kid: existing.kid,
      polling: existing.polling,
      poll_cursor: existing.poll_cursor,
      promoted_at: existing.promoted_at,
      rules: existing.rules,
    });
  }

  /**
   * Alarm: poll dropbox, decrypt, route, check execution.
   */
  async alarm(): Promise<void> {
    await this.recover();
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) return;

    try {
      convState.polling = true;
      await this.state.storage.put('conv_state', convState);

      const dropbox = new DropboxClient(this.env.DROPBOX_URL);
      const convIdBytes = hexToBytes(convState.conv_id);
      const result = await dropbox.receiveMessages(convIdBytes, convState.poll_cursor, 100);

      if (result.messages.length > 0) {
        const conv = this.buildConversation(convState, convIdBytes);

        for (const envelopeBytes of result.messages) {
          try {
            const envelope = deserializeEnvelope(envelopeBytes);
            const msg = decryptMessage(envelope, conv);
            await this.processGateMessage(msg.inner.body_type, msg.inner.body, msg.inner.sender_kid, msg.inner.sender_ik_pk);
          } catch {
            continue;
          }
        }

        convState.poll_cursor = result.sequence;
        await this.state.storage.put('conv_state', convState);

        // After processing new messages, check for executable requests
        if (convState.gate_promoted) {
          await this.checkAndExecute(convState);
        }
      }
      // Sweep expired secrets every poll cycle
      if (convState.gate_promoted) {
        await this.sweepExpiredSecrets(convState);
      }
    } finally {
      convState.polling = false;
      await this.state.storage.put('conv_state', convState);
      await this.state.storage.setAlarm(Date.now() + this.pollIntervalMs());
    }
  }

  /**
   * Route a decrypted gate message to the appropriate handler.
   */
  private async processGateMessage(bodyType: string, body: Uint8Array, senderKid: Uint8Array, senderPublicKey: Uint8Array): Promise<void> {
    const authenticatedKid = base64UrlEncode(senderKid);
    const bodyStr = new TextDecoder().decode(body);

    // Reject gate actions before promotion (except gate.promote and gate.executed)
    if (bodyType !== 'gate.promote' && bodyType !== 'gate.executed') {
      const convState = await this.state.storage.get<ConversationState>('conv_state');
      if (!convState?.gate_promoted) {
        throw new Error(`${bodyType} rejected: conversation not yet promoted`);
      }
    }

    switch (bodyType) {
      case 'gate.promote':
        await this.handleGatePromote(body, authenticatedKid);
        break;
      case 'gate.request':
        await this.handleGateRequest(bodyStr, authenticatedKid);
        break;
      case 'gate.approval':
        await this.handleGateApproval(bodyStr, authenticatedKid);
        break;
      case 'gate.disapproval':
        await this.handleGateDisapproval(bodyStr, authenticatedKid);
        break;
      case 'gate.secret':
        await this.handleGateSecret(bodyStr, senderKid, senderPublicKey);
        break;
      case 'gate.config':
        await this.handleGateConfig(bodyStr, authenticatedKid);
        break;
      case 'gate.executed':
        await this.handleGateExecuted(bodyStr);
        break;
      default:
        break;
    }
  }

  private async handleGatePromote(body: Uint8Array, authenticatedKid: string): Promise<void> {
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.promote: no bootstrapped state');

    const msg = JSON.parse(new TextDecoder().decode(body)) as GatePromoteMessage;

    if (msg.gateway_kid !== convState.kid) {
      throw new Error(`gate.promote gateway_kid mismatch: expected ${convState.kid}, got ${msg.gateway_kid}`);
    }
    if (msg.conv_id !== convState.conv_id) {
      throw new Error(`gate.promote conv_id mismatch: expected ${convState.conv_id}, got ${msg.conv_id}`);
    }

    // Invalidate pending requests if participants changed on re-promotion
    if (convState.gate_promoted) {
      const oldParticipants = JSON.stringify(Object.keys(convState.participants).sort());
      const newParticipants = JSON.stringify(Object.keys(msg.participants || {}).sort());
      if (oldParticipants !== newParticipants) {
        await this.invalidatePendingRequests();
      }
    }

    convState.gate_promoted = true;
    convState.rules = msg.rules || [];
    convState.participants = msg.participants || {};
    convState.promotion_floor = msg.floor ?? 1;
    await this.state.storage.put('conv_state', convState);
  }

  private async handleGateRequest(bodyStr: string, authenticatedKid: string): Promise<void> {
    const msg = JSON.parse(bodyStr) as GateRequestMessage;

    // Validate JSON signer_kid matches authenticated envelope sender
    if (msg.signer_kid && msg.signer_kid !== authenticatedKid) {
      throw new Error('gate.request rejected: signer_kid does not match authenticated sender');
    }

    // Validate sender is a participant
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.request: no bootstrapped state');
    if (!convState.participants[authenticatedKid]) {
      throw new Error('gate.request rejected: sender is not a participant');
    }

    // Check required_approvals >= promotion floor
    if (msg.required_approvals < convState.promotion_floor) {
      throw new Error(`gate.request rejected: required_approvals ${msg.required_approvals} below promotion floor ${convState.promotion_floor}`);
    }

    // Check required_approvals >= applicable rule threshold
    const rule = lookupThreshold(convState.rules, msg.target_service, msg.target_endpoint, msg.verb);
    if (rule && msg.required_approvals < rule.m) {
      throw new Error(`gate.request rejected: required_approvals ${msg.required_approvals} below rule threshold ${rule.m}`);
    }

    // Check eligible_signer_kids matches current participants
    const currentParticipantKids = new Set(Object.keys(convState.participants));
    const requestedSigners = new Set(msg.eligible_signer_kids);

    for (const kid of requestedSigners) {
      if (!currentParticipantKids.has(kid)) {
        throw new Error(`gate.request rejected: eligible signer ${kid} is not a current participant`);
      }
    }
    for (const kid of currentParticipantKids) {
      if (!requestedSigners.has(kid)) {
        throw new Error(`gate.request rejected: current participant ${kid} missing from eligible_signer_kids`);
      }
    }

    await this.storeGateMessage({
      seq: ++this.messageSeq,
      type: 'gate.request',
      request_id: msg.request_id,
      signer_kid: authenticatedKid,
      signature: msg.signature,
      body: bodyStr,
    });
  }

  private async handleGateApproval(bodyStr: string, authenticatedKid: string): Promise<void> {
    const msg = JSON.parse(bodyStr) as GateApprovalMessage;

    // Validate JSON signer_kid matches authenticated envelope sender
    if (msg.signer_kid && msg.signer_kid !== authenticatedKid) {
      throw new Error('gate.approval rejected: signer_kid does not match authenticated sender');
    }

    // Validate sender is a participant
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.approval: no bootstrapped state');
    if (!convState.participants[authenticatedKid]) {
      throw new Error('gate.approval rejected: sender is not a participant');
    }

    await this.storeGateMessage({
      seq: ++this.messageSeq,
      type: 'gate.approval',
      request_id: msg.request_id,
      signer_kid: authenticatedKid,
      signature: msg.signature,
    });
  }

  private async handleGateDisapproval(bodyStr: string, authenticatedKid: string): Promise<void> {
    const msg = JSON.parse(bodyStr) as GateDisapprovalMessage;

    // Validate JSON signer_kid matches authenticated envelope sender
    if (msg.signer_kid && msg.signer_kid !== authenticatedKid) {
      throw new Error('gate.disapproval rejected: signer_kid does not match authenticated sender');
    }

    // Validate sender is a participant
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.disapproval: no bootstrapped state');
    if (!convState.participants[authenticatedKid]) {
      throw new Error('gate.disapproval rejected: sender is not a participant');
    }

    await this.storeGateMessage({
      seq: ++this.messageSeq,
      type: 'gate.disapproval',
      request_id: msg.request_id,
      signer_kid: authenticatedKid,
    });
  }

  private async handleGateExecuted(bodyStr: string): Promise<void> {
    const msg = JSON.parse(bodyStr) as { request_id: string };
    await this.storeGateMessage({
      seq: ++this.messageSeq,
      type: 'gate.executed',
      request_id: msg.request_id,
    });
  }

  private async handleGateSecret(bodyStr: string, senderKid: Uint8Array, senderPublicKey: Uint8Array): Promise<void> {
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.secret: no bootstrapped state');

    // Validate sender is a participant
    const senderKidStr = base64UrlEncode(senderKid);
    if (!convState.participants[senderKidStr]) {
      throw new Error('gate.secret rejected: sender is not a participant');
    }

    const msg = JSON.parse(bodyStr) as GateSecretMessage;

    const vaultKey = await importVaultKey(this.env.GATE_VAULT_KEY);
    const gatewayPrivateKey = base64UrlDecode(convState.private_key);

    // senderPublicKey is the sender's 32-byte Ed25519 public key (sender_ik_pk)
    // The openSecret function handles Ed25519→X25519 conversion internally
    const entry = await processSecret(msg, gatewayPrivateKey, senderPublicKey, vaultKey);

    // Store in vault (keyed by service for lookup)
    await this.state.storage.put(`vault:${msg.service}`, entry);
  }

  private async handleGateConfig(bodyStr: string, authenticatedKid: string): Promise<void> {
    const convState = await this.state.storage.get<ConversationState>('conv_state');
    if (!convState) throw new Error('gate.config: no bootstrapped state');

    // Validate sender is a participant
    if (!convState.participants[authenticatedKid]) {
      throw new Error('gate.config rejected: sender is not a participant');
    }

    const msg = JSON.parse(bodyStr) as GateConfigMessage;
    convState.rules = msg.rules || [];
    await this.state.storage.put('conv_state', convState);
  }

  /**
   * Sweep expired vault credentials, delete them, and post gate.expired
   * notifications to the conversation so participants know to re-provision.
   */
  private async sweepExpiredSecrets(convState: ConversationState): Promise<void> {
    const entries = await this.state.storage.list<VaultEntry>({ prefix: 'vault:' });
    const now = Date.now();

    for (const [key, entry] of entries) {
      if (!isExpired(entry, now)) continue;

      // Delete the expired entry
      await this.state.storage.delete(key);

      // Post gate.expired notification to conversation
      const convIdBytes = hexToBytes(convState.conv_id);
      const conv = this.buildConversation(convState, convIdBytes);
      const identity = this.buildIdentity(convState);
      const dropbox = new DropboxClient(this.env.DROPBOX_URL);

      const expiredBody = JSON.stringify({
        type: 'gate.expired',
        secret_id: entry.secret_id,
        service: entry.service,
        expired_at: entry.expires_at,
        message: `Credential for ${entry.service} has expired. Please re-provision.`,
      });
      const expiredEnv = createMessage(
        identity, conv, 'gate.expired',
        new TextEncoder().encode(expiredBody), undefined, defaultTTL(),
      );

      try {
        await dropbox.postMessage(convIdBytes, serializeEnvelope(expiredEnv));
      } catch {
        // Best effort: if post fails, the entry is still deleted.
        // Next sweep will not see it again.
      }
    }
  }

  /**
   * Check for requests that have met their approval threshold and execute them.
   */
  private async checkAndExecute(convState: ConversationState): Promise<void> {
    const messages = await this.loadGateMessages();
    const executable = findExecutableRequests(messages, convState.kid, convState.rules);

    for (const scan of executable) {
      if (!scan.request) continue;

      // Check if credential exists and is not expired
      const vaultEntry = await this.state.storage.get<VaultEntry>(`vault:${scan.request.target_service}`);
      if (!vaultEntry) continue;
      if (isExpired(vaultEntry)) continue;

      // Idempotency: check if we already have an executed marker
      const alreadyExecuted = messages.some(
        m => m.type === 'gate.executed' && m.request_id === scan.request_id,
      );
      if (alreadyExecuted) continue;

      // Execute the HTTP request
      const vaultKey = await importVaultKey(this.env.GATE_VAULT_KEY);
      const result = await executeRequest(scan.request, vaultEntry, vaultKey);

      // Post gate.executed and gate.result to the conversation FIRST
      // The conversation is the canonical record of execution.
      const convIdBytes = hexToBytes(convState.conv_id);
      const conv = this.buildConversation(convState, convIdBytes);
      const identity = this.buildIdentity(convState);
      const dropbox = new DropboxClient(this.env.DROPBOX_URL);

      // Send gate.executed
      const executedBody = JSON.stringify({
        type: 'gate.executed',
        request_id: scan.request_id,
        executed_at: result.executed_at,
        execution_status_code: result.status_code,
      });
      const executedEnv = createMessage(
        identity, conv, 'gate.executed',
        new TextEncoder().encode(executedBody), undefined, defaultTTL(),
      );
      await dropbox.postMessage(convIdBytes, serializeEnvelope(executedEnv));

      // Send gate.result
      const resultBody = JSON.stringify({
        type: 'gate.result',
        request_id: scan.request_id,
        status_code: result.status_code,
        content_type: result.content_type,
        body: result.body,
      });
      const resultEnv = createMessage(
        identity, conv, 'gate.result',
        new TextEncoder().encode(resultBody), undefined, defaultTTL(),
      );
      await dropbox.postMessage(convIdBytes, serializeEnvelope(resultEnv));

      // Only store the local marker AFTER successful conversation post.
      // If this fails, the next poll will see the gate.executed from the conversation
      // and create the local marker then (via handleGateExecuted).
      await this.storeGateMessage({
        seq: ++this.messageSeq,
        type: 'gate.executed',
        request_id: scan.request_id,
      });
    }
  }

  private async invalidatePendingRequests(): Promise<void> {
    const messages = await this.loadGateMessages();
    const terminalIds = new Set<string>();
    for (const msg of messages) {
      if ((msg.type === 'gate.executed' || msg.type === 'gate.invalidated') && msg.request_id) {
        terminalIds.add(msg.request_id);
      }
    }
    for (const msg of messages) {
      if (msg.type === 'gate.request' && msg.request_id && !terminalIds.has(msg.request_id)) {
        await this.storeGateMessage({
          seq: ++this.messageSeq,
          type: 'gate.invalidated',
          request_id: msg.request_id,
        });
      }
    }
  }

  // ---- Storage helpers ----

  private async storeGateMessage(msg: StoredGateMessage): Promise<void> {
    const key = `msg:${String(msg.seq).padStart(8, '0')}`;
    await this.state.storage.put(key, msg);
  }

  private async loadGateMessages(): Promise<StoredGateMessage[]> {
    const entries = await this.state.storage.list<StoredGateMessage>({ prefix: 'msg:' });
    const messages: StoredGateMessage[] = [];
    for (const [, value] of entries) {
      messages.push(value);
    }
    return messages;
  }

  private buildIdentity(convState: ConversationState): Identity {
    return {
      privateKey: base64UrlDecode(convState.private_key),
      publicKey: base64UrlDecode(convState.public_key),
      keyID: base64UrlDecode(convState.kid),
    };
  }

  private buildConversation(convState: ConversationState, convIdBytes: Uint8Array): Conversation {
    const keys: ConversationKeys = {
      root: new Uint8Array(32),
      aeadKey: base64UrlDecode(convState.conv_aead_key),
      nonceKey: base64UrlDecode(convState.conv_nonce_key),
    };
    return {
      id: convIdBytes,
      type: 'group',
      keys,
      participants: Object.keys(convState.participants).map(kid => base64UrlDecode(kid)),
      createdAt: new Date(convState.promoted_at),
      currentEpoch: convState.conv_epoch,
    };
  }

  private pollIntervalMs(): number {
    return parseInt(this.env.POLL_INTERVAL_MS || '5000', 10);
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
