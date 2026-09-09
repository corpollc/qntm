/** Local, reviewed gateway actions over the canonical qntm protocol helpers. */
import { createHash, randomUUID } from 'node:crypto';
import { unlinkSync } from 'node:fs';
import { z } from 'zod';
import {
  GateClient, DropboxClient, base64UrlEncode, createGatewayInviteBody, sealGatewayBootstrap,
  sessionGatewayContext, createGatewayMessage, serializeEnvelope, receiveConversationEvent,
  createGateRequestBody, createGateApprovalBody, createGateDisapprovalBody, createGateSecretBody,
  createGatewayProposalBody, createGatewayProposalApprovalBody, createGatewayProposalDisapprovalBody,
  scanGateRequest, scanGatewayProposal,
  type GatewayBody, type GatewayContext, type GatewayReferences, type GatewayInvitation,
  type CreateGateRequestOptions, type CreateGatewayProposalOptions, type CreateGateSecretOptions,
} from '@corpollc/qntm';
import { QntmCheckpointStore, type QntmCheckpoint } from './checkpoint.js';
import { readBoundedFile, writePrivateJSON } from './storage.js';
import { toHex } from './qntm.js';
import type { ResolvedQntmAccount, ResolvedQntmBinding, QntmGatewayAction } from './types.js';

export class GatewayActionError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
function requireState(value: unknown, code: string, message: string): asserts value {
  if (!value) throw new GatewayActionError(code, message);
}
const hex = z.string().regex(/^[0-9a-f]{32}$/);
const safeInteger = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const action = z.enum(['invite', 'request', 'approve', 'disapprove', 'secret', 'propose', 'gov-approve', 'gov-disapprove', 'retry-bootstrap']);
export const GatewayToolInput = z.discriminatedUnion('operation', [
  z.object({ operation: z.literal('status'), offset: safeInteger.optional(), limit: z.number().int().min(1).max(50).optional() }).strict(),
  z.object({ operation: z.literal('prepare'), action, options: z.record(z.string(), z.unknown()).optional() }).strict(),
  z.object({ operation: z.literal('commit'), reviewToken: hex, reviewHash: z.string().regex(/^[0-9a-f]{64}$/) }).strict(),
  z.object({ operation: z.literal('cancel'), reviewToken: hex }).strict(),
]);
export type GatewayInput = z.infer<typeof GatewayToolInput>;
type PreparedAction = QntmGatewayAction | 'retry-bootstrap';
export type GatewayScope = {
  /** Trusted native host context, never tool arguments or message text. */
  key: string;
  account: ResolvedQntmAccount;
  binding: ResolvedQntmBinding;
  store: QntmCheckpointStore;
};
const BootstrapSchema = z.object({
  version: z.literal(1), identityKid: hex, conversationId: hex, epoch: safeInteger,
  relay: z.string().max(2048), url: z.string().max(2048), messageId: hex, sequence: safeInteger,
  expiresAt: safeInteger, gatewayPublicKey: z.string().max(44),
  request: z.object({ invitation_id: hex, inviter_public_key: z.string().max(44), sealed: z.string().max(65536) }).strict(),
}).strict();
type Bootstrap = z.infer<typeof BootstrapSchema>;
type Pending = {
  scope: string; action: PreparedAction; fingerprint: string; expiresAt: number; reviewHash: string;
  body?: GatewayBody; context?: GatewayContext; references: GatewayReferences;
  invitation?: { url: string; value: GatewayInvitation }; bootstrap?: Bootstrap;
  timer?: ReturnType<typeof setTimeout>;
};
type Transport = Pick<DropboxClient, 'postMessage'>;
type GateTransport = Pick<GateClient, 'createInvitation' | 'promote'>;
const MAX_REVIEW_BYTES = 128 * 1024;
const digest = (value: unknown): string => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function fingerprint(scope: GatewayScope, checkpoint: QntmCheckpoint): string {
  return digest({ account: scope.account.accountId, relay: scope.account.relayUrl,
    identity: toHex(scope.account.identity!.publicKey), seed: checkpoint.seedHash,
    actions: scope.binding.gatewayActions, epoch: checkpoint.conversation.currentEpoch,
    keys: Object.values(checkpoint.conversation.keys).map(toHex),
    participants: checkpoint.session.participants, known: checkpoint.conversation.participants.map(toHex),
    removed: checkpoint.session.removed, gateway: checkpoint.session.gateway,
  });
}
function validURL(value: unknown): string {
  requireState(typeof value === 'string', 'invalid_gateway_url', 'Supply a gateway URL');
  let url: URL;
  try { url = new URL(value); } catch { throw new GatewayActionError('invalid_gateway_url', 'Invalid gateway URL'); }
  requireState(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)),
    'invalid_gateway_url', 'Gateway requires HTTPS except on loopback');
  requireState(!url.username && !url.password && !url.search && !url.hash, 'invalid_gateway_url', 'Gateway URL cannot contain credentials, a query or fragment');
  return url.href.replace(/\/$/, '');
}
function optionsOnly(options: Record<string, unknown>, fields: string[]): void {
  requireState(Object.keys(options).every(key => fields.includes(key)), 'invalid_options', 'Unsupported gateway options');
}
function permitted(scope: GatewayScope, action?: PreparedAction): QntmCheckpoint {
  requireState(scope.account.enabled && scope.account.identity && scope.account.configured && scope.binding.enabled,
    'disabled', 'This qntm account or conversation is disabled or unconfigured');
  requireState(Array.isArray(scope.binding.gatewayActions) && scope.binding.gatewayActions.length > 0
    && scope.binding.gatewayActions.every(value => ['invite', 'request', 'approve', 'disapprove', 'secret', 'propose', 'gov-approve', 'gov-disapprove'].includes(value)),
    'disabled', 'Gateway tools are not enabled for this conversation');
  if (action) requireState(scope.binding.gatewayActions.includes(action === 'retry-bootstrap' ? 'invite' : action),
    'action_denied', 'This gateway action is not permitted by local configuration');
  const checkpoint = scope.store.load(scope.binding);
  requireState(!checkpoint.session.removed, 'removed', 'The local identity was removed from this conversation');
  return checkpoint;
}
function bootstrapPath(scope: GatewayScope): string { return `${scope.store.path(scope.binding)}.gateway-bootstrap`; }
export function clearGatewayBootstrap(store: QntmCheckpointStore, binding: ResolvedQntmBinding): void {
  try { unlinkSync(`${store.path(binding)}.gateway-bootstrap`); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
}
function loadBootstrap(scope: GatewayScope): Bootstrap {
  try {
    const value = BootstrapSchema.parse(JSON.parse(readBoundedFile(bootstrapPath(scope), 96 * 1024).toString('utf8')));
    requireState(value.identityKid === toHex(scope.account.identity!.keyID) && value.conversationId === scope.binding.conversationId
      && value.relay === scope.account.relayUrl && value.request.inviter_public_key === base64UrlEncode(scope.account.identity!.publicKey),
      'bootstrap_mismatch', 'Saved bootstrap belongs to a different identity or configuration');
    validURL(value.url);
    return value;
  } catch { throw new GatewayActionError('bootstrap_unavailable', 'No valid saved gateway bootstrap is available'); }
}
function readable(body: unknown): unknown {
  if (!body || typeof body !== 'object') return body;
  const value = { ...(body as Record<string, unknown>) };
  delete value.signature; delete value.encrypted_blob;
  return value;
}

export class QntmGatewayActions {
  private pending = new Map<string, Pending>();
  private preparing = new Set<symbol>();
  constructor(private readonly deps: {
    now?: () => number; client?: (url: string) => Transport; gate?: (url: string, signal?: AbortSignal) => GateTransport;
    saveBootstrap?: typeof writePrivateJSON;
  } = {}) {}
  private now(): number { return this.deps.now?.() ?? Date.now(); }
  private prune(): void {
    for (const [token, pending] of this.pending) if (pending.expiresAt <= this.now()) this.discard(token);
  }
  private discard(token: string): void {
    clearTimeout(this.pending.get(token)?.timer);
    this.pending.delete(token);
  }
  private gate(url: string, signal?: AbortSignal): GateTransport { return this.deps.gate?.(url, signal) ?? new GateClient(url, { signal }); }
  private client(url: string): Transport { return this.deps.client?.(url) ?? new DropboxClient(url); }

  status(scope: GatewayScope, offset = 0, limit = 20): unknown {
    const state = permitted(scope).session;
    if (!state.gateway) return { status: 'no_invitation', permittedActions: scope.binding.gatewayActions };
    if (!state.gateway.accepted) return { status: 'awaiting_signed_acceptance', gateway: state.gateway.context.gateway,
      invitationMessageId: state.gateway.invitation.messageId, expiresAt: state.gateway.invitation.body.expires_at,
      permittedActions: scope.binding.gatewayActions };
    const context = sessionGatewayContext(state);
    const subjects = new Map<string, { kind: string; id: string }>();
    for (const event of state.events) {
      const subject = event.body.type === 'gate.request' ? { kind: 'request', id: event.body.request_id }
        : event.body.type === 'gov.propose' ? { kind: 'proposal', id: event.body.proposal_id } : undefined;
      if (subject) subjects.set(JSON.stringify(subject), subject);
    }
    const entries = [...subjects.values()].slice(offset, offset + limit).map(({ kind, id }) => {
      const summary = kind === 'request' ? scanGateRequest(state.events, context, id)! : scanGatewayProposal(state.events, context, id)!;
      return { kind, id, status: summary.status, approvals: summary.approvals, threshold: summary.threshold };
    });
    return { status: 'accepted', context, permittedActions: scope.binding.gatewayActions, entries,
      total: subjects.size, nextOffset: offset + entries.length < subjects.size ? offset + entries.length : null };
  }

  async prepare(scope: GatewayScope, action: PreparedAction, options: Record<string, unknown> = {}, signal?: AbortSignal): Promise<unknown> {
    this.prune();
    requireState(this.pending.size + this.preparing.size < 64, 'review_capacity', 'Too many pending reviews; cancel a review or wait for expiry');
    requireState(!signal?.aborted, 'cancelled', 'Gateway action was cancelled before preparation');
    const slot = Symbol();
    this.preparing.add(slot);
    try { return await this.prepareReview(scope, action, options, slot, signal); }
    finally { this.preparing.delete(slot); }
  }

  private async prepareReview(scope: GatewayScope, action: PreparedAction, options: Record<string, unknown>, slot: symbol, signal?: AbortSignal): Promise<unknown> {
    const encodedOptions = JSON.stringify(options);
    requireState(Buffer.byteLength(encodedOptions) <= 65536, 'options_too_large', 'Gateway options exceed 64 KiB');
    options = JSON.parse(encodedOptions); // Hold immutable reviewed values, not caller-owned payload objects.
    const checkpoint = permitted(scope, action);
    const originalFingerprint = fingerprint(scope, checkpoint);
    const state = checkpoint.session, conversation = checkpoint.conversation, identity = scope.account.identity!;
    let context: GatewayContext | undefined, body: GatewayBody | undefined;
    let references: GatewayReferences = {}, invitation: Pending['invitation'], bootstrap: Bootstrap | undefined, subject: unknown;
    let expiresAt = this.now() + 300_000;
    if (action === 'retry-bootstrap') {
      optionsOnly(options, []);
      bootstrap = loadBootstrap(scope);
      requireState(!state.gateway?.accepted && state.gateway?.invitation.messageId === bootstrap.messageId
        && conversation.currentEpoch === bootstrap.epoch
        && state.gateway.invitation.body.invitation_id === bootstrap.request.invitation_id
        && state.gateway.invitation.body.expires_at === bootstrap.expiresAt
        && state.gateway.context.gateway.publicKey === bootstrap.gatewayPublicKey,
        'bootstrap_stale', 'Saved bootstrap no longer matches the current invitation');
      expiresAt = Math.min(expiresAt, bootstrap.expiresAt * 1000);
      context = state.gateway.context;
      subject = { gatewayURL: bootstrap.url, gatewayPublicKey: bootstrap.gatewayPublicKey, invitationMessageId: bootstrap.messageId };
    } else if (action === 'invite') {
      optionsOnly(options, ['gatewayUrl', 'floor']);
      requireState(!state.gateway?.accepted, 'already_accepted', 'This conversation already has an accepted gateway');
      requireState(!state.gateway || state.gateway.invitation.body.expires_at * 1000 <= this.now(), 'invitation_pending', 'A gateway invitation is still pending');
      const url = validURL(options.gatewayUrl), invitationId = randomUUID().replaceAll('-', '');
      const value = await this.gate(url, signal).createInvitation(base64UrlEncode(identity.publicKey), invitationId);
      requireState(value.invitation_id === invitationId && value.inviter_public_key === base64UrlEncode(identity.publicKey)
        && Number.isSafeInteger(value.expires_at) && value.expires_at * 1000 > this.now() && value.expires_at * 1000 <= this.now() + 600_000,
        'invalid_invitation', 'Gateway returned an invalid or mismatched invitation');
      requireState(options.floor === undefined || typeof options.floor === 'number', 'invalid_options', 'Gateway floor must be a number');
      body = createGatewayInviteBody(value, conversation, state.participants, options.floor ?? 1);
      context = { conversationId: scope.binding.conversationId, epoch: conversation.currentEpoch,
        gateway: { kid: value.gateway_kid, publicKey: value.gateway_public_key }, participants: body.participants, floor: body.floor, rules: body.rules };
      invitation = { url, value };
    } else {
      context = sessionGatewayContext(state);
      if (action === 'request') {
        optionsOnly(options, ['service', 'endpoint', 'verb', 'targetUrl', 'payload', 'recipeName', 'arguments', 'requiredApprovals', 'expiresInSeconds']);
        body = createGateRequestBody(identity, context, options as unknown as CreateGateRequestOptions);
      } else if (action === 'secret') {
        optionsOnly(options, ['service', 'value', 'headerName', 'headerTemplate', 'ttl']);
        requireState(typeof options.value === 'string' && options.value.length > 0, 'invalid_secret', 'Supply a nonempty credential value');
        const bytes = Buffer.from(options.value, 'utf8');
        subject = { secretBytes: bytes.length, secretSha256: createHash('sha256').update(bytes).digest('hex') };
        try { body = createGateSecretBody(identity, context, { ...options, value: bytes } as unknown as CreateGateSecretOptions); }
        finally { bytes.fill(0); }
      } else if (action === 'propose') {
        optionsOnly(options, ['proposalType', 'proposedFloor', 'proposedRules', 'proposedMembers', 'removedMemberKids', 'requiredApprovals', 'expiresInSeconds']);
        body = createGatewayProposalBody(identity, context, options as unknown as CreateGatewayProposalOptions);
      } else {
        optionsOnly(options, ['id']);
        requireState(typeof options.id === 'string' && options.id.length > 0 && options.id.length <= 256, 'invalid_subject', 'Use the complete verified request or proposal ID');
        if (action === 'approve' || action === 'disapprove') {
          const summary = scanGateRequest(state.events, context, options.id);
          requireState(summary && ['pending', 'approved'].includes(summary.status), 'subject_unavailable', 'The verified request is absent, expired or no longer pending');
          references = { request: summary.subject }; subject = { ...summary, subject: readable(summary.subject) };
          body = action === 'approve' ? createGateApprovalBody(identity, context, summary.subject) : createGateDisapprovalBody(identity, context, summary.subject);
        } else {
          const summary = scanGatewayProposal(state.events, context, options.id);
          requireState(summary && ['pending', 'approved'].includes(summary.status), 'subject_unavailable', 'The verified proposal is absent, expired or no longer pending');
          references = { proposal: summary.subject }; subject = { ...summary, subject: readable(summary.subject) };
          body = action === 'gov-approve' ? createGatewayProposalApprovalBody(identity, context, summary.subject) : createGatewayProposalDisapprovalBody(identity, context, summary.subject);
        }
      }
    }
    if (body) {
      const envelope = createGatewayMessage(identity, conversation, body, context!, references);
      if (invitation) receiveConversationEvent(envelope, conversation, identity, state);
      if ('expires_at' in body) expiresAt = Math.min(expiresAt, typeof body.expires_at === 'number' ? body.expires_at * 1000 : Date.parse(body.expires_at));
    }
    requireState(expiresAt > this.now(), 'review_expired', 'This gateway action has expired');
    requireState(!signal?.aborted, 'cancelled', 'Gateway action was cancelled during preparation');
    requireState(fingerprint(scope, permitted(scope, action)) === originalFingerprint, 'review_stale', 'Conversation changed during preparation; prepare again');
    const review = { action, accountId: scope.account.accountId, conversationId: scope.binding.conversationId,
      signer: base64UrlEncode(identity.publicKey), relay: scope.account.relayUrl, gatewayURL: invitation?.url,
      context, subject, body: readable(body), expiresAt,
      effect: action === 'invite' || action === 'retry-bootstrap'
        ? 'Discloses current conversation keys to this gateway. Authority starts only after its signed chat acceptance. Previously shared keys are not revoked.'
        : action === 'secret' ? 'Seals the credential to the gateway. Plaintext supplied as tool input can remain in local host transcripts.'
        : action === 'disapprove' || action === 'gov-disapprove' ? 'Withdraws this identity’s vote; does not veto others or undo execution.'
        : 'Sends this signed action. Its signature may satisfy an approval threshold and authorize an API call or governance change.',
    };
    requireState(Buffer.byteLength(JSON.stringify(review)) <= MAX_REVIEW_BYTES, 'review_too_large', 'Complete gateway review exceeds 128 KiB');
    const reviewToken = randomUUID().replaceAll('-', ''), reviewHash = digest(review);
    const timer = setTimeout(() => this.discard(reviewToken), Math.max(0, expiresAt - this.now()));
    timer.unref();
    this.pending.set(reviewToken, { scope: scope.key, action, fingerprint: originalFingerprint, expiresAt, reviewHash, body, context, references, invitation, bootstrap, timer });
    this.preparing.delete(slot);
    return { status: 'review_required', reviewToken, reviewHash, review: JSON.parse(JSON.stringify(review)) };
  }

  cancel(scope: GatewayScope, token: string): unknown {
    const pending = this.pending.get(token);
    requireState(pending?.scope === scope.key, 'review_unavailable', 'No review belongs to this host session and conversation');
    this.discard(token);
    return { status: 'cancelled' };
  }

  async commit(scope: GatewayScope, token: string, reviewHash: string, signal?: AbortSignal): Promise<unknown> {
    this.prune();
    const pending = this.pending.get(token);
    requireState(pending?.scope === scope.key, 'review_unavailable', 'No review belongs to this host session and conversation');
    requireState(pending.reviewHash === reviewHash, 'review_mismatch', 'Commit must match the complete reviewed content');
    this.discard(token); // One attempt, including failures and ambiguous acknowledgements.
    requireState(!signal?.aborted, 'cancelled', 'Gateway action was cancelled before sending');
    const checkpoint = permitted(scope, pending.action);
    requireState(fingerprint(scope, checkpoint) === pending.fingerprint, 'review_stale', 'Conversation or local policy changed; prepare again');
    const { context, body, references, invitation } = pending;
    if (references.request) {
      const summary = scanGateRequest(checkpoint.session.events, context!, references.request.request_id);
      requireState(summary && ['pending', 'approved'].includes(summary.status), 'subject_unavailable', 'Request is no longer pending');
    }
    if (references.proposal) {
      const summary = scanGatewayProposal(checkpoint.session.events, context!, references.proposal.proposal_id);
      requireState(summary && ['pending', 'approved'].includes(summary.status), 'subject_unavailable', 'Proposal is no longer pending');
    }
    if (pending.bootstrap) {
      requireState(digest(loadBootstrap(scope)) === digest(pending.bootstrap), 'bootstrap_stale', 'Saved bootstrap changed since review');
      await this.gate(pending.bootstrap.url, signal).promote(pending.bootstrap.request);
      return { status: 'awaiting_signed_acceptance', invitationMessageId: pending.bootstrap.messageId };
    }
    const envelope = createGatewayMessage(scope.account.identity!, checkpoint.conversation, body!, context!, references);
    const messageId = toHex(envelope.msg_id);
    let sequence: number;
    try { sequence = await this.client(scope.account.relayUrl).postMessage(checkpoint.conversation.id, serializeEnvelope(envelope)); }
    catch { return { status: 'delivery_unknown', messageId, conversationId: scope.binding.conversationId,
      instruction: 'Inspect verified conversation history before preparing another action. This attempt will not be automatically retried.' }; }
    if (invitation) {
      const bootstrap: Bootstrap = { version: 1, identityKid: toHex(scope.account.identity!.keyID), conversationId: scope.binding.conversationId,
        epoch: checkpoint.conversation.currentEpoch, relay: scope.account.relayUrl, url: invitation.url, messageId, sequence,
        expiresAt: invitation.value.expires_at, gatewayPublicKey: invitation.value.gateway_public_key,
        request: sealGatewayBootstrap(scope.account.identity!, invitation.value, checkpoint.conversation, messageId, sequence) };
      try { (this.deps.saveBootstrap ?? writePrivateJSON)(bootstrapPath(scope), bootstrap, 96 * 1024); }
      catch { return { status: 'invitation_posted_bootstrap_not_saved', messageId, sequence,
        instruction: 'The invitation was posted, but sealed bootstrap persistence failed. It was not delivered; do not blindly repeat admission.' }; }
      if (signal?.aborted) return { status: 'invitation_posted_bootstrap_pending', messageId, sequence,
        instruction: 'Cancelled after the invitation POST. Its sealed bootstrap is saved for explicit retry after the subscription verifies the invitation.' };
      try { await this.gate(invitation.url, signal).promote(bootstrap.request); }
      catch { return { status: 'invitation_posted_bootstrap_pending', messageId, sequence,
        instruction: 'Prepare retry-bootstrap after the subscription verifies this invitation; retry sends only its saved sealed bootstrap.' }; }
      return { status: 'awaiting_signed_acceptance', messageId, sequence };
    }
    // The subscription is the only writer of protocol state and relay progress.
    return { status: 'submitted', bodyType: body!.type, messageId, sequence,
      instruction: 'Submission is not execution. Inspect verified gateway events for the result.' };
  }
}
