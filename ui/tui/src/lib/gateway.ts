/** Explicit local actions. Network messages never invoke this controller. */
import fs from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import {
  GateClient, base64UrlEncode, createGatewayInviteBody, sealGatewayBootstrap,
  sessionGatewayContext, createGatewayMessage, serializeEnvelope,
  createGateRequestBody, createGateApprovalBody, createGateDisapprovalBody, createGateSecretBody,
  createGatewayProposalBody, createGatewayProposalApprovalBody, createGatewayProposalDisapprovalBody,
  scanGateRequest, scanGatewayProposal, receiveConversationEvent,
  type DropboxClient, type Identity, type GatewayBody, type GatewayContext, type GatewayReferences,
  type GatewayInvitation, type GatewaySessionState, type CreateGateRequestOptions,
  type CreateGateSecretOptions, type CreateGatewayProposalOptions,
} from '@corpollc/qntm';
import { Store, bytesToHex } from './store.js';

export interface GatewayReview { title: string; details: string }
interface Pending {
  conversationId: string;
  fingerprint: string;
  context: GatewayContext;
  body: GatewayBody;
  references: GatewayReferences;
  invitation?: { url: string; value: GatewayInvitation };
}
const json = (value: unknown) => JSON.stringify(value, null, 2);
const invariant = (ok: unknown, message: string): void => { if (!ok) throw new Error(message); };

/** Preserve every character without letting terminal escape/bidi controls act. */
export function terminalText(value: string): string {
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
function gatewayURL(input: string): string {
  const url = new URL(input);
  invariant(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)), 'Gateway URL must use HTTPS (HTTP allowed on loopback)');
  invariant(!url.username && !url.password && !url.search && !url.hash, 'Gateway URL must not contain credentials, query, or fragment');
  return url.toString().replace(/\/$/, '');
}
function readOptions(filename: string, allowed: string[]): Record<string, unknown> {
  invariant(filename.trim(), 'Supply a JSON file path; see /help for the command');
  const fd = fs.openSync(filename.trim(), 'r');
  try {
    const info = fs.fstatSync(fd);
    invariant(info.isFile() && info.size <= 65536, 'Options must be a regular JSON file of at most 64 KiB');
    const bytes = Buffer.alloc(65537);
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    invariant(length <= 65536, 'Options exceed 64 KiB');
    let data: unknown;
    try { data = JSON.parse(bytes.subarray(0, length).toString('utf8')); }
    catch { throw new Error('Options file is not valid JSON'); }
    finally { bytes.fill(0); }
    invariant(data && typeof data === 'object' && !Array.isArray(data), 'Options must be a JSON object');
    invariant(Object.keys(data as object).every(key => allowed.includes(key)), 'Options contain unsupported fields');
    return data as Record<string, unknown>;
  } finally { fs.closeSync(fd); }
}
function fingerprint(store: Store, id: string, state: GatewaySessionState): string {
  const conv = store.getConversationCrypto(id)!;
  return createHash('sha256').update(JSON.stringify({ epoch: conv.currentEpoch, keys: Object.values(conv.keys).map(bytesToHex),
    participants: state.participants, known: conv.participants.map(bytesToHex), removed: state.removed,
    gateway: state.gateway && { accepted: state.gateway.accepted, context: state.gateway.context, invitation: state.gateway.invitation.messageId },
  })).digest('hex');
}
function subjectId(state: GatewaySessionState, kind: 'gate.request' | 'gov.propose', prefix: string): string {
  invariant(prefix.length >= 4, 'Use at least four characters of the request or proposal ID');
  const ids = [...new Set(state.events.flatMap(event => event.body.type === kind
    ? [event.body.type === 'gate.request' ? event.body.request_id : (event.body as { proposal_id: string }).proposal_id] : []))]
    .filter(id => id.startsWith(prefix));
  invariant(ids.length === 1, ids.length ? 'ID prefix is ambiguous; provide more characters' : 'No verified request or proposal matches that ID');
  return ids[0];
}

export class GatewayActions {
  private pending?: Pending;
  constructor(private store: Store, private dropbox: DropboxClient, private identity: Identity) {}
  cancel(): void { this.pending = undefined; }

  status(id: string): string {
    const state = this.store.gatewaySession(id, this.identity);
    if (state.removed) return 'You have been removed from this conversation.';
    if (!state.gateway) return 'No verified gateway invitation. Use /gate invite <https-url> [floor]. Older histories cannot establish gateway authority from display text alone.';
    if (!state.gateway.accepted) return `Waiting for signed acceptance from ${state.gateway.context.gateway.publicKey}. /gate retry resubmits a saved bootstrap after an HTTP failure.`;
    const context = sessionGatewayContext(state);
    const requests = [...new Set(state.events.flatMap(e => e.body.type === 'gate.request' ? [e.body.request_id] : []))];
    const proposals = [...new Set(state.events.flatMap(e => e.body.type === 'gov.propose' ? [e.body.proposal_id] : []))];
    const rows = [json(context)];
    for (const request of requests) {
      const summary = scanGateRequest(state.events, context, request)!;
      rows.push(`Request ${request}: ${summary.status}; ${summary.approvals}/${summary.threshold} approvals`);
    }
    for (const proposal of proposals) {
      const summary = scanGatewayProposal(state.events, context, proposal)!;
      rows.push(`Proposal ${proposal}: ${summary.status}; ${summary.approvals}/${summary.threshold} approvals`);
    }
    return rows.join('\n');
  }

  async retry(id: string): Promise<string> {
    const stored = this.store.findConversation(id);
    invariant(stored?.pendingGatewayBootstrap, 'No saved gateway bootstrap to retry');
    if (stored!.session?.gateway?.accepted) return 'Gateway already accepted in chat.';
    const pending = stored!.pendingGatewayBootstrap!;
    await new GateClient(pending.url).promote(pending.request);
    return 'Bootstrap delivered. Waiting for the gateway to accept in chat.';
  }

  async prepare(id: string, command: string, args: string): Promise<GatewayReview> {
    this.cancel();
    const state = this.store.gatewaySession(id, this.identity);
    const conversation = this.store.getConversationCrypto(id)!;
    invariant(!state.removed, 'You have been removed from this conversation');
    const checkpoint = fingerprint(this.store, id, state);
    let context: GatewayContext, body: GatewayBody;
    let references: GatewayReferences = {}, invitation: Pending['invitation'];
    let subject: unknown;
    if (command === 'gate') {
      invariant(!state.gateway?.accepted, 'Gateway is already accepted in this conversation');
      invariant(!state.gateway || state.gateway.invitation.body.expires_at * 1000 <= Date.now(), 'Invitation is still pending; use /gate or /gate retry until it expires');
      const [action, address, floorValue, ...rest] = args.trim().split(/\s+/);
      invariant(action === 'invite' && address && rest.length === 0, 'Usage: /gate invite <https-url> [floor]');
      const url = gatewayURL(address), invitationId = randomUUID().replaceAll('-', '');
      const value = await new GateClient(url).createInvitation(base64UrlEncode(this.identity.publicKey), invitationId);
      invariant(value.invitation_id === invitationId && value.inviter_public_key === base64UrlEncode(this.identity.publicKey), 'Gateway returned a mismatched invitation');
      invariant(Number.isSafeInteger(value.expires_at) && value.expires_at > Math.floor(Date.now() / 1000) && value.expires_at <= Math.floor(Date.now() / 1000) + 600, 'Gateway returned an invalid invitation expiry');
      body = createGatewayInviteBody(value, conversation, state.participants, floorValue === undefined ? 1 : Number(floorValue));
      context = { conversationId: id, epoch: conversation.currentEpoch, gateway: { kid: value.gateway_kid, publicKey: value.gateway_public_key }, participants: body.participants, floor: body.floor, rules: body.rules };
      invitation = { url, value };
    } else {
      context = sessionGatewayContext(state);
      switch (command) {
        case 'request': {
          const options = readOptions(args, ['service', 'endpoint', 'verb', 'targetUrl', 'payload', 'recipeName', 'arguments', 'requiredApprovals', 'expiresInSeconds']);
          body = createGateRequestBody(this.identity, context, options as unknown as CreateGateRequestOptions);
          break;
        }
        case 'secret': {
          const options = readOptions(args, ['service', 'value', 'headerName', 'headerTemplate', 'ttl']);
          invariant(typeof options.value === 'string' && options.value.length > 0, 'Secret value must be a nonempty string');
          const bytes = Buffer.from(options.value as string, 'utf8');
          subject = { secret_bytes: bytes.length, secret_sha256: createHash('sha256').update(bytes).digest('hex') };
          try { body = createGateSecretBody(this.identity, context, { ...options, value: bytes } as unknown as CreateGateSecretOptions); }
          finally { bytes.fill(0); delete options.value; }
          break;
        }
        case 'propose': {
          const options = readOptions(args, ['proposalType', 'proposedFloor', 'proposedRules', 'proposedMembers', 'removedMemberKids', 'requiredApprovals', 'expiresInSeconds']);
          body = createGatewayProposalBody(this.identity, context, options as unknown as CreateGatewayProposalOptions);
          break;
        }
        case 'approve': case 'disapprove': {
          const requestId = subjectId(state, 'gate.request', args.trim());
          const summary = scanGateRequest(state.events, context, requestId)!;
          invariant(['pending', 'approved'].includes(summary.status), `Request is ${summary.status}`);
          subject = summary; references = { request: summary.subject };
          body = command === 'approve' ? createGateApprovalBody(this.identity, context, summary.subject) : createGateDisapprovalBody(this.identity, context, summary.subject);
          break;
        }
        case 'gov-approve': case 'gov-disapprove': {
          const proposalId = subjectId(state, 'gov.propose', args.trim());
          const summary = scanGatewayProposal(state.events, context, proposalId)!;
          invariant(['pending', 'approved'].includes(summary.status), `Proposal is ${summary.status}`);
          subject = summary; references = { proposal: summary.subject };
          body = command === 'gov-approve' ? createGatewayProposalApprovalBody(this.identity, context, summary.subject) : createGatewayProposalDisapprovalBody(this.identity, context, summary.subject);
          break;
        }
        default: throw new Error('Unknown gateway action');
      }
    }
    // Validate the same admission/event path receivers use, before showing review.
    const envelope = createGatewayMessage(this.identity, conversation, body, context, references);
    if (invitation) receiveConversationEvent(envelope, conversation, this.identity, state);
    invariant(fingerprint(this.store, id, this.store.gatewaySession(id, this.identity)) === checkpoint, 'Conversation changed while preparing; review again');
    this.pending = { conversationId: id, fingerprint: checkpoint, context, body, references, invitation };
    const withdrawal = body.type === 'gate.disapproval' || body.type === 'gov.disapprove';
    const disclosure = invitation
      ? 'This gateway will receive the current conversation keys, read decryptable chat, and enforce the shown API policy after accepting in chat.' + (state.gateway ? ' Replacing an expired invitation does not revoke keys previously disclosed to another gateway.' : '')
      : body.type === 'gate.secret' ? 'The credential is sealed to this gateway. Only its byte length and SHA-256 appear below. The source file remains on disk.'
      : withdrawal ? 'This withdraws your vote. It does not veto other participants or undo an executed action.'
      : body.type === 'gate.approval' ? 'Your approval can authorize this API call when the required vote count is reached.'
      : body.type === 'gov.approve' ? 'Your approval can authorize this governance change when the required quorum is reached.'
      : 'This signed action will be sent to the conversation. Your signature counts as the first approval.';
    const readableBody = (value: unknown) => {
      const copy = { ...(value as Record<string, unknown>) };
      for (const key of ['signature', 'encrypted_blob']) delete copy[key];
      return copy;
    };
    const shownSubject = subject && typeof subject === 'object' && 'subject' in subject
      ? { ...subject, subject: readableBody(subject.subject) } : subject;
    const action = readableBody(body);
    // Put the requested effect first. Audience and identity remain complete;
    // signature/ciphertext bytes are held privately, not useful review content.
    return { title: `Review ${body.type}`, details: terminalText(`${disclosure}\n\n${json({ subject: shownSubject, action, relay: this.store.dropboxUrl, gateway_url: invitation?.url, context })}`) };
  }

  async confirm(id: string): Promise<string> {
    const pending = this.pending;
    this.cancel(); // A failed send is not silently retried with a new envelope.
    invariant(pending && pending.conversationId === id, 'No reviewed action for the active conversation');
    const { body, context, references, invitation } = pending!;
    const state = this.store.gatewaySession(id, this.identity);
    invariant(fingerprint(this.store, id, state) === pending!.fingerprint, 'Conversation changed since review; prepare the action again');
    if ('expires_at' in body) invariant(typeof body.expires_at === 'number' ? Date.now() < body.expires_at * 1000 : Date.now() < Date.parse(body.expires_at), 'Reviewed action expired');
    if (references.request) {
      const summary = scanGateRequest(state.events, context, references.request.request_id);
      invariant(summary && ['pending', 'approved'].includes(summary.status), 'Request is no longer pending');
    }
    if (references.proposal) {
      const summary = scanGatewayProposal(state.events, context, references.proposal.proposal_id);
      invariant(summary && ['pending', 'approved'].includes(summary.status), 'Proposal is no longer pending');
    }
    const conversation = this.store.getConversationCrypto(id)!;
    const envelope = createGatewayMessage(this.identity, conversation, body, context, references);
    const sequence = await this.dropbox.postMessage(conversation.id, serializeEnvelope(envelope));
    const receipt = `Message ${bytesToHex(envelope.msg_id)}.`;
    // Receive-order state is advanced only by the subscription, never this POST.
    this.store.appendHistory(id, { id: bytesToHex(envelope.msg_id), conversationId: id, direction: 'outgoing', sender: 'You', senderKey: bytesToHex(this.identity.keyID), bodyType: body.type, text: JSON.stringify(body), createdAt: new Date(envelope.created_ts * 1000).toISOString(), gatewayVerified: true });
    if (invitation) {
      const request = sealGatewayBootstrap(this.identity, invitation.value, conversation, bytesToHex(envelope.msg_id), sequence);
      this.store.updateConversation(id, stored => { stored.pendingGatewayBootstrap = { url: invitation.url, request }; });
      try { await new GateClient(invitation.url).promote(request); }
      catch { throw new Error('Invitation posted; bootstrap delivery failed. Use /gate retry to resend the saved sealed bootstrap.'); }
      return `Invitation posted. ${receipt} Waiting for signed gateway acceptance in chat.`;
    }
    return `${body.type} sent. ${receipt} Watch /gate for verified votes and results; approvals alone do not prove execution.`;
  }
}
