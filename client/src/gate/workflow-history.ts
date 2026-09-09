import { gatewayRequestThreshold, gatewayGovernanceQuorum } from './workflow-build.js';
import { gatewayTime, requireGateway, validateGatewayContext } from './workflow-parse.js';
import type { VerifiedGatewayEvent } from './workflow-message.js';
import type { GatewayBody, GatewayContext, GateRequestBody, GatewayProposalBody, GateResultBody } from './workflow-types.js';

export type GatewayWorkflowStatus = 'pending' | 'approved' | 'executed' | 'applied' | 'expired' | 'invalidated';
export interface GatewayWorkflowState<T extends GateRequestBody | GatewayProposalBody> {
  subject: T;
  status: GatewayWorkflowStatus;
  threshold: number;
  approvals: number;
  votes: Record<string, 'approve' | 'disapprove'>;
  result?: GateResultBody;
}
function idOf(body: GatewayBody): string | undefined {
  return 'request_id' in body ? body.request_id : 'proposal_id' in body ? body.proposal_id : undefined;
}
/** Input order must be authenticated relay order, not sender timestamps. */
function history(events: readonly VerifiedGatewayEvent[], conversationId: string): VerifiedGatewayEvent[] {
  const seen = new Map<string, string>();
  return events.filter(event => {
    if (event.conversationId !== conversationId) return false;
    const content = JSON.stringify([event.senderKid, event.body]);
    const previous = seen.get(event.messageId);
    requireGateway(previous === undefined || previous === content, 'Conflicting history message ID');
    if (previous !== undefined) return false;
    seen.set(event.messageId, content);
    return true;
  });
}
function findSubject<T extends GateRequestBody | GatewayProposalBody>(events: readonly VerifiedGatewayEvent[], type: T['type'], id: string): T | undefined {
  let found: T | undefined;
  for (const event of events) {
    if (event.body.type !== type || idOf(event.body) !== id) continue;
    const body = event.body as T;
    requireGateway(!found || JSON.stringify(found) === JSON.stringify(body), 'Ambiguous workflow ID');
    found ??= body;
  }
  return found;
}
export function findGateRequest(events: readonly VerifiedGatewayEvent[], conversationId: string, requestId: string): GateRequestBody | undefined {
  return findSubject<GateRequestBody>(history(events, conversationId), 'gate.request', requestId);
}
export function findGatewayProposal(events: readonly VerifiedGatewayEvent[], conversationId: string, proposalId: string): GatewayProposalBody | undefined {
  return findSubject<GatewayProposalBody>(history(events, conversationId), 'gov.propose', proposalId);
}
function scan<T extends GateRequestBody | GatewayProposalBody>(events: readonly VerifiedGatewayEvent[], context: GatewayContext,
  type: T['type'], id: string, now: number): GatewayWorkflowState<T> | undefined {
  validateGatewayContext(context);
  const ordered = history(events, context.conversationId);
  const subject = findSubject<T>(ordered, type, id);
  if (!subject) return undefined;
  const isRequest = subject.type === 'gate.request';
  const threshold = Math.max(subject.required_approvals, isRequest ? gatewayRequestThreshold(context, subject) : gatewayGovernanceQuorum(context));
  const state: GatewayWorkflowState<T> = { subject, status: 'pending', threshold, approvals: 0, votes: {} };
  let started = false;
  const terminalTypes = isRequest ? ['gate.executed', 'gate.result', 'gate.invalidated'] : ['gov.applied', 'gov.invalidated'];
  for (const event of ordered) {
    if (event.body === subject) started = true;
    if (!started || idOf(event.body) !== id || event.senderKid !== context.gateway.kid || !terminalTypes.includes(event.body.type)) continue;
    if (event.body.type === 'gate.result') state.result = event.body;
    if (state.status === 'pending') state.status = event.body.type.endsWith('invalidated') ? 'invalidated' : isRequest ? 'executed' : 'applied';
  }
  if (state.status !== 'pending') return state;
  const current = Object.keys(context.participants);
  if ((subject.gateway_kid !== context.gateway.kid && !(context.allowLegacyUnbound && !subject.gateway_kid)) ||
      subject.conv_id !== context.conversationId || subject.eligible_signer_kids.length !== current.length ||
      !current.every(kid => subject.eligible_signer_kids.includes(kid))) {
    state.status = 'invalidated'; return state;
  }
  if (now >= gatewayTime(subject.expires_at)) { state.status = 'expired'; return state; }
  const first = ordered.find(event => event.body === subject)!;
  if (first.senderKid !== context.gateway.kid && current.includes(first.senderKid)) state.votes[first.senderKid] = 'approve';
  started = false;
  for (const event of ordered) {
    if (event === first) { started = true; continue; }
    if (!started || idOf(event.body) !== id || event.senderKid === context.gateway.kid || !current.includes(event.senderKid)) continue;
    const body = event.body;
    if (!('conv_id' in body) || body.conv_id !== context.conversationId ||
      ('signer_kid' in body && body.signer_kid !== event.senderKid)) continue;
    if (body.type === (isRequest ? 'gate.approval' : 'gov.approve')) state.votes[event.senderKid] = 'approve';
    if (body.type === (isRequest ? 'gate.disapproval' : 'gov.disapprove')) state.votes[event.senderKid] = 'disapprove';
  }
  state.approvals = Object.values(state.votes).filter(vote => vote === 'approve').length;
  if (state.approvals >= threshold) state.status = 'approved';
  return state;
}
/** A local summary, not execution authorization. Approved does not imply a
 * credential is available, the gateway accepted the request, or execution ran.
 * Supply only events returned by verifyGatewayMessage, preserved in relay order. */
export function scanGateRequest(events: readonly VerifiedGatewayEvent[], context: GatewayContext, requestId: string, now = Date.now()): GatewayWorkflowState<GateRequestBody> | undefined {
  return scan<GateRequestBody>(events, context, 'gate.request', requestId, now);
}
export function scanGatewayProposal(events: readonly VerifiedGatewayEvent[], context: GatewayContext, proposalId: string, now = Date.now()): GatewayWorkflowState<GatewayProposalBody> | undefined {
  return scan<GatewayProposalBody>(events, context, 'gov.propose', proposalId, now);
}
