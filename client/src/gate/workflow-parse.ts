import { base64UrlDecode, base64UrlEncode, keyIDFromPublicKey } from '../identity/index.js';
import type { ThresholdRule } from '../types.js';
import type { GatewayBody, GatewayBodyType, GatewayContext } from './workflow-types.js';

export class GatewayValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'GatewayValidationError'; }
}
export function requireGateway(condition: unknown, message: string): asserts condition {
  if (!condition) throw new GatewayValidationError(message);
}
export function gatewayText(value: unknown, name: string, max = 4096): string {
  requireGateway(typeof value === 'string' && value.length > 0 && value.length <= max, `Invalid ${name}`);
  return value;
}
export function gatewayInteger(value: unknown, name: string, min = 0): number {
  requireGateway(typeof value === 'number' && Number.isSafeInteger(value) && value >= min, `Invalid ${name}`);
  return value;
}
export function gatewayBytes(value: unknown, name: string, length?: number): Uint8Array {
  const text = gatewayText(value, name, 2_000_000);
  let bytes: Uint8Array;
  try { bytes = base64UrlDecode(text); } catch { throw new GatewayValidationError(`Invalid ${name}`); }
  requireGateway(base64UrlEncode(bytes) === text && (length === undefined || bytes.length === length), `Invalid ${name}`);
  return bytes;
}
export function gatewayRecord(value: unknown, name: string): Record<string, unknown> {
  requireGateway(value !== null && typeof value === 'object' && !Array.isArray(value), `Invalid ${name}`);
  return value as Record<string, unknown>;
}
export function gatewayTime(value: unknown, name = 'expires_at'): number {
  const text = gatewayText(value, name);
  requireGateway(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(text), `Invalid ${name}`);
  const time = Date.parse(text);
  requireGateway(Number.isFinite(time), `Invalid ${name}`);
  return time;
}
function hex(value: unknown, name: string, length: number): void {
  requireGateway(typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value), `Invalid ${name}`);
}
export function gatewayRoster(value: unknown): string[] {
  requireGateway(Array.isArray(value) && value.length > 0, 'Invalid signer roster');
  value.forEach(kid => gatewayBytes(kid, 'signer kid', 16));
  requireGateway(new Set(value).size === value.length, 'Duplicate signer');
  return value as string[];
}
export function gatewayRules(value: unknown): ThresholdRule[] {
  requireGateway(Array.isArray(value), 'Invalid rules');
  for (const item of value) {
    const rule = gatewayRecord(item, 'rule');
    for (const field of ['service', 'endpoint', 'verb']) requireGateway(typeof rule[field] === 'string', `Invalid rule ${field}`);
    gatewayInteger(rule.m, 'rule threshold', 1);
    if (rule.n !== undefined) gatewayInteger(rule.n, 'rule signer count', 1);
  }
  return value as ThresholdRule[];
}
export function gatewayParticipants(value: unknown): Record<string, string> {
  const record = gatewayRecord(value, 'participants');
  requireGateway(Object.keys(record).length > 0, 'Empty participants');
  for (const [kid, pk] of Object.entries(record)) {
    const bytes = gatewayBytes(pk, 'participant public key', 32);
    requireGateway(base64UrlEncode(keyIDFromPublicKey(bytes)) === kid, 'Participant key ID mismatch');
  }
  return record as Record<string, string>;
}
export function validateGatewayContext(context: GatewayContext): void {
  hex(context.conversationId, 'conversation ID', 32);
  gatewayInteger(context.epoch, 'epoch');
  const pk = gatewayBytes(context.gateway?.publicKey, 'gateway public key', 32);
  requireGateway(base64UrlEncode(keyIDFromPublicKey(pk)) === context.gateway.kid, 'Gateway key ID mismatch');
  const participants = gatewayParticipants(context.participants);
  requireGateway(!Object.hasOwn(participants, context.gateway.kid), 'Gateway cannot be a participant');
  gatewayInteger(context.floor, 'floor', 1);
  gatewayRules(context.rules);
}
function members(value: unknown): void {
  requireGateway(Array.isArray(value) && value.length > 0, 'Invalid proposed members');
  const seen = new Set<string>();
  for (const item of value) {
    const member = gatewayRecord(item, 'member');
    const pk = gatewayBytes(member.public_key, 'member public key', 32);
    const kid = base64UrlEncode(keyIDFromPublicKey(pk));
    requireGateway(member.kid === kid && !seen.has(kid), 'Invalid or duplicate member key ID');
    seen.add(kid);
  }
}
function signed(body: Record<string, unknown>, id: string): void {
  hex(body.conv_id, 'conversation ID', 32);
  gatewayText(body[id], id, 256);
  gatewayBytes(body.signer_kid, 'signer kid', 16);
}
function proposalFields(body: Record<string, unknown>, applied = false): void {
  requireGateway(['floor_change', 'rules_change', 'member_add', 'member_remove'].includes(String(body.proposal_type)), 'Invalid proposal type');
  const fields = applied
    ? ['applied_floor', 'applied_rules', 'applied_members', 'removed_member_kids']
    : ['proposed_floor', 'proposed_rules', 'proposed_members', 'removed_member_kids'];
  const selected = ['floor_change', 'rules_change', 'member_add', 'member_remove'].indexOf(String(body.proposal_type));
  for (let index = 0; index < fields.length; index++) {
    const value = body[fields[index]];
    if (index !== selected) { requireGateway(value === undefined || value === null, 'Unexpected proposal branch'); continue; }
    if (index === 0) gatewayInteger(value, fields[index], 1);
    if (index === 1) gatewayRules(value);
    if (index === 2) members(value);
    if (index === 3) gatewayRoster(value);
  }
}

/** Decode and validate shape without granting authority. Use verifyGatewayMessage
 * with an authenticated envelope and trusted context before acting on a body.
 * Unknown fields are preserved, including nullable Python governance branches. */
export function parseGatewayBody(bodyType: string, data: string | Uint8Array): GatewayBody {
  let value: unknown;
  try { value = JSON.parse(typeof data === 'string' ? data : new TextDecoder('utf-8', { fatal: true }).decode(data)); }
  catch { throw new GatewayValidationError('Invalid gateway JSON'); }
  const body = gatewayRecord(value, 'gateway body');
  requireGateway(body.type === bodyType, 'Gateway body type mismatch');
  if (body.gateway_kid !== undefined) gatewayBytes(body.gateway_kid, 'gateway kid', 16);
  switch (bodyType as GatewayBodyType) {
    case 'gate.request': {
      signed(body, 'request_id');
      gatewayBytes(body.signature, 'signature', 64);
      gatewayRoster(body.eligible_signer_kids);
      const count = gatewayInteger(body.required_approvals, 'required approvals', 1);
      requireGateway(count <= (body.eligible_signer_kids as string[]).length, 'Threshold exceeds signer count');
      gatewayTime(body.expires_at);
      const verb = gatewayText(body.verb, 'verb');
      requireGateway(/^[A-Z]+$/.test(verb), 'Invalid verb');
      gatewayText(body.target_endpoint, 'endpoint');
      gatewayText(body.target_service, 'service');
      const target = gatewayText(body.target_url, 'target URL', 16384);
      let url: URL;
      try { url = new URL(target); } catch { throw new GatewayValidationError('Invalid target URL'); }
      requireGateway(['https:', 'http:'].includes(url.protocol) && !url.username && !url.password && !url.hash, 'Invalid target URL');
      if (body.recipe_name !== undefined) gatewayText(body.recipe_name, 'recipe name');
      if (body.arguments !== undefined) {
        for (const arg of Object.values(gatewayRecord(body.arguments, 'arguments'))) requireGateway(typeof arg === 'string', 'Invalid argument');
      }
      break;
    }
    case 'gate.approval': case 'gate.disapproval':
      signed(body, 'request_id');
      if (bodyType === 'gate.approval') gatewayBytes(body.signature, 'signature', 64);
      break;
    case 'gov.approve': case 'gov.disapprove':
      signed(body, 'proposal_id');
      if (bodyType === 'gov.approve') gatewayBytes(body.signature, 'signature', 64);
      break;
    case 'gov.propose':
      signed(body, 'proposal_id');
      gatewayBytes(body.signature, 'signature', 64);
      gatewayRoster(body.eligible_signer_kids);
      requireGateway(gatewayInteger(body.required_approvals, 'required approvals', 1) <= (body.eligible_signer_kids as string[]).length, 'Threshold exceeds signer count');
      gatewayTime(body.expires_at);
      proposalFields(body);
      break;
    case 'gate.secret':
      for (const key of ['secret_id', 'service', 'header_name', 'header_template']) gatewayText(body[key], key);
      gatewayBytes(body.sender_kid, 'sender kid', 16);
      requireGateway(gatewayBytes(body.encrypted_blob, 'encrypted blob').length >= 40, 'Invalid sealed credential');
      requireGateway(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(String(body.header_name)), 'Invalid header name');
      requireGateway(!/[\r\n]/.test(String(body.header_template)) && String(body.header_template).includes('{value}'), 'Invalid header template');
      if (body.ttl !== undefined) gatewayInteger(body.ttl, 'credential TTL');
      break;
    case 'gate.executed':
      gatewayText(body.request_id, 'request ID', 256);
      gatewayTime(body.executed_at, 'executed_at');
      gatewayInteger(body.execution_status_code, 'execution status');
      break;
    case 'gate.result':
      gatewayText(body.request_id, 'request ID', 256);
      gatewayInteger(body.status_code, 'status code');
      for (const key of ['body', 'content_type']) if (body[key] !== undefined) requireGateway(typeof body[key] === 'string', `Invalid ${key}`);
      break;
    case 'gate.expired':
      for (const key of ['secret_id', 'service', 'message']) gatewayText(body[key], key);
      gatewayTime(body.expired_at, 'expired_at');
      break;
    case 'gate.invalidated': case 'gov.invalidated':
      gatewayText(body[bodyType === 'gate.invalidated' ? 'request_id' : 'proposal_id'], 'invalidated ID', 256);
      gatewayTime(body.invalidated_at, 'invalidated_at');
      gatewayText(body.message, 'invalidation message');
      break;
    case 'gov.applied':
      gatewayText(body.proposal_id, 'proposal ID', 256);
      gatewayTime(body.applied_at, 'applied_at');
      proposalFields(body, true);
      break;
    case 'gate.promote': case 'gate.accept': {
      hex(body.conv_id, 'conversation ID', 32);
      hex(body.invitation_id, 'invitation ID', 32);
      gatewayInteger(body.conv_epoch, 'epoch');
      const pk = gatewayBytes(body.gateway_public_key, 'gateway public key', 32);
      requireGateway(base64UrlEncode(keyIDFromPublicKey(pk)) === body.gateway_kid, 'Gateway key ID mismatch');
      if (bodyType === 'gate.promote') {
        gatewayInteger(body.expires_at, 'invitation expiry', 1);
        hex(body.keys_hash, 'keys hash', 64);
        const participants = gatewayParticipants(body.participants);
        requireGateway(!Object.hasOwn(participants, String(body.gateway_kid)), 'Gateway cannot be a participant');
        requireGateway(gatewayInteger(body.floor, 'floor', 1) <= Object.keys(participants).length, 'Floor exceeds signer count');
        gatewayRules(body.rules);
      } else {
        hex(body.invitation_msg_id, 'invitation message ID', 32);
        hex(body.invitation_hash, 'invitation hash', 64);
      }
      break;
    }
    default: throw new GatewayValidationError(`Unsupported gateway body type: ${bodyType}`);
  }
  return body as unknown as GatewayBody;
}
