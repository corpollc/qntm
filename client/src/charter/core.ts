/** Experimental Charter Registry v0.2: offline creation, signatures and authority replay. */
import { validateCharterPublicKey, verifyCharterSignature } from './crypto.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlDecode, base64UrlEncode, keyIDFromPublicKey } from '../identity/index.js';
import type { Identity } from '../types.js';
import { charterJsonBytes, parseCharterJson, canonicalizeCharterJson } from './json.js';
import type { CharterJson } from './json.js';
export { charterJsonBytes, parseCharterJson, canonicalizeCharterJson } from './json.js';
export type { CharterJson } from './json.js';

export const CHARTER_DRAFT_VERSION = '0.2' as const;
export const CHARTER_GENESIS_HASH = '0'.repeat(64);
export type CharterStatementType = 'charter' | 'constitution.amend' | 'governance.rotate' | 'opkey.delegate' | 'opkey.revoke' | 'agent.decommission' | 'agent.successor' | 'liveness.update' | 'statement';
export type CharterAgentRight = 'liveness.update' | 'statement';
export type CharterKey = { kid: string; pubkey: string };
export type CharterGovernance = { keys: CharterKey[]; threshold: number };
export interface CharterBody {
  agent_pubkey: string;
  governance: CharterGovernance | null;
  agent_rights: CharterAgentRight[];
  next_governance_commitment?: string;
  extensions?: Record<string, CharterJson>;
}
export interface CharterSignedBody {
  registry: string;
  agent_id: string;
  seq: number;
  prev_hash: string;
  type: CharterStatementType;
  issued_at: string;
  body: CharterJson;
}
export interface CharterStatement {
  signed: CharterSignedBody;
  signatures: Array<{ kid: string; sig: string }>;
}
export interface CharterRecord {
  registry: string;
  agentId: string;
  agentPublicKey: string;
  sequence: number;
  headHash: string;
  charter: CharterBody;
  governance: CharterGovernance | null;
  agentRights: CharterAgentRight[];
  nextGovernanceCommitment?: string;
  constitution?: CharterJson;
  liveness?: CharterJson;
  operationalKeys: Record<string, { scope: string; expires_at?: string }>;
  successor?: string;
  decommissioned: boolean;
  /** Application-defined statements stay ordered; the library imposes no merge semantics. */
  statements: Array<{ seq: number; namespace: string; data: CharterJson; schema?: string }>;
}
const suite = new QSP1Suite();
const hex = (bytes: Uint8Array): string => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const own = (obj: object, key: string): boolean => Object.prototype.hasOwnProperty.call(obj, key);
const clone = <T>(value: T): T => JSON.parse(canonicalizeCharterJson(value)) as T;
function requireCondition(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
function object(value: unknown, label: string): Record<string, unknown> {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  return value as Record<string, unknown>;
}
function text(value: unknown, label: string): asserts value is string { requireCondition(typeof value === 'string' && value.length > 0, `${label} must be a non-empty string`); }
function hash(value: unknown): asserts value is string { requireCondition(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'Invalid SHA-256 hash'); }
function kid(value: unknown): asserts value is string { requireCondition(typeof value === 'string' && /^[0-9a-f]{32}$/.test(value), 'Invalid key/agent ID'); }
function wire(value: unknown, length: number): Uint8Array {
  requireCondition(typeof value === 'string', 'Expected base64url string');
  const bytes = base64UrlDecode(value);
  requireCondition(bytes.length === length && base64UrlEncode(bytes) === value, 'Invalid canonical base64url encoding');
  return bytes;
}
function timestamp(value: unknown): asserts value is string {
  requireCondition(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value)), 'Expected RFC 3339 UTC timestamp');
  // Date.parse normalizes impossible dates such as February 30; reject those too.
  requireCondition(new Date(value).toISOString().slice(0, 19) === value.slice(0, 19), 'Invalid timestamp');
}
function governance(value: unknown): asserts value is CharterGovernance {
  const set = object(value, 'Governance');
  requireCondition(Array.isArray(set.keys) && set.keys.length > 0, 'Governance keys cannot be empty');
  requireCondition(Number.isSafeInteger(set.threshold) && Number(set.threshold) >= 1 && Number(set.threshold) <= set.keys.length, 'Invalid governance threshold');
  const seen = new Set<string>();
  for (const raw of set.keys) {
    const key = object(raw, 'Governance key'); kid(key.kid);
    validateCharterPublicKey(wire(key.pubkey, 32));
    requireCondition(charterAgentId(wire(key.pubkey, 32)) === key.kid, 'Governance key ID does not match public key');
    requireCondition(!seen.has(key.kid), 'Duplicate governance key'); seen.add(key.kid);
    requireCondition(Object.keys(key).every(k => ['kid', 'pubkey'].includes(k)), 'Unknown governance-key field');
  }
  requireCondition(Object.keys(set).every(k => ['keys', 'threshold'].includes(k)), 'Unknown governance field');
}
function charterBody(value: unknown, agentId: string): CharterBody {
  const body = object(value, 'Charter body');
  validateCharterPublicKey(wire(body.agent_pubkey, 32));
  requireCondition(charterAgentId(wire(body.agent_pubkey, 32)) === agentId, 'Agent public key does not match agent ID');
  if (body.governance !== null) governance(body.governance);
  requireCondition(Array.isArray(body.agent_rights) && body.agent_rights.every(r => r === 'liveness.update' || r === 'statement'), 'Agent rights may grant only informational statement types');
  requireCondition(new Set(body.agent_rights).size === body.agent_rights.length, 'Duplicate agent right');
  if (own(body, 'next_governance_commitment')) hash(body.next_governance_commitment);
  if (own(body, 'extensions')) {
    const extensions = object(body.extensions, 'Charter extensions');
    for (const namespace of Object.keys(extensions)) text(namespace, 'Extension namespace');
  }
  return clone(body) as unknown as CharterBody;
}

export function charterAgentId(publicKey: Uint8Array): string {
  requireCondition(publicKey.length === 32, 'Expected 32-byte Ed25519 public key');
  return hex(keyIDFromPublicKey(publicKey));
}
export function charterKey(publicKey: Uint8Array): CharterKey { return { kid: charterAgentId(publicKey), pubkey: base64UrlEncode(publicKey) }; }
export function charterGovernanceCommitment(set: CharterGovernance): string {
  governance(set);
  return hex(suite.hash(charterJsonBytes({ keys: [...set.keys].sort((a, b) => a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0), threshold: set.threshold })));
}
export function charterStatementHash(statement: CharterStatement | CharterSignedBody): string {
  return hex(suite.hash(charterJsonBytes('signed' in statement ? statement.signed : statement)));
}

/** Adds/replaces this key's signature, without mutating the caller's document. */
export function signCharterStatement(statement: CharterStatement, identity: Identity): CharterStatement {
  const result = clone(statement);
  const signer = charterAgentId(identity.publicKey);
  const signature = suite.sign(identity.privateKey, charterJsonBytes(result.signed));
  requireCondition(verifyCharterSignature(identity.publicKey, charterJsonBytes(result.signed), signature), 'Identity private/public keys do not match');
  result.signatures = [...result.signatures.filter(s => s.kid !== signer), { kid: signer, sig: base64UrlEncode(signature) }];
  return result;
}

export function createCharter(options: {
  registry: string; agent: Identity; governance: CharterGovernance | null;
  agentRights?: CharterAgentRight[]; extensions?: Record<string, CharterJson>;
  nextGovernanceCommitment?: string; issuedAt?: string;
}): CharterStatement {
  const body: CharterBody = { agent_pubkey: base64UrlEncode(options.agent.publicKey), governance: options.governance, agent_rights: options.agentRights ?? [],
    ...(options.extensions !== undefined ? { extensions: options.extensions } : {}),
    ...(options.nextGovernanceCommitment !== undefined ? { next_governance_commitment: options.nextGovernanceCommitment } : {}) };
  const statement: CharterStatement = { signed: { registry: options.registry, agent_id: charterAgentId(options.agent.publicKey), seq: 0, prev_hash: CHARTER_GENESIS_HASH,
    type: 'charter', issued_at: options.issuedAt ?? new Date().toISOString(), body: body as unknown as CharterJson }, signatures: [] };
  validateShape(statement);
  charterBody(body, statement.signed.agent_id);
  return signCharterStatement(statement, options.agent);
}

/** Create an unsigned next statement. Replay the full chain before trusting a received head. */
export function createCharterStatement(previous: CharterStatement, type: Exclude<CharterStatementType, 'charter'>, body: CharterJson, issuedAt = new Date().toISOString()): CharterStatement {
  validateShape(previous);
  const next: CharterStatement = { signed: { registry: previous.signed.registry, agent_id: previous.signed.agent_id, seq: previous.signed.seq + 1,
    prev_hash: charterStatementHash(previous), type, issued_at: issuedAt, body: clone(body) }, signatures: [] };
  validateShape(next);
  return next;
}

function validateShape(statement: unknown): asserts statement is CharterStatement {
  // Validate JSON first, including unsupported JS values, Unicode, and data accessors.
  charterJsonBytes(statement);
  const envelope = object(statement, 'Statement');
  requireCondition(Object.keys(envelope).every(k => ['signed', 'signatures'].includes(k)), 'Unknown envelope field');
  const signed = object(envelope.signed, 'Signed body');
  requireCondition(Object.keys(signed).every(k => ['registry', 'agent_id', 'seq', 'prev_hash', 'type', 'issued_at', 'body'].includes(k)), 'Unknown signed-body field');
  text(signed.registry, 'Registry'); kid(signed.agent_id); hash(signed.prev_hash); timestamp(signed.issued_at);
  requireCondition(Number.isSafeInteger(signed.seq) && Number(signed.seq) >= 0, 'Invalid sequence number');
  requireCondition(['charter', 'constitution.amend', 'governance.rotate', 'opkey.delegate', 'opkey.revoke', 'agent.decommission', 'agent.successor', 'liveness.update', 'statement'].includes(String(signed.type)), 'Unknown core statement type');
  requireCondition(own(signed, 'body') && Array.isArray(envelope.signatures), 'Missing body or signatures');
  const seen = new Set<string>();
  for (const raw of envelope.signatures) {
    const signature = object(raw, 'Signature'); kid(signature.kid); wire(signature.sig, 64);
    requireCondition(Object.keys(signature).every(k => ['kid', 'sig'].includes(k)), 'Unknown signature field');
    requireCondition(!seen.has(signature.kid), 'Duplicate signature key'); seen.add(signature.kid);
  }
}

export function parseCharterStatement(json: string): CharterStatement {
  const statement = parseCharterJson(json); validateShape(statement); return clone(statement);
}

/** Validate the entire ordered chain for the explicitly expected registry and agent. No network access. */
export function replayCharterChain(chain: readonly CharterStatement[], expected: { registry: string; agentId: string }): CharterRecord {
  text(expected.registry, 'Expected registry'); kid(expected.agentId);
  requireCondition(chain.length > 0, 'Charter chain is empty');
  let state: CharterRecord | undefined;
  for (const input of chain) {
    validateShape(input);
    const statement = clone(input);
    const s = statement.signed;
    requireCondition(s.registry === expected.registry && s.agent_id === expected.agentId, 'Registry or agent audience mismatch');
    requireCondition(s.seq === (state ? state.sequence + 1 : 0), 'Sequence gap, duplicate, or out-of-order statement');
    requireCondition(s.prev_hash === (state ? state.headHash : CHARTER_GENESIS_HASH), 'Previous statement hash mismatch');
    requireCondition(!state?.decommissioned, 'Decommissioned records are terminal');
    let genesis: CharterBody | undefined;
    if (!state) {
      requireCondition(s.type === 'charter', 'First statement must be a charter');
      genesis = charterBody(s.body, s.agent_id);
    } else {
      requireCondition(s.type !== 'charter', 'Charter cannot be replaced');
      requireCondition(state.governance !== null, 'Record is frozen at birth');
    }
    const currentGovernance = genesis ? genesis.governance : state!.governance;
    const agentPublicKey = genesis ? genesis.agent_pubkey : state!.agentPublicKey;
    const authorizedKeys = new Map((currentGovernance?.keys ?? []).map(k => [k.kid, k.pubkey]));
    authorizedKeys.set(s.agent_id, agentPublicKey);
    const validSigners = new Set<string>();
    for (const signature of statement.signatures) {
      const publicKey = authorizedKeys.get(signature.kid);
      requireCondition(publicKey, 'Signature is from a key outside the current authority');
      requireCondition(verifyCharterSignature(wire(publicKey, 32), charterJsonBytes(s), wire(signature.sig, 64)), 'Invalid statement signature');
      validSigners.add(signature.kid);
    }
    const governanceSigned = currentGovernance !== null && currentGovernance.keys.filter(k => validSigners.has(k.kid)).length >= currentGovernance.threshold;
    if (genesis) {
      requireCondition(validSigners.has(s.agent_id), 'Charter requires the agent signature');
      requireCondition(genesis.governance === null || governanceSigned, 'Charter requires governance acceptance');
      state = { registry: s.registry, agentId: s.agent_id, agentPublicKey, sequence: s.seq, headHash: charterStatementHash(statement), charter: genesis,
        governance: clone(genesis.governance), agentRights: [...genesis.agent_rights], operationalKeys: {}, statements: [], decommissioned: false,
        ...(genesis.next_governance_commitment ? { nextGovernanceCommitment: genesis.next_governance_commitment } : {}) };
      continue;
    }
    const agentAllowed = state!.agentRights.includes(s.type as CharterAgentRight) && validSigners.has(s.agent_id);
    requireCondition(governanceSigned || agentAllowed, 'Statement lacks current governing authority');
    switch (s.type) {
      case 'constitution.amend': state!.constitution = s.body; break;
      case 'liveness.update': state!.liveness = s.body; break;
      case 'statement': {
        const b = object(s.body, 'Namespaced statement'); text(b.namespace, 'Namespace'); requireCondition(own(b, 'data'), 'Namespaced statement requires data');
        if (own(b, 'schema')) text(b.schema, 'Schema identifier');
        state!.statements.push({ seq: s.seq, namespace: b.namespace, data: b.data as CharterJson, ...(typeof b.schema === 'string' ? { schema: b.schema } : {}) });
        break;
      }
      case 'governance.rotate': {
        const b = object(s.body, 'Governance rotation'); governance(b.governance);
        if (state!.nextGovernanceCommitment) requireCondition(charterGovernanceCommitment(b.governance) === state!.nextGovernanceCommitment, 'Rotation violates governance commitment');
        if (own(b, 'next_governance_commitment')) hash(b.next_governance_commitment);
        state!.governance = clone(b.governance);
        state!.nextGovernanceCommitment = b.next_governance_commitment as string | undefined;
        break;
      }
      case 'opkey.delegate': {
        const b = object(s.body, 'Operational delegation'); kid(b.kid); text(b.scope, 'Scope');
        if (own(b, 'expires_at')) timestamp(b.expires_at);
        state!.operationalKeys[b.kid] = { scope: b.scope, ...(typeof b.expires_at === 'string' ? { expires_at: b.expires_at } : {}) }; break;
      }
      case 'opkey.revoke': {
        const b = object(s.body, 'Operational revocation'); kid(b.kid);
        requireCondition(own(state!.operationalKeys, b.kid), 'Operational key is not delegated'); delete state!.operationalKeys[b.kid]; break;
      }
      case 'agent.successor': {
        const b = object(s.body, 'Successor'); kid(b.agent_id); requireCondition(b.agent_id !== s.agent_id, 'Successor must be a different agent'); state!.successor = b.agent_id; break;
      }
      case 'agent.decommission': state!.decommissioned = true; break;
    }
    state!.sequence = s.seq; state!.headHash = charterStatementHash(statement);
  }
  return state!;
}
