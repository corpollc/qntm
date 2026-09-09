import { verifyCharterSignature } from './crypto.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlDecode, base64UrlEncode } from '../identity/index.js';
import { charterAgentId, charterStatementHash, replayCharterChain } from './core.js';
import type { CharterKey, CharterStatement, CharterRecord } from './core.js';
import { charterJsonBytes, canonicalizeCharterJson } from './json.js';

export type CharterLogHead = { kind: 'charter.log'; registry: string; tree_size: number; root_hash: string; timestamp: string };
export type CharterEpochHead = { kind: 'charter.epoch'; registry: string; epoch: number; map_size: number; map_root: string; log_size: number; log_root: string; timestamp: string };
export type CharterSignedHead<T> = { signed: T; kid: string; sig: string };
export type CharterHeads = { log: CharterSignedHead<CharterLogHead>; epoch: CharterSignedHead<CharterEpochHead> };
export type CharterLogEntry = { statement: CharterStatement; received_at: string };
export type CharterMapLeaf = { agent_id: string; seq: number; statement_hash: string };
export type CharterMapWitness = { leaf: CharterMapLeaf; index: number; siblings: string[] };
export type CharterRangeProof = { agent_id: string; present: boolean; left: CharterMapWitness | null; right: CharterMapWitness | null };
export type CharterChainResponse = { chain: CharterStatement[]; proof: CharterRangeProof; heads: CharterHeads };
export type CharterInclusion = { entry: CharterLogEntry; index: number; siblings: string[] };
export type CharterReceipt = { index: number; statement_hash: string; inclusion: CharterInclusion; heads: CharterHeads };
export type CharterTrust = { registry: string; registrar: CharterKey };

const suite = new QSP1Suite();
const hex = (bytes: Uint8Array): string => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
function check(value: unknown, message: string): asserts value { if (!value) throw new Error(message); }
function hashBytes(value: string): Uint8Array { check(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'Invalid Merkle hash'); return Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16)); }
function size(value: number): void { check(Number.isSafeInteger(value) && value >= 0, 'Invalid tree size/index'); }
function id(value: string): void { check(typeof value === 'string' && /^[0-9a-f]{32}$/.test(value), 'Invalid map agent ID'); }
function split(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k; }
function leaf(value: unknown): string { return hex(suite.hash(Uint8Array.from([0, ...charterJsonBytes(value)]))); }
function node(left: string, right: string): string { return hex(suite.hash(Uint8Array.from([1, ...hashBytes(left), ...hashBytes(right)]))); }
const empty = hex(suite.hash(new Uint8Array()));
function timestamp(value: string): void {
  check(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0,19) === value.slice(0,19), 'Invalid head timestamp');
}

/** Verify registrar signatures against an independently pinned key and registry ID. */
export function verifyCharterHeads(heads: CharterHeads, trust: CharterTrust): void {
  charterJsonBytes(heads);
  const pk = base64UrlDecode(trust.registrar.pubkey);
  check(base64UrlEncode(pk) === trust.registrar.pubkey && charterAgentId(pk) === trust.registrar.kid && trust.registry.length > 0, 'Invalid registrar pin');
  for (const head of [heads.log, heads.epoch]) {
    check(head.signed.registry === trust.registry && head.kid === trust.registrar.kid, 'Head audience or signing key mismatch');
    const sig = base64UrlDecode(head.sig);
    check(sig.length === 64 && base64UrlEncode(sig) === head.sig && verifyCharterSignature(pk, charterJsonBytes(head.signed), sig), 'Invalid registrar head signature');
    timestamp(head.signed.timestamp);
  }
  const log = heads.log.signed, epoch = heads.epoch.signed;
  check(log.kind === 'charter.log' && epoch.kind === 'charter.epoch', 'Head domain mismatch');
  size(log.tree_size); size(epoch.map_size); size(epoch.log_size); size(epoch.epoch);
  hashBytes(log.root_hash); hashBytes(epoch.map_root); hashBytes(epoch.log_root);
  check(epoch.epoch === epoch.map_size && epoch.map_size === epoch.log_size && epoch.log_size === log.tree_size && epoch.log_root === log.root_hash && epoch.timestamp === log.timestamp, 'Epoch/log binding mismatch');
  if (log.tree_size === 0) check(log.root_hash === empty && epoch.map_root === empty, 'Invalid empty tree roots');
}

function inclusionRoot(hash: string, index: number, count: number, siblings: string[]): string {
  size(index); size(count); check(count > 0 && index < count && Array.isArray(siblings) && siblings.length <= 53, 'Invalid inclusion index/path');
  let used = 0;
  const visit = (i: number, n: number): string => {
    if (n === 1) return hash;
    const k = split(n);
    const child = i < k ? visit(i, k) : visit(i-k, n-k);
    check(used < siblings.length, 'Truncated inclusion path');
    const sibling = siblings[used++]; hashBytes(sibling);
    return i < k ? node(child, sibling) : node(sibling, child);
  };
  const root = visit(index, count); check(used === siblings.length, 'Extra inclusion path elements'); return root;
}

/** The caller must first authenticate the supplied head with verifyCharterHeads. */
export function verifyCharterInclusion(proof: CharterInclusion, head: CharterLogHead): void {
  timestamp(proof.entry.received_at);
  check(inclusionRoot(leaf(proof.entry), proof.index, head.tree_size, proof.siblings) === head.root_hash, 'Log inclusion proof mismatch');
}

/** Verify append-only growth between two already-authenticated log heads. */
export function verifyCharterConsistency(older: CharterLogHead, newer: CharterLogHead, proof: string[]): void {
  size(older.tree_size); size(newer.tree_size); hashBytes(older.root_hash); hashBytes(newer.root_hash);
  check(older.registry === newer.registry && older.kind === 'charter.log' && newer.kind === 'charter.log' && older.tree_size <= newer.tree_size, 'Invalid consistency head range');
  check(Array.isArray(proof) && proof.length <= 54, 'Invalid consistency path');
  if (older.tree_size === 0) { check(older.root_hash === empty && proof.length === 0 && (newer.tree_size !== 0 || newer.root_hash === empty), 'Invalid empty consistency proof'); return; }
  let used = 0;
  const take = (): string => { check(used < proof.length, 'Truncated consistency proof'); const h = proof[used++]; hashBytes(h); return h; };
  const visit = (m: number, n: number, complete: boolean): [string, string] => {
    if (m === n) { const h = complete ? older.root_hash : take(); return [h,h]; }
    const k = split(n);
    if (m <= k) { const [a,b] = visit(m,k,complete); return [a,node(b,take())]; }
    const [a,b] = visit(m-k,n-k,false); const left = take(); return [node(left,a),node(left,b)];
  };
  const [a,b] = visit(older.tree_size,newer.tree_size,true);
  check(used === proof.length && a === older.root_hash && b === newer.root_hash, 'Log consistency proof mismatch');
}

function mapWitness(witness: CharterMapWitness, head: CharterEpochHead): void {
  id(witness.leaf.agent_id); size(witness.leaf.seq); hashBytes(witness.leaf.statement_hash);
  check(inclusionRoot(leaf(witness.leaf),witness.index,head.map_size,witness.siblings) === head.map_root, 'Map inclusion proof mismatch');
}

/** Authenticate the response, prove the upper boundary, then replay every signature and authority change. */
export function verifyCharterChainResponse(response: CharterChainResponse, trust: CharterTrust, agentId: string): CharterRecord | null {
  id(agentId); verifyCharterHeads(response.heads,trust);
  const p = response.proof, head = response.heads.epoch.signed;
  check(p.agent_id === agentId && typeof p.present === 'boolean' && Array.isArray(response.chain), 'Range proof audience/shape mismatch');
  if (p.left !== null) mapWitness(p.left,head);
  if (p.right !== null) mapWitness(p.right,head);
  if (p.left === null && p.right === null) check(head.map_size === 0 && head.map_root === empty, 'Missing range witnesses');
  else if (p.left === null) check(p.right!.index === 0, 'Invalid lower tree boundary');
  else if (p.right === null) check(p.left.index === head.map_size-1, 'Invalid upper tree boundary');
  else check(p.left.index+1 === p.right.index, 'Range witnesses are not adjacent');
  if (p.right !== null) check(p.right.leaf.agent_id > agentId, 'Successor does not bound agent range');
  if (!p.present) {
    check(response.chain.length === 0 && (p.left === null || p.left.leaf.agent_id < agentId), 'Invalid non-membership proof'); return null;
  }
  check(p.left !== null && p.left.leaf.agent_id === agentId && response.chain.length === p.left.leaf.seq+1, 'Incomplete charter chain');
  const state = replayCharterChain(response.chain,{registry:trust.registry,agentId});
  check(state.headHash === p.left.leaf.statement_hash, 'Chain head does not match map');
  return state;
}

export function verifyCharterReceipt(receipt: CharterReceipt, statement: CharterStatement, trust: CharterTrust): void {
  verifyCharterHeads(receipt.heads,trust);
  check(statement.signed.registry === trust.registry && receipt.statement_hash === charterStatementHash(statement) && receipt.index === receipt.inclusion.index && canonicalizeCharterJson(receipt.inclusion.entry.statement) === canonicalizeCharterJson(statement), 'Receipt is for a different statement');
  verifyCharterInclusion(receipt.inclusion,receipt.heads.log.signed);
}

/** Full snapshot audit: authenticate every chain and recompute both trees from the global log. */
export function auditCharterSnapshot(entries: readonly CharterLogEntry[], heads: CharterHeads, trust: CharterTrust): void {
  verifyCharterHeads(heads,trust); check(entries.length === heads.log.signed.tree_size, 'Snapshot log length mismatch');
  const chains = new Map<string,CharterStatement[]>();
  const map: CharterMapLeaf[] = [];
  const hashes = entries.map(e => {
    timestamp(e.received_at);
    const s = e.statement; const chain = chains.get(s.signed.agent_id) ?? []; chain.push(s); chains.set(s.signed.agent_id,chain);
    map.push({agent_id:s.signed.agent_id,seq:s.signed.seq,statement_hash:charterStatementHash(s)}); return leaf(e);
  });
  for (const [agentId,chain] of chains) replayCharterChain(chain,{registry:trust.registry,agentId});
  map.sort((a,b) => a.agent_id === b.agent_id ? a.seq-b.seq : a.agent_id < b.agent_id ? -1 : 1);
  const root = (values: string[]): string => { if (!values.length) return empty; if (values.length === 1) return values[0]; const k=split(values.length);return node(root(values.slice(0,k)),root(values.slice(k))); };
  check(root(hashes) === heads.log.signed.root_hash && root(map.map(leaf)) === heads.epoch.signed.map_root, 'Snapshot log/map mismatch');
}
