import { canonicalizeCharterJson, parseCharterJson } from './json.js';
import type { CharterStatement, CharterRecord } from './core.js';
import { verifyCharterHeads, verifyCharterChainResponse, verifyCharterReceipt, verifyCharterConsistency } from './proofs.js';
import type { CharterHeads, CharterTrust, CharterChainResponse, CharterReceipt, CharterLogEntry } from './proofs.js';

export class CharterRegistryError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) { super(message); this.name='CharterRegistryError'; }
}

/** Transport for the reference Go registrar. Pins are caller-supplied, never silently learned from /info. */
export class CharterRegistryClient {
  private readonly base: string;
  private readonly trust: CharterTrust;
  constructor(baseUrl: string, trust: CharterTrust) {
    const url = new URL(baseUrl);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) throw new Error('Registry requires HTTPS (HTTP is allowed on loopback for development)');
    if (url.username || url.password || url.search || url.hash) throw new Error('Invalid registry base URL');
    this.base=url.href.replace(/\/$/,''); this.trust=JSON.parse(canonicalizeCharterJson(trust)) as CharterTrust;
  }
  private async request<T>(path: string, method='GET', body?: unknown): Promise<T> {
    const response=await fetch(this.base+path,{method,headers:body===undefined ? {} : {'Content-Type':'application/json'},...(body===undefined?{}:{body:canonicalizeCharterJson(body)}),redirect:'error',signal:AbortSignal.timeout(30_000)});
    const raw=await response.text();
    const value=parseCharterJson(raw);
    if (!response.ok) {
      const e=value as {error?:string;message?:string};throw new CharterRegistryError(response.status,e?.error??'http_error',e?.message??`Registry HTTP ${response.status}`);
    }
    return value as T;
  }
  async heads(size?: number): Promise<CharterHeads> {
    const result=await this.request<CharterHeads>('/v1/heads'+querySize(size));verifyCharterHeads(result,this.trust);
    if (size!==undefined && result.log.signed.tree_size!==size) throw new Error('Wrong snapshot size');return result;
  }
  async submit(statement: CharterStatement): Promise<CharterReceipt> {
    const result=await this.request<CharterReceipt>('/v1/statements','POST',statement);verifyCharterReceipt(result,statement,this.trust);return result;
  }
  async chain(agentId: string,size?: number): Promise<{record:CharterRecord|null; evidence:CharterChainResponse}> {
    if (!/^[0-9a-f]{32}$/.test(agentId)) throw new Error('Invalid agent ID');
    const evidence=await this.request<CharterChainResponse>(`/v1/chain/${agentId}`+querySize(size));
    const record=verifyCharterChainResponse(evidence,this.trust,agentId);
    if (size!==undefined && evidence.heads.log.signed.tree_size!==size) throw new Error('Wrong snapshot size');return {record,evidence};
  }
  async consistency(older: CharterHeads,newer: CharterHeads): Promise<string[]> {
    verifyCharterHeads(older,this.trust);verifyCharterHeads(newer,this.trust);
    const result=await this.request<{from:CharterHeads;to:CharterHeads;proof:string[]}>(`/v1/consistency?from=${older.log.signed.tree_size}&to=${newer.log.signed.tree_size}`);
    verifyCharterConsistency(older.log.signed,newer.log.signed,result.proof);return result.proof;
  }
  /** Fetch a pinned-size snapshot for auditCharterSnapshot; the full audit authenticates the entries. */
  async log(heads: CharterHeads): Promise<CharterLogEntry[]> {
    verifyCharterHeads(heads,this.trust);const result:CharterLogEntry[]=[];const size=heads.log.signed.tree_size;
    while (result.length<size) {
      const page=await this.request<{entries:CharterLogEntry[];from:number;next:number;heads:CharterHeads}>(`/v1/log?size=${size}&from=${result.length}&limit=1000`);
      if (!Array.isArray(page.entries) || page.from!==result.length || page.next!==result.length+page.entries.length || page.next<=result.length || page.next>size) throw new Error('Invalid log pagination');
      result.push(...page.entries);
    }
    return result;
  }
}
function querySize(size?:number):string { if (size===undefined) return '';if (!Number.isSafeInteger(size)||size<0) throw new Error('Invalid snapshot size');return `?size=${size}`; }
