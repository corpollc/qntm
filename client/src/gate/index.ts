import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { base64UrlEncode, base64UrlDecode } from '../identity/index.js';
import type {
  GateConversationMessage, GateSignable, ApprovalSignable,
  ThresholdRule, Credential, Signer, Org, ScanResult, ExecuteResult,
  Recipe,
} from '../types.js';

// Gate message type constants (mirrors Go gate package constants)
export const GateMessagePromote = 'gate.promote' as const;
export const GateMessageConfig = 'gate.config' as const;
export const GateMessageSecret = 'gate.secret' as const;
export const GateMessageResult = 'gate.result' as const;

const suite = new QSP1Suite();

// Signing helpers

export function signRequest(
  privateKey: Uint8Array,
  signable: GateSignable,
): Uint8Array {
  const data = marshalCanonical(signable);
  return suite.sign(privateKey, data);
}

export function verifyRequest(
  publicKey: Uint8Array,
  signable: GateSignable,
  signature: Uint8Array,
): boolean {
  const data = marshalCanonical(signable);
  return suite.verify(publicKey, data, signature);
}

export function signApproval(
  privateKey: Uint8Array,
  approval: ApprovalSignable,
): Uint8Array {
  const data = marshalCanonical(approval);
  return suite.sign(privateKey, data);
}

export function verifyApproval(
  publicKey: Uint8Array,
  approval: ApprovalSignable,
  signature: Uint8Array,
): boolean {
  const data = marshalCanonical(approval);
  return suite.verify(publicKey, data, signature);
}

export function hashRequest(signable: GateSignable): Uint8Array {
  const data = marshalCanonical(signable);
  return suite.hash(data);
}

export function computePayloadHash(payload: unknown): Uint8Array {
  if (payload === undefined || payload === null) {
    return suite.hash(new Uint8Array(0));
  }
  const data = new TextEncoder().encode(JSON.stringify(payload));
  return suite.hash(data);
}

// HTTP client

export class GateClient {
  private baseURL: string;
  private adminToken?: string;

  constructor(baseURL: string, adminToken?: string) {
    this.baseURL = baseURL.replace(/\/$/, '');
    this.adminToken = adminToken;
  }

  private headers(withAuth = false): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (withAuth && this.adminToken) {
      h['Authorization'] = `Bearer ${this.adminToken}`;
    }
    return h;
  }

  async createOrg(org: { id: string; signers: Signer[]; rules: ThresholdRule[] }): Promise<Org> {
    const resp = await fetch(`${this.baseURL}/v1/orgs`, {
      method: 'POST',
      headers: this.headers(true),
      body: JSON.stringify(org),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
    return resp.json() as Promise<Org>;
  }

  async getOrg(orgID: string): Promise<Org> {
    const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}`, {
      headers: this.headers(true),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
    return resp.json() as Promise<Org>;
  }

  async addCredential(orgID: string, credential: Credential): Promise<void> {
    const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/credentials`, {
      method: 'POST',
      headers: this.headers(true),
      body: JSON.stringify(credential),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
  }

  async submitMessage(orgID: string, message: GateConversationMessage): Promise<void> {
    const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/messages`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(message),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
  }

  async scanRequest(orgID: string, requestID: string): Promise<ScanResult> {
    const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/scan/${requestID}`, {
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
    return resp.json() as Promise<ScanResult>;
  }

  async executeRequest(orgID: string, requestID: string): Promise<ExecuteResult> {
    const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/execute/${requestID}`, {
      method: 'POST',
      headers: this.headers(true),
    });
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
    return resp.json() as Promise<ExecuteResult>;
  }

  async health(): Promise<{ status: string }> {
    const resp = await fetch(`${this.baseURL}/health`);
    if (!resp.ok) {
      throw new GateError(resp.status, await resp.text());
    }
    return resp.json() as Promise<{ status: string }>;
  }
}

export class GateError extends Error {
  status: number;
  body: string;

  constructor(status: number, body: string) {
    super(`Gate API error ${status}: ${body}`);
    this.status = status;
    this.body = body;
  }
}

// Threshold matching (mirrors Go LookupThreshold)
export function lookupThreshold(
  rules: ThresholdRule[],
  service: string,
  endpoint: string,
  verb: string,
): ThresholdRule | undefined {
  // Priority: exact(service+endpoint+verb) > service+verb > service > default
  let bestMatch: ThresholdRule | undefined;
  let bestScore = -1;

  for (const rule of rules) {
    let score = 0;

    if (rule.service === service) {
      score = 1;
      if (rule.endpoint === endpoint) {
        score = 2;
        if (rule.verb === verb) {
          score = 3;
        }
      } else if (rule.endpoint === '' && rule.verb === verb) {
        score = 1.5; // service+verb but no endpoint
      }
    } else if (rule.service === '' || rule.service === '*') {
      score = 0.5; // default
    }

    if (score > bestScore) {
      bestScore = score;
      bestMatch = rule;
    }
  }

  return bestMatch;
}

// Placeholder regex matching {param}
const placeholderRe = /\{([^}]+)\}/g;

/**
 * resolveRecipe substitutes parameter placeholders in a recipe's endpoint and
 * target URL, validates required parameters, and builds a JSON body from args
 * when the recipe defines a body schema.
 *
 * Mirrors Go's ResolveRecipe function.
 */
export function resolveRecipe(
  recipe: Recipe,
  args?: Record<string, string>,
): { endpoint: string; target_url: string; body?: Uint8Array } {
  const a: Record<string, string> = args ? { ...args } : {};

  // Validate required path params
  if (recipe.path_params) {
    for (const p of recipe.path_params) {
      if (p.required && !(p.name in a)) {
        if (p.default) {
          a[p.name] = p.default;
        } else {
          throw new Error(`missing required path parameter "${p.name}"`);
        }
      }
    }
  }

  // Validate required query params
  if (recipe.query_params) {
    for (const p of recipe.query_params) {
      if (p.required && !(p.name in a)) {
        if (p.default) {
          a[p.name] = p.default;
        } else {
          throw new Error(`missing required query parameter "${p.name}"`);
        }
      }
    }
  }

  // Substitute {param} placeholders
  const substitute = (s: string): string =>
    s.replace(placeholderRe, (match, key) => {
      if (key in a) return a[key];
      return match;
    });

  let endpoint = substitute(recipe.endpoint);
  let targetURL = substitute(recipe.target_url);

  // Append query params to target URL
  const queryParts: string[] = [];
  if (recipe.query_params) {
    for (const p of recipe.query_params) {
      if (p.name in a) {
        queryParts.push(`${p.name}=${a[p.name]}`);
      } else if (p.default) {
        queryParts.push(`${p.name}=${p.default}`);
      }
    }
  }
  if (queryParts.length > 0) {
    const sep = targetURL.includes('?') ? '&' : '?';
    targetURL = targetURL + sep + queryParts.join('&');
  }

  // Build body from body_schema + args for POST/PUT/PATCH
  let body: Uint8Array | undefined;
  const verb = recipe.verb.toUpperCase();
  if (verb === 'POST' || verb === 'PUT' || verb === 'PATCH') {
    if (recipe.body_schema && typeof recipe.body_schema === 'object') {
      const schema = recipe.body_schema as Record<string, unknown>;

      // Discover field names from "properties" (JSON Schema style)
      let fieldNames: string[] = [];
      if (schema.properties && typeof schema.properties === 'object') {
        fieldNames = Object.keys(schema.properties as Record<string, unknown>);
      }

      // Build body object from args matching schema fields
      const bodyMap: Record<string, string> = {};
      if (fieldNames.length > 0) {
        for (const name of fieldNames) {
          if (name in a) {
            bodyMap[name] = a[name];
          }
        }
      } else {
        // Flat schema: treat each top-level key as a field name
        for (const name of Object.keys(schema)) {
          if (name === 'type' || name === 'properties' || name === 'required') continue;
          if (name in a) {
            bodyMap[name] = a[name];
          }
        }
      }

      if (Object.keys(bodyMap).length > 0) {
        body = new TextEncoder().encode(JSON.stringify(bodyMap));
      }

      // Validate required body params from body_schema "required" field
      if (Array.isArray(schema.required)) {
        for (const name of schema.required as string[]) {
          if (!(name in a)) {
            throw new Error(`missing required body parameter "${name}"`);
          }
        }
      }
    }
  }

  return { endpoint, target_url: targetURL, body };
}
