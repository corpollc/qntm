import type { GatewayInvitation, GatewayBootstrapRequest } from './handshake.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { base64UrlEncode, base64UrlDecode } from '../identity/index.js';
import type {
  GateSignable, ApprovalSignable,
  ThresholdRule, Recipe,
} from '../types.js';

// Gate message type constants (mirrors Go gate package constants)
export const GateMessageRequest = 'gate.request' as const;
export const GateMessageApproval = 'gate.approval' as const;
export const GateMessageDisapproval = 'gate.disapproval' as const;
export const GateMessageExecuted = 'gate.executed' as const;
export const GateMessagePromote = 'gate.promote' as const;
export const GateMessageConfig = 'gate.config' as const;
export const GateMessageSecret = 'gate.secret' as const;
export const GateMessageRevoke = 'gate.revoke' as const;
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

export interface GateClientOptions {
  /** Deadline for headers and the complete response body. Default: 30 seconds. */
  timeoutMs?: number;
  /** Cancels each request made by this client. Requests are never retried. */
  signal?: AbortSignal;
}

export class GateClient {
  private baseURL: string;
  private timeoutMs: number;
  constructor(baseURL: string, private readonly options: GateClientOptions = {}) {
    this.baseURL = baseURL.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 300_000) {
      throw new RangeError('Gateway timeout must be an integer from 1 to 300000 milliseconds');
    }
  }

  private async request<T>(path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const signal = this.options.signal;
    const cancel = () => controller.abort(signal?.reason);
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel, { once: true });
    const timer = setTimeout(() => controller.abort(new DOMException('Gateway request timed out', 'TimeoutError')), this.timeoutMs);
    try {
      if (controller.signal.aborted) throw controller.signal.reason;
      const response = await fetch(`${this.baseURL}${path}`, {
        ...(body === undefined ? { method: 'GET' } : {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        }),
        redirect: 'error', signal: controller.signal,
      });
      const chunks: Uint8Array[] = [];
      let length = 0;
      const reader = response.body?.getReader();
      if (reader) {
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            length += value.byteLength;
            if (length > 64 * 1024) {
              controller.abort();
              void reader.cancel().catch(() => {});
              throw new RangeError('Gateway response exceeds 64 KiB');
            }
            chunks.push(value);
          }
        } finally { reader.releaseLock(); }
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const text = new TextDecoder().decode(bytes);
      if (!response.ok) throw new GateError(response.status, text);
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
    }
  }

  createInvitation(inviterPublicKey: string, invitationId: string): Promise<GatewayInvitation> {
    return this.request('/v1/invitations', { inviter_public_key: inviterPublicKey, invitation_id: invitationId });
  }

  /** HTTP completion is advisory: clients activate only after verifying gate.accept in chat. */
  promote(body: GatewayBootstrapRequest): Promise<{ status: 'waiting' | 'joined'; gateway_public_key: string; gateway_kid: string; invitation_id: string }> {
    return this.request('/v1/promote', body);
  }

  health(): Promise<{ status: string }> { return this.request('/health'); }
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
  // All specified fields must match. Specificity is service, endpoint, then
  // verb; the first rule wins ties. Empty strings are legacy wildcards.
  let bestMatch: ThresholdRule | undefined;
  let bestScore = -1;
  const wildcard = (value: string) => value === '' || value === '*';
  for (const rule of rules) {
    if ((!wildcard(rule.service) && rule.service !== service) ||
        (!wildcard(rule.endpoint) && rule.endpoint !== endpoint) ||
        (!wildcard(rule.verb) && rule.verb !== verb)) continue;
    const score = (wildcard(rule.service) ? 0 : 4) +
      (wildcard(rule.endpoint) ? 0 : 2) + (wildcard(rule.verb) ? 0 : 1);
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
