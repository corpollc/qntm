import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical, unmarshalCanonical } from '../crypto/cbor.js';
import { base64UrlEncode, base64UrlDecode } from '../identity/index.js';
import type {
  GateConversationMessage, GateSignable, ApprovalSignable,
  ThresholdRule, Credential, Signer, Org, ScanResult, ExecuteResult,
} from '../types.js';

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
