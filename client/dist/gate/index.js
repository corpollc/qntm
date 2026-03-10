import { QSP1Suite } from '../crypto/qsp1.js';
import { marshalCanonical } from '../crypto/cbor.js';
const suite = new QSP1Suite();
// Signing helpers
export function signRequest(privateKey, signable) {
    const data = marshalCanonical(signable);
    return suite.sign(privateKey, data);
}
export function verifyRequest(publicKey, signable, signature) {
    const data = marshalCanonical(signable);
    return suite.verify(publicKey, data, signature);
}
export function signApproval(privateKey, approval) {
    const data = marshalCanonical(approval);
    return suite.sign(privateKey, data);
}
export function verifyApproval(publicKey, approval, signature) {
    const data = marshalCanonical(approval);
    return suite.verify(publicKey, data, signature);
}
export function hashRequest(signable) {
    const data = marshalCanonical(signable);
    return suite.hash(data);
}
export function computePayloadHash(payload) {
    if (payload === undefined || payload === null) {
        return suite.hash(new Uint8Array(0));
    }
    const data = new TextEncoder().encode(JSON.stringify(payload));
    return suite.hash(data);
}
// HTTP client
export class GateClient {
    baseURL;
    adminToken;
    constructor(baseURL, adminToken) {
        this.baseURL = baseURL.replace(/\/$/, '');
        this.adminToken = adminToken;
    }
    headers(withAuth = false) {
        const h = { 'Content-Type': 'application/json' };
        if (withAuth && this.adminToken) {
            h['Authorization'] = `Bearer ${this.adminToken}`;
        }
        return h;
    }
    async createOrg(org) {
        const resp = await fetch(`${this.baseURL}/v1/orgs`, {
            method: 'POST',
            headers: this.headers(true),
            body: JSON.stringify(org),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
        return resp.json();
    }
    async getOrg(orgID) {
        const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}`, {
            headers: this.headers(true),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
        return resp.json();
    }
    async addCredential(orgID, credential) {
        const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/credentials`, {
            method: 'POST',
            headers: this.headers(true),
            body: JSON.stringify(credential),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
    }
    async submitMessage(orgID, message) {
        const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/messages`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify(message),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
    }
    async scanRequest(orgID, requestID) {
        const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/scan/${requestID}`, {
            headers: this.headers(),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
        return resp.json();
    }
    async executeRequest(orgID, requestID) {
        const resp = await fetch(`${this.baseURL}/v1/orgs/${orgID}/execute/${requestID}`, {
            method: 'POST',
            headers: this.headers(true),
        });
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
        return resp.json();
    }
    async health() {
        const resp = await fetch(`${this.baseURL}/health`);
        if (!resp.ok) {
            throw new GateError(resp.status, await resp.text());
        }
        return resp.json();
    }
}
export class GateError extends Error {
    status;
    body;
    constructor(status, body) {
        super(`Gate API error ${status}: ${body}`);
        this.status = status;
        this.body = body;
    }
}
// Threshold matching (mirrors Go LookupThreshold)
export function lookupThreshold(rules, service, endpoint, verb) {
    // Priority: exact(service+endpoint+verb) > service+verb > service > default
    let bestMatch;
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
            }
            else if (rule.endpoint === '' && rule.verb === verb) {
                score = 1.5; // service+verb but no endpoint
            }
        }
        else if (rule.service === '' || rule.service === '*') {
            score = 0.5; // default
        }
        if (score > bestScore) {
            bestScore = score;
            bestMatch = rule;
        }
    }
    return bestMatch;
}
//# sourceMappingURL=index.js.map