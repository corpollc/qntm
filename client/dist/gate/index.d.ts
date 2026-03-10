import type { GateConversationMessage, GateSignable, ApprovalSignable, ThresholdRule, Credential, Signer, Org, ScanResult, ExecuteResult } from '../types.js';
export declare function signRequest(privateKey: Uint8Array, signable: GateSignable): Uint8Array;
export declare function verifyRequest(publicKey: Uint8Array, signable: GateSignable, signature: Uint8Array): boolean;
export declare function signApproval(privateKey: Uint8Array, approval: ApprovalSignable): Uint8Array;
export declare function verifyApproval(publicKey: Uint8Array, approval: ApprovalSignable, signature: Uint8Array): boolean;
export declare function hashRequest(signable: GateSignable): Uint8Array;
export declare function computePayloadHash(payload: unknown): Uint8Array;
export declare class GateClient {
    private baseURL;
    private adminToken?;
    constructor(baseURL: string, adminToken?: string);
    private headers;
    createOrg(org: {
        id: string;
        signers: Signer[];
        rules: ThresholdRule[];
    }): Promise<Org>;
    getOrg(orgID: string): Promise<Org>;
    addCredential(orgID: string, credential: Credential): Promise<void>;
    submitMessage(orgID: string, message: GateConversationMessage): Promise<void>;
    scanRequest(orgID: string, requestID: string): Promise<ScanResult>;
    executeRequest(orgID: string, requestID: string): Promise<ExecuteResult>;
    health(): Promise<{
        status: string;
    }>;
}
export declare class GateError extends Error {
    status: number;
    body: string;
    constructor(status: number, body: string);
}
export declare function lookupThreshold(rules: ThresholdRule[], service: string, endpoint: string, verb: string): ThresholdRule | undefined;
