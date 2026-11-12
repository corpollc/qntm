import { pathnameMatchesEndpoint, validateGatewayTargetUrl } from '@corpollc/qntm';
import { decryptVaultEntry } from './vault.js';
import type { VaultEntry, GateRequestMessage } from './types.js';

// Even worst-case JSON escaping fits comfortably inside a 64 KiB envelope.
export const MAX_RESULT_BODY_BYTES = 8 * 1024;

async function boundedResponseBody(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let length = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = MAX_RESULT_BODY_BYTES - length;
      chunks.push(value.subarray(0, remaining));
      length += Math.min(value.length, remaining);
      if (value.length > remaining) { truncated = true; await reader.cancel(); break; }
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder().decode(bytes) + (truncated ? '\n[Response truncated]' : '');
}

export interface ExecutionResult {
  request_id: string;
  status_code: number;
  content_type: string;
  body: string;
  executed_at: string;
}

/**
 * Execute an authorized HTTP request.
 *
 * 1. Decrypt credential from vault
 * 2. Inject into request header using header_name and header_template
 * 3. Execute via fetch() with 30s timeout
 * 4. Return the result
 */
export async function executeRequest(
  request: GateRequestMessage,
  vaultEntry: VaultEntry,
  vaultKey: CryptoKey,
): Promise<ExecutionResult> {
  // Validate target URL, endpoint binding, and vault allowed_origins BEFORE decrypting or sending credentials
  const targetUrl = validateGatewayTargetUrl(request.target_url);
  if (request.target_endpoint !== undefined && !pathnameMatchesEndpoint(targetUrl.pathname, request.target_endpoint)) {
    throw new Error('Target endpoint does not match target URL pathname');
  }
  if (!Array.isArray(vaultEntry.allowed_origins) || vaultEntry.allowed_origins.length === 0 ||
      !vaultEntry.allowed_origins.includes(targetUrl.origin)) {
    throw new Error(`Target origin ${targetUrl.origin} is not authorized for service "${vaultEntry.service}"`);
  }
  const verb = request.verb.toUpperCase();
  if (!/^[A-Z]+$/.test(verb)) {
    throw new Error('Invalid HTTP verb');
  }

  // Decrypt credential value
  const credentialValue = await decryptVaultEntry(vaultEntry, vaultKey);

  try {
    // Build the header value from template (using function replacer so '$' in secrets is never interpreted)
    let headerValue = vaultEntry.header_template;
    if (headerValue.includes('{value}')) {
      headerValue = headerValue.replace('{value}', () => credentialValue);
    } else {
      headerValue = credentialValue;
    }

    // Build request headers
    const headers: Record<string, string> = {
      [vaultEntry.header_name || 'Authorization']: headerValue,
    };

    // Add content-type for requests with payloads
    let body: string | undefined;
    if (request.payload !== undefined && request.payload !== null) {
      body = typeof request.payload === 'string'
        ? request.payload
        : JSON.stringify(request.payload);
      headers['Content-Type'] = 'application/json';
    }

    // Execute with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch(targetUrl.toString(), {
        method: verb,
        headers,
        body,
        signal: controller.signal,
        redirect: 'manual',
      });
      // Workers supports manual/follow, but not redirect:error. Never forward
      // a vault header to the redirect destination.
      if (response.status >= 300 && response.status < 400) throw new Error('Gateway redirects are not allowed');

      const responseBody = await boundedResponseBody(response);

      return {
        request_id: request.request_id,
        status_code: response.status,
        content_type: (response.headers.get('Content-Type') || '').slice(0, 256),
        body: responseBody,
        executed_at: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeout);
    }
  } finally {
    // Best-effort zero the credential in memory
    // (JS strings are immutable, but we do what we can)
  }
}
