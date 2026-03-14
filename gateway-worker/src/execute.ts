import { decryptVaultEntry } from './vault.js';
import type { VaultEntry, GateRequestMessage } from './types.js';

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
  // Decrypt credential value
  const credentialValue = await decryptVaultEntry(vaultEntry, vaultKey);

  try {
    // Build the header value from template
    let headerValue = vaultEntry.header_template;
    if (headerValue.includes('{value}')) {
      headerValue = headerValue.replace('{value}', credentialValue);
    } else {
      headerValue = credentialValue;
    }

    // Build request headers
    const headers: Record<string, string> = {
      [vaultEntry.header_name || 'Authorization']: headerValue,
    };

    // Add content-type for requests with payloads
    const verb = request.verb.toUpperCase();
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
      const response = await fetch(request.target_url, {
        method: verb,
        headers,
        body,
        signal: controller.signal,
      });

      const responseBody = await response.text();

      return {
        request_id: request.request_id,
        status_code: response.status,
        content_type: response.headers.get('Content-Type') || '',
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
