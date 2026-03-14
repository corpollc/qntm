import type { Env, PromoteRequest } from './types.js';

export { GatewayConversationDO } from './do.js';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    // Health check — lightweight, no auth
    if (url.pathname === '/health') {
      return cors(Response.json({ status: 'ok', service: 'qntm-gateway' }));
    }

    // POST /v1/promote — bootstrap contract
    if (request.method === 'POST' && url.pathname === '/v1/promote') {
      return cors(await handlePromote(request, env));
    }

    return cors(new Response('Not Found', { status: 404 }));
  },
} satisfies ExportedHandler<Env>;

/**
 * POST /v1/promote
 *
 * Bootstrap-only endpoint. Creates or returns the per-conversation gateway
 * keypair and accepts conversation crypto material for dropbox polling.
 *
 * This is NOT a control plane for gate config, approval, or execution.
 * After bootstrap, all state flows through conversation messages.
 */
async function handlePromote(request: Request, env: Env): Promise<Response> {
  let body: PromoteRequest;
  try {
    body = await request.json() as PromoteRequest;
  } catch {
    return Response.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  if (!body.conv_id || typeof body.conv_id !== 'string') {
    return Response.json({ error: 'conv_id is required' }, { status: 400 });
  }
  // conv_id is a 16-byte hex string (32 chars)
  if (!/^[0-9a-f]{32}$/i.test(body.conv_id)) {
    return Response.json({ error: 'conv_id must be a 32-character hex string' }, { status: 400 });
  }
  if (!body.conv_aead_key || typeof body.conv_aead_key !== 'string') {
    return Response.json({ error: 'conv_aead_key is required' }, { status: 400 });
  }
  if (!body.conv_nonce_key || typeof body.conv_nonce_key !== 'string') {
    return Response.json({ error: 'conv_nonce_key is required' }, { status: 400 });
  }
  if (typeof body.conv_epoch !== 'number') {
    return Response.json({ error: 'conv_epoch is required' }, { status: 400 });
  }

  // Route to the DO instance for this conversation
  const doId = env.GATEWAY_CONVO_DO.idFromName(body.conv_id);
  const stub = env.GATEWAY_CONVO_DO.get(doId);

  const doReq = new Request('http://do/promote', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  return stub.fetch(doReq);
}

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function cors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders())) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
