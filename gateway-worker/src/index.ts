import type { Env } from './types.js';
import { validInvitationRequest } from './handshake.js';
import type { InvitationRequest } from './handshake.js';

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

    if (request.method === 'POST' && ['/v1/invitations', '/v1/promote'].includes(url.pathname)) {
      let body: InvitationRequest & { sealed?: string };
      const text = await request.text();
      if (text.length > 16384) return cors(Response.json({ error: 'invitation request too large' }, { status: 413 }));
      try { body = JSON.parse(text); } catch { return cors(Response.json({ error: 'invalid JSON body' }, { status: 400 })); }
      if (!validInvitationRequest(body) || (url.pathname === '/v1/promote' && typeof body.sealed !== 'string')) {
        return cors(Response.json({ error: 'invitation_id, inviter_public_key and encrypted promotion material are required' }, { status: 400 }));
      }
      // Pending invitations do not reserve a conversation ID. Each inviter controls their namespace.
      const id = env.GATEWAY_CONVO_DO.idFromName(`invite:${body.inviter_public_key}:${body.invitation_id}`);
      return cors(await env.GATEWAY_CONVO_DO.get(id).fetch(new Request(`http://do/${url.pathname.endsWith('invitations') ? 'invitations' : 'promote'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })));
    }

    return cors(new Response('Not Found', { status: 404 }));
  },
} satisfies ExportedHandler<Env>;

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
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
