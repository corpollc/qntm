export interface Env {
	QNTM_KV: KVNamespace;
	ENVELOPE_TTL_SECONDS: string;
	MAX_ENVELOPE_SIZE: string;
	MAX_MESSAGES_PER_CHANNEL: string;
	RATE_LIMIT_PER_MIN: string;
}

// In-memory rate limit state (resets per isolate lifetime)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string, maxPerMin: number): boolean {
	const now = Date.now();
	const entry = rateLimitMap.get(ip);
	if (!entry || now > entry.resetAt) {
		rateLimitMap.set(ip, { count: 1, resetAt: now + 60_000 });
		return true;
	}
	entry.count++;
	return entry.count <= maxPerMin;
}

function corsHeaders(): HeadersInit {
	return {
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "GET, PUT, DELETE, HEAD, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type",
		"Access-Control-Max-Age": "86400",
	};
}

function jsonResponse(body: unknown, status: number, extra?: HeadersInit): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", ...corsHeaders(), ...extra },
	});
}

function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
}

function parseMessageKey(key: string): { convID: string; ts: number; msgID: string } | null {
	const match = key.match(/^\/([0-9a-f]{32})\/msg\/(\d+)\/([0-9a-f]{32})\.cbor$/i);
	if (!match) {
		return null;
	}

	return {
		convID: match[1].toLowerCase(),
		ts: Number(match[2]),
		msgID: match[3].toLowerCase(),
	};
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// CORS preflight
		if (request.method === "OPTIONS") {
			return new Response(null, { status: 204, headers: corsHeaders() });
		}

		// Rate limiting
		const ip = request.headers.get("CF-Connecting-IP") || "unknown";
		const maxPerMin = parseInt(env.RATE_LIMIT_PER_MIN || "100", 10);
		if (!checkRateLimit(ip, maxPerMin)) {
			return errorResponse("rate limit exceeded", 429);
		}

		const url = new URL(request.url);
		const path = url.pathname;

		// Route: /v1/drop/:key or /v1/drop/?prefix=
		if (!path.startsWith("/v1/drop")) {
			return errorResponse("not found", 404);
		}

		const keyPart = path.slice("/v1/drop".length); // e.g. "" or "/" or "/some/key"

		// LIST: GET /v1/drop/?prefix=...
		if (request.method === "GET" && (keyPart === "" || keyPart === "/") && url.searchParams.has("prefix")) {
			const prefix = url.searchParams.get("prefix") || "";
			const list = await env.QNTM_KV.list({ prefix });
			const keys = list.keys.map((k) => k.name);
			return jsonResponse(keys, 200);
		}

		// All other operations require a key
		// Key is everything after /v1/drop (including leading /)
		if (!keyPart || keyPart === "/") {
			return errorResponse("key required", 400);
		}
		const key = keyPart; // includes leading /

		const ttl = parseInt(env.ENVELOPE_TTL_SECONDS || "604800", 10);
		const maxSize = parseInt(env.MAX_ENVELOPE_SIZE || "65536", 10);
		const maxMessagesPerChannel = parseInt(env.MAX_MESSAGES_PER_CHANNEL || "512", 10);

		switch (request.method) {
			case "PUT": {
				const body = await request.arrayBuffer();
				if (body.byteLength > maxSize) {
					return errorResponse("envelope too large", 413);
				}

				let pruned = 0;
				const parsed = parseMessageKey(key);
				if (parsed && maxMessagesPerChannel > 0) {
					const prefix = `/${parsed.convID}/msg/`;
					const listed = await env.QNTM_KV.list({ prefix, limit: 1000 });
					const messageKeys = listed.keys
						.map((entry) => entry.name)
						.map((name) => ({ name, parsed: parseMessageKey(name) }))
						.filter((entry): entry is { name: string; parsed: { convID: string; ts: number; msgID: string } } => entry.parsed !== null)
						.sort((left, right) => {
							if (left.parsed.ts !== right.parsed.ts) {
								return left.parsed.ts - right.parsed.ts;
							}
							return left.name.localeCompare(right.name);
						});

					const pruneCount = Math.max(0, messageKeys.length - maxMessagesPerChannel + 1);
					for (let i = 0; i < pruneCount; i++) {
						const victim = messageKeys[i];
						await env.QNTM_KV.delete(victim.name);
						pruned++;

						const ackPrefix = `/${parsed.convID}/ack/${victim.parsed.msgID}/`;
						const ackList = await env.QNTM_KV.list({ prefix: ackPrefix, limit: 1000 });
						for (const ackKey of ackList.keys) {
							await env.QNTM_KV.delete(ackKey.name);
						}
					}
				}

				await env.QNTM_KV.put(key, body, { expirationTtl: ttl });
				return new Response(null, {
					status: 201,
					headers: {
						...corsHeaders(),
						"X-QNTM-Pruned": String(pruned),
					},
				});
			}

			case "GET": {
				const value = await env.QNTM_KV.get(key, "arrayBuffer");
				if (value === null) {
					return errorResponse("not found", 404);
				}
				return new Response(value, {
					status: 200,
					headers: { "Content-Type": "application/octet-stream", ...corsHeaders() },
				});
			}

			case "HEAD": {
				const value = await env.QNTM_KV.get(key, "arrayBuffer");
				if (value === null) {
					return new Response(null, { status: 404, headers: corsHeaders() });
				}
				return new Response(null, {
					status: 200,
					headers: { "Content-Length": value.byteLength.toString(), ...corsHeaders() },
				});
			}

			case "DELETE": {
				await env.QNTM_KV.delete(key);
				return new Response(null, { status: 200, headers: corsHeaders() });
			}

			default:
				return errorResponse("method not allowed", 405);
		}
	},
} satisfies ExportedHandler<Env>;
