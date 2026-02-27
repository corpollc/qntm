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
		"Access-Control-Allow-Methods": "GET, PUT, POST, HEAD, OPTIONS",
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

const receiptProto = "qntm-receipt-v1";

type ReadReceiptPayload = {
	proto: string;
	conv_id: string;
	msg_id: string;
	reader_kid: string;
	reader_ik_pk: string;
	read_ts: number;
	required_acks: number;
	sig: string;
};

function toHex(data: Uint8Array): string {
	return Array.from(data)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function fromHex(hex: string): Uint8Array | null {
	if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
		return null;
	}
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

function fromBase64URL(input: string): Uint8Array {
	const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
	const raw = atob(padded);
	const out = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) {
		out[i] = raw.charCodeAt(i);
	}
	return out;
}

function buildReceiptSignable(payload: ReadReceiptPayload): Uint8Array {
	const signable = `${receiptProto}|${payload.conv_id}|${payload.msg_id}|${payload.reader_kid}|${payload.read_ts}|${payload.required_acks}`;
	return new TextEncoder().encode(signable);
}

async function computeKeyIDHexFromPublicKey(publicKeyRaw: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", publicKeyRaw);
	return toHex(new Uint8Array(digest).slice(0, 16));
}

async function verifyReceiptSignature(payload: ReadReceiptPayload): Promise<boolean> {
	const publicKeyRaw = fromBase64URL(payload.reader_ik_pk);
	if (publicKeyRaw.length !== 32) {
		return false;
	}

	const keyIDHex = await computeKeyIDHexFromPublicKey(publicKeyRaw);
	if (keyIDHex !== payload.reader_kid.toLowerCase()) {
		return false;
	}

	const signatureRaw = fromBase64URL(payload.sig);
	if (signatureRaw.length !== 64) {
		return false;
	}

	const publicKey = await crypto.subtle.importKey("raw", publicKeyRaw, { name: "Ed25519" }, false, ["verify"]);
	return crypto.subtle.verify({ name: "Ed25519" }, publicKey, signatureRaw, buildReceiptSignable(payload));
}

function isHexID(value: string, expectedLength: number): boolean {
	return new RegExp(`^[0-9a-f]{${expectedLength}}$`, "i").test(value);
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
		const ttl = parseInt(env.ENVELOPE_TTL_SECONDS || "604800", 10);
		const maxSize = parseInt(env.MAX_ENVELOPE_SIZE || "65536", 10);
		const maxMessagesPerChannel = parseInt(env.MAX_MESSAGES_PER_CHANNEL || "512", 10);

		if (request.method === "POST" && path === "/v1/receipt") {
			let payload: ReadReceiptPayload;
			try {
				payload = (await request.json()) as ReadReceiptPayload;
			} catch {
				return errorResponse("invalid receipt payload", 400);
			}

			if (
				!payload ||
				payload.proto !== receiptProto ||
				typeof payload.conv_id !== "string" ||
				typeof payload.msg_id !== "string" ||
				typeof payload.reader_kid !== "string" ||
				typeof payload.reader_ik_pk !== "string" ||
				typeof payload.sig !== "string" ||
				typeof payload.read_ts !== "number" ||
				typeof payload.required_acks !== "number"
			) {
				return errorResponse("invalid receipt fields", 400);
			}

			payload.conv_id = payload.conv_id.toLowerCase();
			payload.msg_id = payload.msg_id.toLowerCase();
			payload.reader_kid = payload.reader_kid.toLowerCase();

			if (!isHexID(payload.conv_id, 32) || !isHexID(payload.msg_id, 32) || !isHexID(payload.reader_kid, 32)) {
				return errorResponse("invalid receipt identifiers", 400);
			}

			if (!Number.isFinite(payload.read_ts) || payload.read_ts <= 0) {
				return errorResponse("invalid read timestamp", 400);
			}
			if (!Number.isInteger(payload.required_acks) || payload.required_acks < 1 || payload.required_acks > 256) {
				return errorResponse("invalid required_acks", 400);
			}

			const signatureValid = await verifyReceiptSignature(payload);
			if (!signatureValid) {
				return errorResponse("invalid receipt signature", 401);
			}

			const messagePrefix = `/${payload.conv_id}/msg/`;
			const messageList = await env.QNTM_KV.list({ prefix: messagePrefix, limit: 1000 });
			const messageSuffix = `/${payload.msg_id}.cbor`;
			const messageKey = messageList.keys.map((entry) => entry.name).find((name) => name.endsWith(messageSuffix));
			if (!messageKey) {
				return errorResponse("message not found", 404);
			}

			const receiptPrefix = `/${payload.conv_id}/receipt/${payload.msg_id}/`;
			const receiptKey = `${receiptPrefix}${payload.reader_kid}.json`;
			await env.QNTM_KV.put(receiptKey, JSON.stringify(payload), { expirationTtl: ttl });

			const receiptList = await env.QNTM_KV.list({ prefix: receiptPrefix, limit: 1000 });
			const uniqueReaderKIDs = new Set<string>();
			for (const entry of receiptList.keys) {
				const suffix = entry.name.slice(receiptPrefix.length);
				if (!suffix.endsWith(".json")) {
					continue;
				}
				const kid = suffix.slice(0, -".json".length).toLowerCase();
				if (isHexID(kid, 32)) {
					uniqueReaderKIDs.add(kid);
				}
			}

			const shouldDelete = uniqueReaderKIDs.size >= payload.required_acks;
			if (shouldDelete) {
				await env.QNTM_KV.delete(messageKey);
				for (const entry of receiptList.keys) {
					await env.QNTM_KV.delete(entry.name);
				}

				// Clean up any legacy ACK objects for this message.
				const legacyAckPrefix = `/${payload.conv_id}/ack/${payload.msg_id}/`;
				const legacyAckList = await env.QNTM_KV.list({ prefix: legacyAckPrefix, limit: 1000 });
				for (const ack of legacyAckList.keys) {
					await env.QNTM_KV.delete(ack.name);
				}
			}

			return jsonResponse(
				{
					recorded: true,
					deleted: shouldDelete,
					receipts: uniqueReaderKIDs.size,
					required_acks: payload.required_acks,
				},
				200,
			);
		}

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

						const receiptPrefix = `/${parsed.convID}/receipt/${victim.parsed.msgID}/`;
						const receiptList = await env.QNTM_KV.list({ prefix: receiptPrefix, limit: 1000 });
						for (const receiptKey of receiptList.keys) {
							await env.QNTM_KV.delete(receiptKey.name);
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

			default:
				return errorResponse("method not allowed", 405);
		}
	},
} satisfies ExportedHandler<Env>;
