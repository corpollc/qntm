import { DurableObject } from "cloudflare:workers";

export interface Env {
	QNTM_KV: KVNamespace;
	CONVO_SEQ_DO: DurableObjectNamespace;
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

type SendPayload = {
	conv_id: string;
	envelope_b64: string;
	announce_sig?: string; // hex Ed25519 sig over SHA-256(envelope_b64), required for announce channels
};

// --- Announce channel types ---

const announceProto = "qntm-announce-v1";

type AnnounceChannelMeta = {
	name: string;
	conv_id: string;
	master_pk: string; // base64url Ed25519 public key
	posting_pk: string; // base64url Ed25519 public key
};

type AnnounceRegisterPayload = {
	name: string;
	conv_id: string;
	master_pk: string;
	posting_pk: string;
	sig: string; // hex Ed25519 sig over pipe-delimited signable
};

type AnnounceRotatePayload = {
	conv_id: string;
	new_posting_pk: string;
	master_pk: string;
	sig: string;
};

type AnnounceDeletePayload = {
	conv_id: string;
	master_pk: string;
	sig: string;
};

type PollConversation = {
	conv_id: string;
	from_seq: number;
};

type PollPayload = {
	conversations: PollConversation[];
	max_messages?: number;
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

function fromBase64(input: string): Uint8Array {
	const raw = atob(input);
	const out = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) {
		out[i] = raw.charCodeAt(i);
	}
	return out;
}

function toBase64(input: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < input.length; i++) {
		binary += String.fromCharCode(input[i]);
	}
	return btoa(binary);
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

// --- Announce channel helpers ---

function announceMetaKey(convID: string): string {
	return `/__announce__/${convID}/meta.json`;
}

async function getAnnounceMeta(env: Env, convID: string): Promise<AnnounceChannelMeta | null> {
	const raw = await env.QNTM_KV.get(announceMetaKey(convID), "text");
	if (!raw) return null;
	return JSON.parse(raw) as AnnounceChannelMeta;
}

async function verifyEd25519Hex(publicKeyBase64URL: string, message: Uint8Array, signatureHex: string): Promise<boolean> {
	const sigBytes = fromHex(signatureHex);
	if (!sigBytes || sigBytes.length !== 64) return false;

	const pkBytes = fromBase64URL(publicKeyBase64URL);
	if (pkBytes.length !== 32) return false;

	const key = await crypto.subtle.importKey("raw", pkBytes, { name: "Ed25519" }, false, ["verify"]);
	return crypto.subtle.verify({ name: "Ed25519" }, key, sigBytes, message);
}

async function verifyAnnounceSig(publicKeyBase64URL: string, plaintext: string, signatureHex: string): Promise<boolean> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(plaintext)));
	return verifyEd25519Hex(publicKeyBase64URL, digest, signatureHex);
}

async function nextSequence(env: Env, convID: string): Promise<number> {
	const id = env.CONVO_SEQ_DO.idFromName(convID);
	const stub = env.CONVO_SEQ_DO.get(id);
	const response = await stub.fetch("https://convo-seq/next", { method: "POST" });
	if (!response.ok) {
		throw new Error(`sequence allocation failed: HTTP ${response.status}`);
	}
	const payload = (await response.json()) as { seq?: number };
	if (!payload || !Number.isInteger(payload.seq) || payload.seq! <= 0) {
		throw new Error("invalid sequence allocation response");
	}
	return payload.seq!;
}

type RelayPublishPayload = {
	conv_id: string;
	envelope_b64: string;
};

type RelayFrame =
	| {
			type: "message";
			seq: number;
			envelope_b64: string;
	  }
	| {
			type: "pong";
	  };

function conversationMessageKey(convID: string, seq: number): string {
	return `/${convID}/msg/${seq}.cbor`;
}

function conversationMessagePrefix(convID: string): string {
	return `/${convID}/msg/`;
}

function parseSequencedMessageKey(convID: string, key: string): number | null {
	const prefix = conversationMessagePrefix(convID);
	if (!key.startsWith(prefix) || !key.endsWith(".cbor")) {
		return null;
	}

	const rawSeq = key.slice(prefix.length, -".cbor".length);
	const seq = Number.parseInt(rawSeq, 10);
	if (!Number.isInteger(seq) || seq <= 0) {
		return null;
	}
	return seq;
}

async function listConversationMessages(
	env: Env,
	convID: string,
	fromSeq: number,
	limit: number,
): Promise<Array<{ seq: number; key: string }>> {
	if (limit <= 0) {
		return [];
	}

	const listed = await env.QNTM_KV.list({ prefix: conversationMessagePrefix(convID), limit: 1000 });
	return listed.keys
		.map((entry) => {
			const seq = parseSequencedMessageKey(convID, entry.name);
			return seq === null ? null : { seq, key: entry.name };
		})
		.filter((entry): entry is { seq: number; key: string } => entry !== null && entry.seq > fromSeq)
		.sort((left, right) => left.seq - right.seq)
		.slice(0, limit);
}

async function loadConversationMessages(
	env: Env,
	convID: string,
	fromSeq: number,
	limit: number,
): Promise<Array<{ seq: number; envelope_b64: string }>> {
	const messageEntries = await listConversationMessages(env, convID, fromSeq, limit);
	const messages: Array<{ seq: number; envelope_b64: string }> = [];
	for (const entry of messageEntries) {
		const value = await env.QNTM_KV.get(entry.key, "arrayBuffer");
		if (value === null) {
			continue;
		}
		messages.push({
			seq: entry.seq,
			envelope_b64: toBase64(new Uint8Array(value)),
		});
	}
	return messages;
}

async function publishConversationMessage(env: Env, convID: string, envelope_b64: string): Promise<number> {
	const id = env.CONVO_SEQ_DO.idFromName(convID);
	const stub = env.CONVO_SEQ_DO.get(id);
	const response = await stub.fetch("https://convo-seq/publish", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ conv_id: convID, envelope_b64 } satisfies RelayPublishPayload),
	});
	if (!response.ok) {
		throw new Error(`conversation publish failed: HTTP ${response.status}`);
	}
	const payload = (await response.json()) as { seq?: number };
	if (!payload || !Number.isInteger(payload.seq) || payload.seq! <= 0) {
		throw new Error("invalid publish response");
	}
	return payload.seq!;
}

async function replayConversationMessages(
	env: Env,
	convID: string,
	fromSeq: number,
): Promise<Array<{ seq: number; envelope_b64: string }>> {
	return loadConversationMessages(env, convID, fromSeq, 1000);
}

function validateUpgradeRequest(request: Request): Response | null {
	if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
		return errorResponse("websocket upgrade required", 426);
	}
	return null;
}

export class ConversationSequencerDO extends DurableObject<Env> {
	private sqlReady = false;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
	}

	private ensureSchema(): void {
		if (this.sqlReady) return;
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS messages (
				seq INTEGER PRIMARY KEY,
				envelope_b64 TEXT NOT NULL,
				created_at INTEGER NOT NULL DEFAULT (unixepoch())
			)
		`);
		this.sqlReady = true;
	}

	private async handlePublish(request: Request): Promise<Response> {
		let payload: RelayPublishPayload;
		try {
			payload = (await request.json()) as RelayPublishPayload;
		} catch {
			return Response.json({ error: "invalid publish payload" }, { status: 400 });
		}

		if (!payload || typeof payload.conv_id !== "string" || typeof payload.envelope_b64 !== "string") {
			return Response.json({ error: "invalid publish fields" }, { status: 400 });
		}

		const convID = payload.conv_id.toLowerCase();
		const ttl = parseInt(this.env.ENVELOPE_TTL_SECONDS || "604800", 10);
		let envelopeBytes: Uint8Array;
		try {
			envelopeBytes = fromBase64(payload.envelope_b64);
		} catch {
			return Response.json({ error: "invalid envelope_b64" }, { status: 400 });
		}

		const current = ((await this.ctx.storage.get<number>("next_seq")) ?? 0) as number;
		const seq = current + 1;
		await this.ctx.storage.put("next_seq", seq);
		await this.env.QNTM_KV.put(conversationMessageKey(convID, seq), envelopeBytes, { expirationTtl: ttl });

		// Store in SQLite for KV-list-free reads
		this.ensureSchema();
		this.ctx.storage.sql.exec(
			`INSERT OR REPLACE INTO messages (seq, envelope_b64, created_at) VALUES (?, ?, ?)`,
			seq, payload.envelope_b64, Math.floor(Date.now() / 1000)
		);

		// Purge expired messages from SQLite (keep in sync with KV TTL)
		const cutoff = Math.floor(Date.now() / 1000) - ttl;
		this.ctx.storage.sql.exec(`DELETE FROM messages WHERE created_at < ?`, cutoff);

		const frame = JSON.stringify({
			type: "message",
			seq,
			envelope_b64: payload.envelope_b64,
		} satisfies RelayFrame);
		for (const webSocket of this.ctx.getWebSockets()) {
			try {
				webSocket.send(frame);
			} catch {
				try {
					webSocket.close(1011, "relay send failed");
				} catch {
					// Ignore best-effort close failures.
				}
			}
		}

		return Response.json({ seq });
	}

	private async handleSubscribe(request: Request): Promise<Response> {
		const upgradeError = validateUpgradeRequest(request);
		if (upgradeError) {
			return upgradeError;
		}

		const url = new URL(request.url);
		const convID = (url.searchParams.get("conv_id") || "").toLowerCase();
		const fromSeqRaw = Number(url.searchParams.get("from_seq") || "0");
		if (!isHexID(convID, 32)) {
			return Response.json({ error: "invalid conv_id" }, { status: 400 });
		}
		if (!Number.isInteger(fromSeqRaw) || fromSeqRaw < 0) {
			return Response.json({ error: "invalid from_seq" }, { status: 400 });
		}

		const [client, server] = Object.values(new WebSocketPair());
		this.ctx.acceptWebSocket(server);

		// Replay from DO SQLite instead of KV to avoid list() limits
		this.ensureSchema();
		const replayRows = this.ctx.storage.sql.exec(
			`SELECT seq, envelope_b64 FROM messages WHERE seq > ? ORDER BY seq ASC LIMIT 1000`,
			fromSeqRaw
		).toArray() as Array<{ seq: number; envelope_b64: string }>;

		for (const message of replayRows) {
			server.send(
				JSON.stringify({
					type: "message",
					seq: message.seq,
					envelope_b64: message.envelope_b64,
				} satisfies RelayFrame),
			);
		}

		return new Response(null, {
			status: 101,
			webSocket: client,
		});
	}

	private handlePoll(request: Request): Response {
		const url = new URL(request.url);
		const fromSeq = Number(url.searchParams.get("from_seq") || "0");
		const limit = Math.min(Number(url.searchParams.get("limit") || "200"), 1000);

		this.ensureSchema();
		const rows = this.ctx.storage.sql.exec(
			`SELECT seq, envelope_b64 FROM messages WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
			fromSeq, limit
		).toArray() as Array<{ seq: number; envelope_b64: string }>;

		const messages = rows.map(r => ({ seq: r.seq, envelope_b64: r.envelope_b64 }));
		const upToSeq = messages.length > 0 ? messages[messages.length - 1]!.seq : fromSeq;

		return Response.json({ messages, up_to_seq: upToSeq });
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		if (request.method === "POST" && url.pathname === "/publish") {
			return this.handlePublish(request);
		}

		if (request.method === "GET" && url.pathname === "/subscribe") {
			return this.handleSubscribe(request);
		}

		if (request.method === "GET" && url.pathname === "/poll") {
			return this.handlePoll(request);
		}

		if (request.method === "POST" && url.pathname === "/next") {
			const current = ((await this.ctx.storage.get<number>("next_seq")) ?? 0) as number;
			const next = current + 1;
			await this.ctx.storage.put("next_seq", next);
			return new Response(JSON.stringify({ seq: next }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (request.method === "GET" && url.pathname === "/head") {
			const current = ((await this.ctx.storage.get<number>("next_seq")) ?? 0) as number;
			return new Response(JSON.stringify({ seq: current }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		return new Response("not found", { status: 404 });
	}

	webSocketMessage(webSocket: WebSocket, message: string | ArrayBuffer): void | Promise<void> {
		if (typeof message !== "string") {
			return;
		}
		if (message === "ping") {
			webSocket.send(JSON.stringify({ type: "pong" } satisfies RelayFrame));
		}
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// CORS preflight
		if (request.method === "OPTIONS") {
			return new Response(null, { status: 204, headers: corsHeaders() });
		}

		// Rate limiting
		const ip = request.headers.get("CF-Connecting-IP") || "unknown";
		const maxPerMin = parseInt(env.RATE_LIMIT_PER_MIN || "500", 10);
		if (!checkRateLimit(ip, maxPerMin)) {
			return errorResponse("rate limit exceeded", 429);
		}

		try {

		const url = new URL(request.url);
		const path = url.pathname;

			// Health check — no auth, no rate limit, no DO access
			if (request.method === "GET" && path === "/healthz") {
				return jsonResponse({ status: "ok", ts: Date.now() }, 200);
			}

			const ttl = parseInt(env.ENVELOPE_TTL_SECONDS || "604800", 10);
			const maxSize = parseInt(env.MAX_ENVELOPE_SIZE || "65536", 10);
			const maxMessagesPerChannel = parseInt(env.MAX_MESSAGES_PER_CHANNEL || "512", 10);

			if (request.method === "POST" && path === "/v1/send") {
				let payload: SendPayload;
				try {
					payload = (await request.json()) as SendPayload;
				} catch {
					return errorResponse("invalid send payload", 400);
				}

				if (!payload || typeof payload.conv_id !== "string" || typeof payload.envelope_b64 !== "string") {
					return errorResponse("invalid send fields", 400);
				}

				payload.conv_id = payload.conv_id.toLowerCase();
				if (!isHexID(payload.conv_id, 32)) {
					return errorResponse("invalid conv_id", 400);
				}

				let envelopeBytes: Uint8Array;
				try {
					envelopeBytes = fromBase64(payload.envelope_b64);
				} catch {
					return errorResponse("invalid envelope_b64", 400);
				}
				if (envelopeBytes.byteLength > maxSize) {
					return errorResponse("envelope too large", 413);
				}

				// Announce channel write gate: if this conv_id is an announce
				// channel, require a valid transport-layer signature from the
				// channel's posting key.
				const announceMeta = await getAnnounceMeta(env, payload.conv_id);
				if (announceMeta) {
					if (!payload.announce_sig || typeof payload.announce_sig !== "string") {
						return errorResponse("announce channel requires announce_sig", 403);
					}
					const sigValid = await verifyAnnounceSig(announceMeta.posting_pk, payload.envelope_b64, payload.announce_sig);
					if (!sigValid) {
						return errorResponse("invalid announce channel signature", 403);
					}
				}

				const seq = await publishConversationMessage(env, payload.conv_id, payload.envelope_b64);
				return jsonResponse({ seq }, 201);
			}

			if (request.method === "POST" && path === "/v1/poll") {
				let payload: PollPayload;
				try {
					payload = (await request.json()) as PollPayload;
				} catch {
					return errorResponse("invalid poll payload", 400);
				}

				if (!payload || !Array.isArray(payload.conversations) || payload.conversations.length === 0 || payload.conversations.length > 20) {
					return errorResponse("invalid conversations list", 400);
				}

				const maxMessagesRaw = payload.max_messages ?? 200;
				if (!Number.isInteger(maxMessagesRaw) || maxMessagesRaw < 0 || maxMessagesRaw > 1000) {
					return errorResponse("invalid max_messages", 400);
				}
				const maxMessages = maxMessagesRaw;

				const conversationResults: Array<{ conv_id: string; up_to_seq: number; messages: Array<{ seq: number; envelope_b64: string }> }> = [];

				for (const convo of payload.conversations) {
					if (!convo || typeof convo.conv_id !== "string" || !Number.isInteger(convo.from_seq) || convo.from_seq < 0) {
						return errorResponse("invalid conversation entry", 400);
					}
					const convID = convo.conv_id.toLowerCase();
					if (!isHexID(convID, 32)) {
						return errorResponse("invalid conv_id", 400);
					}

					// Route reads through DO SQLite instead of KV list() to avoid free-tier daily limits
					const doId = env.CONVO_SEQ_DO.idFromName(convID);
					const stub = env.CONVO_SEQ_DO.get(doId);
					const doResp = await stub.fetch(
						`https://convo-seq/poll?from_seq=${convo.from_seq}&limit=${maxMessages}`
					);
					const doResult = await doResp.json() as { messages: Array<{ seq: number; envelope_b64: string }>; up_to_seq: number };

					conversationResults.push({
						conv_id: convID,
						up_to_seq: doResult.up_to_seq,
						messages: doResult.messages,
					});
				}

				return jsonResponse({ conversations: conversationResults }, 200);
			}

			if (request.method === "GET" && path === "/v1/subscribe") {
				const convID = (url.searchParams.get("conv_id") || "").toLowerCase();
				const fromSeqRaw = Number(url.searchParams.get("from_seq") || "0");
				if (!isHexID(convID, 32)) {
					return errorResponse("invalid conv_id", 400);
				}
				if (!Number.isInteger(fromSeqRaw) || fromSeqRaw < 0) {
					return errorResponse("invalid from_seq", 400);
				}
				const upgradeError = validateUpgradeRequest(request);
				if (upgradeError) {
					return upgradeError;
				}

				const id = env.CONVO_SEQ_DO.idFromName(convID);
				const stub = env.CONVO_SEQ_DO.get(id);
				return stub.fetch(new Request(`https://convo-seq/subscribe?conv_id=${convID}&from_seq=${fromSeqRaw}`, request));
			}

			// --- Announce channel management endpoints ---

			if (request.method === "POST" && path === "/v1/announce/register") {
				let payload: AnnounceRegisterPayload;
				try {
					payload = (await request.json()) as AnnounceRegisterPayload;
				} catch {
					return errorResponse("invalid register payload", 400);
				}

				if (
					!payload ||
					typeof payload.name !== "string" || payload.name.length === 0 || payload.name.length > 64 ||
					typeof payload.conv_id !== "string" ||
					typeof payload.master_pk !== "string" ||
					typeof payload.posting_pk !== "string" ||
					typeof payload.sig !== "string"
				) {
					return errorResponse("invalid register fields", 400);
				}

				payload.conv_id = payload.conv_id.toLowerCase();
				if (!isHexID(payload.conv_id, 32)) {
					return errorResponse("invalid conv_id", 400);
				}

				// Reject if channel already exists
				const existing = await getAnnounceMeta(env, payload.conv_id);
				if (existing) {
					return errorResponse("announce channel already exists", 409);
				}

				// Verify master key signature: SHA-256("qntm-announce-v1|register|{name}|{conv_id}|{posting_pk}")
				const registerSignable = `${announceProto}|register|${payload.name}|${payload.conv_id}|${payload.posting_pk}`;
				const registerValid = await verifyAnnounceSig(payload.master_pk, registerSignable, payload.sig);
				if (!registerValid) {
					return errorResponse("invalid register signature", 403);
				}

				const meta: AnnounceChannelMeta = {
					name: payload.name,
					conv_id: payload.conv_id,
					master_pk: payload.master_pk,
					posting_pk: payload.posting_pk,
				};
				await env.QNTM_KV.put(announceMetaKey(payload.conv_id), JSON.stringify(meta));
				return jsonResponse({ registered: true, name: meta.name, conv_id: meta.conv_id }, 201);
			}

			if (request.method === "POST" && path === "/v1/announce/rotate") {
				let payload: AnnounceRotatePayload;
				try {
					payload = (await request.json()) as AnnounceRotatePayload;
				} catch {
					return errorResponse("invalid rotate payload", 400);
				}

				if (
					!payload ||
					typeof payload.conv_id !== "string" ||
					typeof payload.new_posting_pk !== "string" ||
					typeof payload.master_pk !== "string" ||
					typeof payload.sig !== "string"
				) {
					return errorResponse("invalid rotate fields", 400);
				}

				payload.conv_id = payload.conv_id.toLowerCase();
				if (!isHexID(payload.conv_id, 32)) {
					return errorResponse("invalid conv_id", 400);
				}

				const rotateMeta = await getAnnounceMeta(env, payload.conv_id);
				if (!rotateMeta) {
					return errorResponse("announce channel not found", 404);
				}

				// Only the registered master key can rotate
				if (payload.master_pk !== rotateMeta.master_pk) {
					return errorResponse("master key mismatch", 403);
				}

				const rotateSignable = `${announceProto}|rotate|${payload.conv_id}|${payload.new_posting_pk}`;
				const rotateValid = await verifyAnnounceSig(payload.master_pk, rotateSignable, payload.sig);
				if (!rotateValid) {
					return errorResponse("invalid rotate signature", 403);
				}

				rotateMeta.posting_pk = payload.new_posting_pk;
				await env.QNTM_KV.put(announceMetaKey(payload.conv_id), JSON.stringify(rotateMeta));
				return jsonResponse({ rotated: true, conv_id: rotateMeta.conv_id }, 200);
			}

			if (request.method === "POST" && path === "/v1/announce/delete") {
				let payload: AnnounceDeletePayload;
				try {
					payload = (await request.json()) as AnnounceDeletePayload;
				} catch {
					return errorResponse("invalid delete payload", 400);
				}

				if (
					!payload ||
					typeof payload.conv_id !== "string" ||
					typeof payload.master_pk !== "string" ||
					typeof payload.sig !== "string"
				) {
					return errorResponse("invalid delete fields", 400);
				}

				payload.conv_id = payload.conv_id.toLowerCase();
				if (!isHexID(payload.conv_id, 32)) {
					return errorResponse("invalid conv_id", 400);
				}

				const deleteMeta = await getAnnounceMeta(env, payload.conv_id);
				if (!deleteMeta) {
					return errorResponse("announce channel not found", 404);
				}

				if (payload.master_pk !== deleteMeta.master_pk) {
					return errorResponse("master key mismatch", 403);
				}

				const deleteSignable = `${announceProto}|delete|${payload.conv_id}`;
				const deleteValid = await verifyAnnounceSig(payload.master_pk, deleteSignable, payload.sig);
				if (!deleteValid) {
					return errorResponse("invalid delete signature", 403);
				}

				// Delete channel metadata
				await env.QNTM_KV.delete(announceMetaKey(payload.conv_id));

				// Delete all messages in the channel
				const msgPrefix = `/${payload.conv_id}/msg/`;
				const msgList = await env.QNTM_KV.list({ prefix: msgPrefix, limit: 1000 });
				for (const entry of msgList.keys) {
					await env.QNTM_KV.delete(entry.name);
				}

				return jsonResponse({ deleted: true, conv_id: payload.conv_id }, 200);
			}

			if (request.method === "GET" && path === "/v1/announce/info") {
				const convID = (url.searchParams.get("conv_id") || "").toLowerCase();
				if (!isHexID(convID, 32)) {
					return errorResponse("invalid conv_id", 400);
				}

				const infoMeta = await getAnnounceMeta(env, convID);
				if (!infoMeta) {
					return errorResponse("announce channel not found", 404);
				}

				return jsonResponse({ name: infoMeta.name, conv_id: infoMeta.conv_id, posting_pk: infoMeta.posting_pk }, 200);
			}

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

			// Block receipt-based deletion for announce channels.
			const receiptAnnounceMeta = await getAnnounceMeta(env, payload.conv_id);
			if (receiptAnnounceMeta) {
				return errorResponse("receipts not supported for announce channels", 403);
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

		} catch (err: unknown) {
			const message = err instanceof Error ? err.message : String(err);
			const stack = err instanceof Error ? err.stack : undefined;
			console.error("Unhandled worker error:", message, stack);
			return jsonResponse({ error: "internal error", detail: message }, 500);
		}
	},
} satisfies ExportedHandler<Env>;
