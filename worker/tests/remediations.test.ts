import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { generateIdentity, base64UrlEncode, QSP1Suite } from "@corpollc/qntm";
import worker, { ConversationSequencerDO, announceID, type Env } from "../src/index.js";
import { MAX_RATE_LIMIT_IPS, RATE_LIMIT_WINDOW_MS, RelayRateLimiter, normalizeRateLimitClientKey } from "../src/rate-limit.js";
import { RelayRetention, maxMessagesPerChannel } from "../src/retention.js";

const databases: DatabaseSync[] = [];
afterEach(() => {
	for (const db of databases.splice(0)) db.close();
});

class MockHibernatableSocket {
	sent: string[] = [];
	closedWith: { code: number; reason: string } | null = null;
	throwOnClose = false;
	private attachmentJson: string | null = null;
	peer?: MockHibernatableSocket;

	send(data: string): void {
		if (this.closedWith) throw new Error("socket already closed");
		this.sent.push(data);
	}

	close(code = 1000, reason = ""): void {
		if (this.throwOnClose || this.closedWith) {
			throw new Error("socket already closed");
		}
		this.closedWith = { code, reason };
	}

	serializeAttachment(value: unknown): void {
		this.attachmentJson = JSON.stringify(value);
	}

	deserializeAttachment(): unknown {
		return this.attachmentJson === null ? null : JSON.parse(this.attachmentJson);
	}
}

// Install WebSocketPair shim for Durable Object handleSubscribe tests
(globalThis as Record<string, unknown>).WebSocketPair = class WebSocketPair {
	0: MockHibernatableSocket;
	1: MockHibernatableSocket;
	constructor() {
		const client = new MockHibernatableSocket();
		const server = new MockHibernatableSocket();
		client.peer = server;
		server.peer = client;
		this[0] = client;
		this[1] = server;
	}
};

// Patch global Response to tolerate status 101 with webSocket in Node undici
const OriginalResponse = globalThis.Response;
class WorkerResponse extends OriginalResponse {
	webSocket?: unknown;
	private _status101 = false;
	constructor(body?: BodyInit | null, init?: ResponseInit & { webSocket?: unknown }) {
		if (init?.status === 101) {
			const { status: _ignored, webSocket, ...rest } = init;
			super(body, { ...rest, status: 200 });
			this.webSocket = webSocket;
			this._status101 = true;
		} else {
			super(body, init);
		}
	}
	override get status(): number {
		return this._status101 ? 101 : super.status;
	}
}
globalThis.Response = WorkerResponse as unknown as typeof Response;

function createDOHarness(envOverrides: Partial<Env> = {}) {
	const db = new DatabaseSync(":memory:");
	databases.push(db);
	const kvStore = new Map<string, unknown>();
	const externalKv = new Map<string, string>();
	let alarm: number | null = null;
	let acceptedSockets: MockHibernatableSocket[] = [];
	let kvPutCalls = 0;

	const storage = {
		sql: {
			exec(query: string, ...bindings: (string | number)[]) {
				const rows = db.prepare(query).all(...bindings);
				return { toArray: () => rows };
			},
		},
		transactionSync<T>(action: () => T): T {
			db.exec("BEGIN");
			try {
				const result = action();
				db.exec("COMMIT");
				return result;
			} catch (err) {
				db.exec("ROLLBACK");
				throw err;
			}
		},
		async get<T>(key: string): Promise<T | undefined> {
			return kvStore.get(key) as T | undefined;
		},
		async put(key: string, value: unknown): Promise<void> {
			kvStore.set(key, value);
		},
		async delete(keys: string | string[]): Promise<void> {
			for (const k of typeof keys === "string" ? [keys] : keys) kvStore.delete(k);
		},
		async list({ prefix, limit }: { prefix: string; limit: number }) {
			return new Map([...kvStore.entries()].filter(([k]) => k.startsWith(prefix)).sort().slice(0, limit));
		},
		async getAlarm() {
			return alarm;
		},
		async setAlarm(value: number) {
			alarm = value;
		},
		async deleteAlarm() {
			alarm = null;
		},
	};

	const makeCtx = () => {
		let initPromise: Promise<unknown> = Promise.resolve();
		const ctx = {
			storage,
			acceptWebSocket(ws: MockHibernatableSocket) {
				acceptedSockets.push(ws);
			},
			getWebSockets() {
				return acceptedSockets.filter((ws) => !ws.closedWith);
			},
			blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> {
				const next = initPromise.then(fn, fn);
				initPromise = next;
				return next;
			},
			waitUntil(_p: Promise<unknown>) {},
			get ready() {
				return initPromise;
			},
		};
		return ctx;
	};

	const env: Env = {
		QNTM_KV: {
			async get(key: string) {
				return externalKv.get(key) ?? null;
			},
			async put(key: string, val: string) {
				kvPutCalls++;
				externalKv.set(key, String(val));
			},
			async delete(key: string) {
				externalKv.delete(key);
			},
			async list({ prefix }: { prefix: string }) {
				const keys = [...externalKv.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
				return { keys, list_complete: true };
			},
		} as unknown as KVNamespace,
		CONVO_SEQ_DO: {} as DurableObjectNamespace,
		RELAY_METRICS_DO: {
			idFromName: () => ({} as DurableObjectId),
			get: () => ({ fetch: async () => new Response(JSON.stringify({ recorded: true }), { status: 200 }) }) as unknown as DurableObjectStub,
		} as unknown as DurableObjectNamespace,
		ENVELOPE_TTL_SECONDS: "600",
		MAX_ENVELOPE_SIZE: "65536",
		MAX_MESSAGES_PER_CHANNEL: "512",
		RATE_LIMIT_PER_MIN: "500",
		...envOverrides,
	};

	const instantiateDO = async () => {
		const ctx = makeCtx();
		const instance = new ConversationSequencerDO(ctx as unknown as DurableObjectState, env);
		await ctx.ready;
		return instance;
	};

	// Wire CONVO_SEQ_DO to route to a live DO instance backed by the same storage
	let activeDO: ConversationSequencerDO | null = null;
	env.CONVO_SEQ_DO = {
		idFromName: (name: string) => name as unknown as DurableObjectId,
		get: () =>
			({
				fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
					if (!activeDO) activeDO = await instantiateDO();
					const req = input instanceof Request ? input : new Request(String(input), init);
					return activeDO.fetch(req);
				},
			}) as unknown as DurableObjectStub,
	} as unknown as DurableObjectNamespace;

	return {
		db,
		storage,
		externalKv,
		env,
		get acceptedSockets() {
			return acceptedSockets;
		},
		get kvPutCalls() {
			return kvPutCalls;
		},
		instantiateDO,
		setActiveDO(instance: ConversationSequencerDO) {
			activeDO = instance;
		},
	};
}

describe("P1-5a: ConversationSequencerDO hibernation auth, broadcast gate & close handshake", () => {
	it("persists WebSocket auth across DO hibernation and withholds live broadcasts until auth_ok", async () => {
		const h = createDOHarness();
		const do1 = await h.instantiateDO();
		h.setActiveDO(do1);

		const convId = "11".repeat(16);
		const subscriber = generateIdentity();
		const suite = new QSP1Suite();
		const pubKeyHex = Buffer.from(subscriber.publicKey).toString("hex");

		// Post message #1 before subscriber connects
		const pub1 = await do1.fetch(
			new Request("https://convo-seq/publish", {
				method: "POST",
				body: JSON.stringify({ conv_id: convId, envelope_b64: Buffer.from("m1").toString("base64") }),
			}),
		);
		assert.equal(pub1.status, 200);

		// Open authenticated WebSocket subscription
		const subRes = await do1.fetch(
			new Request(`https://convo-seq/subscribe?conv_id=${convId}&from_seq=0&pub_key=${pubKeyHex}`, {
				headers: { Upgrade: "websocket" },
			}),
		);
		assert.equal(subRes.status, 101);
		const authWs = h.acceptedSockets[0];
		assert.equal(authWs.sent.length, 1);
		const challengeFrame = JSON.parse(authWs.sent[0]) as { type: string; challenge_hex: string };
		assert.equal(challengeFrame.type, "auth_challenge");

		// Also open an unauthenticated subscriber (immediately ready)
		const openSubRes = await do1.fetch(
			new Request(`https://convo-seq/subscribe?conv_id=${convId}&from_seq=1`, {
				headers: { Upgrade: "websocket" },
			}),
		);
		assert.equal(openSubRes.status, 101);
		const unauthModeWs = h.acceptedSockets[1];
		assert.deepEqual(
			unauthModeWs.sent.map((f) => JSON.parse(f).type),
			["ready"],
		);

		// Simulate DO hibernation BEFORE auth_response AND publish message #2 on woken DO instance!
		const do2 = await h.instantiateDO();
		h.setActiveDO(do2);

		const pub2 = await do2.fetch(
			new Request("https://convo-seq/publish", {
				method: "POST",
				body: JSON.stringify({ conv_id: convId, envelope_b64: Buffer.from("m2").toString("base64") }),
			}),
		);
		assert.equal(pub2.status, 200);

		// Unauthenticated pending socket MUST NOT receive live broadcast of m2!
		assert.equal(authWs.sent.length, 1);
		// Already-ready socket MUST receive m2 even after DO hibernation!
		assert.equal(unauthModeWs.sent.length, 2);
		assert.equal(JSON.parse(unauthModeWs.sent[1]).seq, 2);

		// Simulate ANOTHER DO hibernation before client sends auth_response!
		const do3 = await h.instantiateDO();
		h.setActiveDO(do3);

		const sig = suite.sign(subscriber.privateKey, Buffer.from(challengeFrame.challenge_hex, "hex"));
		await do3.webSocketMessage(
			authWs as unknown as WebSocket,
			JSON.stringify({ type: "auth_response", signature_hex: Buffer.from(sig).toString("hex") }),
		);

		// Verify auth_ok, single ordered replay of m1 + m2 (no duplicates!), and ready(2)
		const framesAfterAuth = authWs.sent.slice(1).map((raw) => JSON.parse(raw));
		assert.deepEqual(
			framesAfterAuth.map((f) => ({ type: f.type, seq: f.seq, head_seq: f.head_seq })),
			[
				{ type: "auth_ok", seq: undefined, head_seq: undefined },
				{ type: "message", seq: 1, head_seq: undefined },
				{ type: "message", seq: 2, head_seq: undefined },
				{ type: "ready", seq: undefined, head_seq: 2 },
			],
		);

		// Simulate hibernation AFTER auth_ok and publish m3: authWs MUST now receive live m3!
		const do4 = await h.instantiateDO();
		await do4.fetch(
			new Request("https://convo-seq/publish", {
				method: "POST",
				body: JSON.stringify({ conv_id: convId, envelope_b64: Buffer.from("m3").toString("base64") }),
			}),
		);
		const lastFrame = JSON.parse(authWs.sent.at(-1)!);
		assert.deepEqual({ type: lastFrame.type, seq: lastFrame.seq }, { type: "message", seq: 3 });
	});

	it("completes close-frame handshakes cleanly and handles errored/already-closed sockets safely", async () => {
		const h = createDOHarness();
		const doInstance = await h.instantiateDO();

		const wsCustom = new MockHibernatableSocket();
		doInstance.webSocketClose(wsCustom as unknown as WebSocket, 4000, "callback retry");
		assert.deepEqual(wsCustom.closedWith, { code: 4000, reason: "callback retry" });

		const wsNoCode = new MockHibernatableSocket();
		doInstance.webSocketClose(wsNoCode as unknown as WebSocket, 1005, "");
		assert.deepEqual(wsNoCode.closedWith, { code: 1000, reason: "" });

		const wsErrored = new MockHibernatableSocket();
		doInstance.webSocketError(wsErrored as unknown as WebSocket);
		assert.deepEqual(wsErrored.closedWith, { code: 1011, reason: "relay connection failed" });

		const wsAlreadyClosed = new MockHibernatableSocket();
		wsAlreadyClosed.throwOnClose = true;
		assert.doesNotThrow(() => doInstance.webSocketClose(wsAlreadyClosed as unknown as WebSocket, 1006, ""));
		assert.doesNotThrow(() => doInstance.webSocketError(wsAlreadyClosed as unknown as WebSocket));
	});
});

describe("P1-5b: HTTP body size guard, MAX_MESSAGES_PER_CHANNEL & dead KV write removal", () => {
	it("rejects oversized streaming and Content-Length bodies with 413 before JSON.parse while preserving exact 64 KiB envelope check", async () => {
		const h = createDOHarness();
		const convId = "22".repeat(16);

		// 1. Streaming chunked body without Content-Length aborts early before reading all chunks
		let chunksRead = 0;
		const hugeStream = new ReadableStream<Uint8Array>({
			pull(controller) {
				chunksRead++;
				if (chunksRead > 20) {
					controller.close();
					return;
				}
				controller.enqueue(new Uint8Array(32 * 1024).fill(65));
			},
		});
		const streamRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/send", {
				method: "POST",
				body: hugeStream,
				// @ts-expect-error Node fetch duplex option for ReadableStream bodies
				duplex: "half",
			}),
			h.env,
		);
		assert.equal(streamRes.status, 413);
		assert.ok(chunksRead <= 4, `expected stream to abort early, read ${chunksRead} chunks`);

		// 2. Oversized announce body rejected with 413
		const bigAnnounceRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/announce/register", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pad: "x".repeat(20_000) }),
			}),
			h.env,
		);
		assert.equal(bigAnnounceRes.status, 413);

		// 3. Exact 65,536-byte decoded envelope succeeds (201), 65,537-byte fails (413) without writing QNTM_KV
		const exact64k = Buffer.alloc(65_536, 7).toString("base64");
		const okRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ conv_id: convId, envelope_b64: exact64k }),
			}),
			h.env,
		);
		assert.equal(okRes.status, 201);
		assert.equal(h.kvPutCalls, 0, "handlePublish must not perform dead QNTM_KV.put writes");

		const over64k = Buffer.alloc(65_537, 7).toString("base64");
		const overRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ conv_id: convId, envelope_b64: over64k }),
			}),
			h.env,
		);
		assert.equal(overRes.status, 413);
	});

	it("enforces MAX_MESSAGES_PER_CHANNEL by evicting oldest retained messages while keeping monotonic sequences", async () => {
		const h = createDOHarness({ MAX_MESSAGES_PER_CHANNEL: "3" });
		const convId = "33".repeat(16);

		for (let i = 1; i <= 5; i++) {
			const res = await worker.fetch(
				new Request("https://inbox.qntm.corpo.llc/v1/send", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						conv_id: convId,
						msg_id: i.toString(16).padStart(32, "0"),
						envelope_b64: Buffer.from(`msg-${i}`).toString("base64"),
					}),
				}),
				h.env,
			);
			assert.equal(res.status, 201);
			assert.deepEqual(await res.json(), { seq: i });
		}

		const rows = h.db.prepare("SELECT seq FROM messages ORDER BY seq").all() as Array<{ seq: number }>;
		assert.deepEqual(rows.map((r) => r.seq), [3, 4, 5]);
		const metaRows = h.db.prepare("SELECT seq FROM message_metadata ORDER BY seq").all() as Array<{ seq: number }>;
		assert.deepEqual(metaRows.map((r) => r.seq), [3, 4, 5]);
		assert.equal(maxMessagesPerChannel(""), 512);
		assert.throws(() => maxMessagesPerChannel("0"), /MAX_MESSAGES_PER_CHANNEL/);
	});
});

describe("P1-5c: RelayRateLimiter IPv6 /64 normalization, bounded eviction & /healthz exemption", () => {
	it("normalizes IPv6 addresses to canonical /64 prefixes while keeping IPv4-mapped addresses per-IPv4", () => {
		assert.equal(
			normalizeRateLimitClientKey("2001:db8:abcd:0012::1"),
			normalizeRateLimitClientKey("2001:0DB8:ABCD:12:ffff:ffff:ffff:ffff"),
		);
		assert.equal(
			normalizeRateLimitClientKey("[2001:db8:abcd:12::99]%eth0"),
			"2001:0db8:abcd:0012::/64",
		);
		assert.equal(normalizeRateLimitClientKey("::ffff:192.0.2.1"), "192.0.2.1");
		assert.notEqual(
			normalizeRateLimitClientKey("::ffff:192.0.2.1"),
			normalizeRateLimitClientKey("::ffff:198.51.100.2"),
		);

		let now = 1_000;
		const limiter = new RelayRateLimiter(() => now, 4);
		assert.equal(limiter.check("2001:db8:1:2::1", 2), true);
		assert.equal(limiter.check("2001:db8:1:2:dead:beef:cafe:1", 2), true);
		// Third request from the same /64 is rate-limited
		assert.equal(limiter.check("2001:0db8:0001:0002::9999", 2), false);
	});

	it("evicts oldest non-exhausted buckets at capacity instead of globally rejecting new IPs", () => {
		let now = 0;
		const limiter = new RelayRateLimiter(() => now, 3);
		// Exhaust attacker IP (count = 2)
		assert.equal(limiter.check("192.0.2.10", 2), true);
		assert.equal(limiter.check("192.0.2.10", 2), true);
		assert.equal(limiter.check("192.0.2.10", 2), false);

		// Fill remaining slots with 1-hit churn IPs
		assert.equal(limiter.check("192.0.2.11", 2), true);
		assert.equal(limiter.check("192.0.2.12", 2), true);
		assert.equal(limiter.size, 3);

		// New client IP must be admitted by evicting oldest churn IP (192.0.2.11), NOT globally rejected!
		assert.equal(limiter.check("198.51.100.50", 2), true);
		assert.equal(limiter.size, 3);
		// Exhausted attacker IP remains blocked!
		assert.equal(limiter.check("192.0.2.10", 2), false);

		// After window expires, expired entries purge cleanly
		now = RATE_LIMIT_WINDOW_MS;
		assert.equal(limiter.check("203.0.113.1", 2), true);
		assert.equal(limiter.size, 1);
		assert.equal(MAX_RATE_LIMIT_IPS, 10_000);
	});

	it("exempts GET /healthz from rate limiting even when the caller IP is rate-limited", async () => {
		const h = createDOHarness({ RATE_LIMIT_PER_MIN: "1" });
		const headers = { "CF-Connecting-IP": "198.51.100.77" };

		const r1 = await worker.fetch(new Request("https://inbox.qntm.corpo.llc/v1/poll", { method: "POST", headers }), h.env);
		assert.equal(r1.status, 410);
		const r2 = await worker.fetch(new Request("https://inbox.qntm.corpo.llc/v1/poll", { method: "POST", headers }), h.env);
		assert.equal(r2.status, 429);

		// /healthz still succeeds with 200
		const health = await worker.fetch(new Request("https://inbox.qntm.corpo.llc/healthz", { headers }), h.env);
		assert.equal(health.status, 200);
	});
});

describe("P2-7: message_metadata replay protection, /v1/announce/info deleted filter & canonical announceID", () => {
	it("does not overwrite seq or extend expires_at when duplicate msg_id is stored", async () => {
		const h = createDOHarness();
		const retention = new RelayRetention(h.storage as unknown as DurableObjectStorage, 60);
		const msgId = "aa".repeat(16);
		const t0 = 1_700_000_000_000;

		await retention.store(1, "first", msgId, t0);
		await retention.receipt(msgId, "bb".repeat(16), t0 + 1_000);

		// Duplicate msg_id submitted 30s later at seq 2 must NOT overwrite seq=1, expires_at, or readers
		await retention.store(2, "replayed", msgId, t0 + 30_000);
		assert.equal(await retention.messageSequence(msgId, t0 + 30_000), 1);
		const meta = h.db
			.prepare("SELECT seq, expires_at, readers_json FROM message_metadata WHERE msg_id = ?")
			.get(msgId) as { seq: number; expires_at: number; readers_json: string };
		assert.equal(meta.seq, 1);
		assert.equal(meta.expires_at, Math.floor(t0 / 1000) + 60);
		assert.deepEqual(JSON.parse(meta.readers_json), ["bb".repeat(16)]);
	});

	it("canonicalizes announceID across base64/padded variants and hides deleted/quarantined channels from /v1/announce/info", async () => {
		const h = createDOHarness();
		const master = generateIdentity();
		const posting = generateIdentity();
		const suite = new QSP1Suite();

		const canonicalMaster = base64UrlEncode(master.publicKey);
		const paddedStdBase64Master = Buffer.from(master.publicKey).toString("base64"); // includes '=' padding and/or '+/'
		const idCanonical = await announceID(canonicalMaster);
		const idPadded = await announceID(paddedStdBase64Master);
		assert.ok(idCanonical);
		assert.equal(idCanonical, idPadded);

		// Small-order identity key [1, 0, ..., 0] must return null
		const weakKey = new Uint8Array(32);
		weakKey[0] = 1;
		assert.equal(await announceID(base64UrlEncode(weakKey)), null);

		const sign = (text: string) =>
			Buffer.from(suite.sign(master.privateKey, suite.hash(new TextEncoder().encode(text)))).toString("hex");
		const postingB64 = base64UrlEncode(posting.publicKey);

		// Register using padded standard base64 master_pk — canonicalized under the hood
		const regRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/announce/register", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					name: "Releases",
					conv_id: idCanonical,
					master_pk: paddedStdBase64Master,
					posting_pk: postingB64,
					sig: sign(`qntm-announce-v1|register|Releases|${idCanonical}|${postingB64}`),
				}),
			}),
			h.env,
		);
		assert.equal(regRes.status, 201);

		// Active channel returns 200 on /v1/announce/info
		const infoBefore = await worker.fetch(
			new Request(`https://inbox.qntm.corpo.llc/v1/announce/info?conv_id=${idCanonical}`),
			h.env,
		);
		assert.equal(infoBefore.status, 200);

		// Delete channel using canonical master_pk
		const delRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/announce/delete", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					conv_id: idCanonical,
					master_pk: canonicalMaster,
					sig: sign(`qntm-announce-v1|delete|${idCanonical}`),
				}),
			}),
			h.env,
		);
		assert.equal(delRes.status, 200);

		// Deleted channel MUST return 404 on /v1/announce/info, while re-registration still returns 409
		const infoAfter = await worker.fetch(
			new Request(`https://inbox.qntm.corpo.llc/v1/announce/info?conv_id=${idCanonical}`),
			h.env,
		);
		assert.equal(infoAfter.status, 404);

		const reRegRes = await worker.fetch(
			new Request("https://inbox.qntm.corpo.llc/v1/announce/register", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					name: "Releases",
					conv_id: idCanonical,
					master_pk: canonicalMaster,
					posting_pk: postingB64,
					sig: sign(`qntm-announce-v1|register|Releases|${idCanonical}|${postingB64}`),
				}),
			}),
			h.env,
		);
		assert.equal(reRegRes.status, 409);

		// Legacy unbound/quarantined announcement in KV also returns 404 on /v1/announce/info
		const hLegacy = createDOHarness();
		const unboundId = "dd".repeat(16);
		hLegacy.externalKv.set(
			`/__announce__/${unboundId}/meta.json`,
			JSON.stringify({ name: "Legacy", conv_id: unboundId, master_pk: canonicalMaster, posting_pk: postingB64 }),
		);
		const legacyInfo = await worker.fetch(
			new Request(`https://inbox.qntm.corpo.llc/v1/announce/info?conv_id=${unboundId}`),
			hLegacy.env,
		);
		assert.equal(legacyInfo.status, 404);
	});
});
