import { MAX_RECEIPT_READERS, recordReceipt } from "./security-policy.js";

const DEFAULT_TTL_SECONDS = 604800;
const MIGRATION_BATCH_SIZE = 64;
export const STATS_KEY = "/__stats__/active_conversations";
export const STATS_TTL_SECONDS = 7 * 24 * 60 * 60;

/** Expires legacy activity keys even when the relay receives no new sends. */
export async function expireConversationStats(kv: KVNamespace, now = Date.now()): Promise<void> {
	const raw = await kv.get(STATS_KEY, "text");
	if (!raw) return;
	const cutoff = now - STATS_TTL_SECONDS * 1000;
	const stats: Record<string, number> = JSON.parse(raw);
	for (const [id, timestamp] of Object.entries(stats)) {
		if (!Number.isFinite(timestamp) || timestamp <= cutoff) delete stats[id];
	}
	const timestamps = Object.values(stats);
	if (!timestamps.length) {
		await kv.delete(STATS_KEY);
		return;
	}
	const latest = timestamps.reduce((maximum, timestamp) => Math.max(maximum, timestamp), 0);
	const remaining = Math.ceil((latest + STATS_TTL_SECONDS * 1000 - now) / 1000);
	await kv.put(STATS_KEY, JSON.stringify(stats), { expirationTtl: Math.max(60, remaining) });
}

export function envelopeTTLSeconds(value: string): number {
	if (!value) return DEFAULT_TTL_SECONDS;
	const ttl = Number(value);
	if (!Number.isSafeInteger(ttl) || ttl < 60) {
		throw new Error("ENVELOPE_TTL_SECONDS must be an integer of at least 60 seconds");
	}
	return ttl;
}

/** Expiry is assigned at publication, rather than extended by reads or receipts. */
export class RelayRetention {
	private initialized = false;
	private migrationPending = false;

	constructor(private storage: DurableObjectStorage, private ttl: number) {}

	private initialize(): void {
		if (this.initialized) return;
		this.storage.transactionSync(() => {
			this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS messages (
				seq INTEGER PRIMARY KEY, envelope_b64 TEXT NOT NULL,
				created_at INTEGER NOT NULL DEFAULT (unixepoch()), expires_at INTEGER
			)`);
			const columns = this.storage.sql.exec<{ name: string }>("PRAGMA table_info(messages)").toArray();
			if (!columns.some((column) => column.name === "expires_at")) {
				this.storage.sql.exec("ALTER TABLE messages ADD COLUMN expires_at INTEGER");
			}
			this.storage.sql.exec("UPDATE messages SET expires_at = created_at + ? WHERE expires_at IS NULL", this.ttl);
			this.storage.sql.exec("CREATE INDEX IF NOT EXISTS messages_expiry ON messages (expires_at)");
			this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS message_metadata (
				msg_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, expires_at INTEGER NOT NULL,
				readers_json TEXT NOT NULL DEFAULT '[]'
			)`);
			this.storage.sql.exec("CREATE INDEX IF NOT EXISTS message_metadata_expiry ON message_metadata (expires_at)");
		});
		this.initialized = true;
	}

	private async migrateMessage(msgID: string): Promise<void> {
		const indexKey = `msg-seq:${msgID}`;
		const receiptKey = `receipt-readers:${msgID}`;
		const seq = await this.storage.get<number>(indexKey);
		if (typeof seq !== "number") return;
		const row = this.storage.sql.exec<{ expires_at: number }>(
			"SELECT expires_at FROM messages WHERE seq = ?", seq,
		).toArray()[0];
		if (row) {
			const readers = await this.storage.get<string[]>(receiptKey) ?? [];
			this.storage.sql.exec(
				"INSERT OR IGNORE INTO message_metadata (msg_id, seq, expires_at, readers_json) VALUES (?, ?, ?, ?)",
				msgID, seq, row.expires_at, JSON.stringify(readers.slice(0, MAX_RECEIPT_READERS)),
			);
		}
		await this.storage.delete([indexKey, receiptKey]);
	}

	/** Bounded migration; alarms continue it even when the channel becomes idle. */
	private async migrateLegacyMetadata(): Promise<boolean> {
		const indices = await this.storage.list<number>({ prefix: "msg-seq:", limit: MIGRATION_BATCH_SIZE });
		for (const [key] of indices) await this.migrateMessage(key.slice("msg-seq:".length));
		if (indices.size === MIGRATION_BATCH_SIZE) return true;
		// Once no old indices remain, unmatched receipt records are stale orphans.
		const orphans = await this.storage.list({ prefix: "receipt-readers:", limit: MIGRATION_BATCH_SIZE });
		if (orphans.size) await this.storage.delete([...orphans.keys()]);
		return orphans.size === MIGRATION_BATCH_SIZE;
	}

	private async schedule(now: number): Promise<void> {
		const row = this.storage.sql.exec<{ next_expiry: number | null }>(`
			SELECT MIN(next_expiry) AS next_expiry FROM (
				SELECT MIN(expires_at) AS next_expiry FROM messages
				UNION ALL SELECT MIN(expires_at) AS next_expiry FROM message_metadata
			)
		`).toArray()[0];
		let next = row?.next_expiry == null ? null : Math.max(now + 1, row.next_expiry * 1000);
		if (this.migrationPending) next = Math.min(next ?? Infinity, now + 1000);
		const current = await this.storage.getAlarm();
		if (next === null) {
			if (current !== null) await this.storage.deleteAlarm();
		} else if (current === null || current > next) {
			await this.storage.setAlarm(next);
		}
	}

	async maintain(now = Date.now()): Promise<void> {
		this.initialize();
		this.migrationPending = await this.migrateLegacyMetadata();
		const nowSeconds = Math.floor(now / 1000);
		this.storage.transactionSync(() => {
			this.storage.sql.exec("DELETE FROM messages WHERE expires_at <= ?", nowSeconds);
			this.storage.sql.exec("DELETE FROM message_metadata WHERE expires_at <= ?", nowSeconds);
		});
		await this.schedule(now);
	}

	async store(seq: number, envelope: string, msgID: string | undefined, now = Date.now(), onStored?: () => void): Promise<void> {
		this.initialize();
		const created = Math.floor(now / 1000);
		this.storage.transactionSync(() => {
			this.storage.sql.exec(
				"INSERT INTO messages (seq, envelope_b64, created_at, expires_at) VALUES (?, ?, ?, ?)",
				seq, envelope, created, created + this.ttl,
			);
			if (msgID) this.storage.sql.exec(
				`INSERT INTO message_metadata (msg_id, seq, expires_at) VALUES (?, ?, ?)
				 ON CONFLICT(msg_id) DO UPDATE SET seq = excluded.seq, expires_at = excluded.expires_at`,
				msgID, seq, created + this.ttl,
			);
			onStored?.();
		});
		await this.schedule(now);
	}

	/** Reads independently enforce expiry if an alarm is delayed or has exhausted retries. */
	messages(fromSeq: number, headSeq: number, limit: number, now = Date.now()): Array<{ seq: number; envelope_b64: string }> {
		this.initialize();
		return this.storage.sql.exec<{ seq: number; envelope_b64: string }>(
			"SELECT seq, envelope_b64 FROM messages WHERE seq > ? AND seq <= ? AND expires_at > ? ORDER BY seq LIMIT ?",
			fromSeq, headSeq, Math.floor(now / 1000), limit,
		).toArray();
	}

	/** Replay a fixed head using bounded pages, including after expired sequence gaps. */
	*replay(fromSeq: number, headSeq: number, now = Date.now()): Generator<{ seq: number; envelope_b64: string }> {
		let cursor = fromSeq;
		while (cursor < headSeq) {
			const page = this.messages(cursor, headSeq, 128, now);
			if (!page.length) return;
			yield* page;
			cursor = page[page.length - 1].seq;
		}
	}

	async messageSequence(msgID: string, now = Date.now()): Promise<number | null> {
		this.initialize();
		await this.migrateMessage(msgID);
		const row = this.storage.sql.exec<{ seq: number }>(
			"SELECT seq FROM message_metadata WHERE msg_id = ? AND expires_at > ?", msgID, Math.floor(now / 1000),
		).toArray()[0];
		return row?.seq ?? null;
	}

	async receipt(msgID: string, readerKID: string, now = Date.now()): Promise<ReturnType<typeof recordReceipt> | null> {
		this.initialize();
		await this.migrateMessage(msgID);
		const row = this.storage.sql.exec<{ readers_json: string }>(
			"SELECT readers_json FROM message_metadata WHERE msg_id = ? AND expires_at > ?", msgID, Math.floor(now / 1000),
		).toArray()[0];
		if (!row) return null;
		const result = recordReceipt(JSON.parse(row.readers_json), readerKID);
		this.storage.sql.exec("UPDATE message_metadata SET readers_json = ? WHERE msg_id = ?", JSON.stringify(result.readers), msgID);
		return result;
	}
}
