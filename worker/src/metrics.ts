/** Aggregate relay telemetry. No payload, participant key, address or IP is stored. */
export const METRICS_WINDOW_MS = 7 * 86400_000;
export const METRICS_BATCH_SIZE = 64;

export type RelayMetricEvent = {
	id: string;
	conv_id: string;
	posted_at: number;
	envelope_bytes: number;
	traffic: "application" | "probe";
};

export function validMetricEvent(value: unknown): value is RelayMetricEvent {
	if (!value || typeof value !== "object") return false;
	const e = value as RelayMetricEvent;
	return typeof e.id === "string" && /^[0-9a-f-]{36}$/.test(e.id)
		&& typeof e.conv_id === "string" && /^[0-9a-f]{32}$/.test(e.conv_id)
		&& Number.isSafeInteger(e.posted_at) && e.posted_at > 0
		&& Number.isSafeInteger(e.envelope_bytes) && e.envelope_bytes >= 0
		&& (e.traffic === "application" || e.traffic === "probe");
}

/** Stored in the same transaction as the envelope; delivery retries are idempotent. */
export class RelayMetricsOutbox {
	constructor(private storage: DurableObjectStorage) {
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS metrics_outbox (
			id TEXT PRIMARY KEY, conv_id TEXT NOT NULL, posted_at INTEGER NOT NULL,
			envelope_bytes INTEGER NOT NULL, traffic TEXT NOT NULL
		)`);
		storage.sql.exec("CREATE INDEX IF NOT EXISTS metrics_outbox_time ON metrics_outbox(posted_at)");
	}

	enqueue(event: RelayMetricEvent): void {
		this.storage.sql.exec("INSERT INTO metrics_outbox VALUES (?, ?, ?, ?, ?)",
			event.id, event.conv_id, event.posted_at, event.envelope_bytes, event.traffic);
	}

	pending(now = Date.now()): RelayMetricEvent[] {
		this.storage.sql.exec("DELETE FROM metrics_outbox WHERE posted_at <= ?", now - METRICS_WINDOW_MS);
		return this.storage.sql.exec<RelayMetricEvent>(
			"SELECT * FROM metrics_outbox ORDER BY posted_at LIMIT ?", METRICS_BATCH_SIZE,
		).toArray();
	}

	acknowledge(events: RelayMetricEvent[]): void {
		this.storage.transactionSync(() => {
			for (const event of events) this.storage.sql.exec("DELETE FROM metrics_outbox WHERE id = ?", event.id);
		});
	}
}

export class RelayMetricsStore {
	constructor(private storage: DurableObjectStorage, now = Date.now()) {
		storage.transactionSync(() => {
			storage.sql.exec(`CREATE TABLE IF NOT EXISTS relay_events (
				id TEXT PRIMARY KEY, conv_id TEXT NOT NULL, posted_at INTEGER NOT NULL,
				envelope_bytes INTEGER NOT NULL, traffic TEXT NOT NULL
			)`);
			storage.sql.exec("CREATE INDEX IF NOT EXISTS relay_events_time ON relay_events(posted_at)");
			storage.sql.exec(`CREATE TABLE IF NOT EXISTS relay_totals (
				traffic TEXT PRIMARY KEY, messages INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0
			)`);
			storage.sql.exec("INSERT OR IGNORE INTO relay_totals(traffic) VALUES ('application'), ('probe')");
			storage.sql.exec("CREATE TABLE IF NOT EXISTS relay_measurement (id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL)");
			storage.sql.exec("INSERT OR IGNORE INTO relay_measurement VALUES (1, ?)", now);
		});
	}

	record(events: RelayMetricEvent[], now = Date.now()): void {
		if (events.length > METRICS_BATCH_SIZE || !events.every(validMetricEvent)) throw new Error("invalid telemetry batch");
		if (events.some(e => e.posted_at > now + 60_000)) throw new Error("future telemetry timestamp");
		this.storage.transactionSync(() => {
			for (const e of events) {
				// Reject old deliveries even after their deduplication records have expired.
				if (e.posted_at <= now - METRICS_WINDOW_MS) continue;
				const inserted = this.storage.sql.exec<{ id: string }>(
					"INSERT OR IGNORE INTO relay_events VALUES (?, ?, ?, ?, ?) RETURNING id",
					e.id, e.conv_id, e.posted_at, e.envelope_bytes, e.traffic,
				).toArray();
				if (inserted.length) this.storage.sql.exec(
					"UPDATE relay_totals SET messages = messages + 1, bytes = bytes + ? WHERE traffic = ?",
					e.envelope_bytes, e.traffic,
				);
			}
		});
	}

	async maintain(now = Date.now()): Promise<void> {
		this.storage.sql.exec("DELETE FROM relay_events WHERE posted_at <= ?", now - METRICS_WINDOW_MS);
		const next = this.storage.sql.exec<{ at: number | null }>(
			"SELECT MIN(posted_at) + ? AS at FROM relay_events", METRICS_WINDOW_MS,
		).toArray()[0]?.at;
		const alarm = await this.storage.getAlarm();
		if (next == null) {
			if (alarm !== null) await this.storage.deleteAlarm();
		} else if (alarm === null || alarm > next) await this.storage.setAlarm(Math.max(now + 1, next));
	}

	snapshot(now = Date.now()) {
		const totals = this.storage.sql.exec<{ traffic: string; messages: number; bytes: number }>("SELECT * FROM relay_totals ORDER BY traffic").toArray();
		return {
			measurement_started_at: this.storage.sql.exec<{ started_at: number }>("SELECT started_at FROM relay_measurement WHERE id = 1").toArray()[0].started_at,
			measured_at: now,
			traffic: totals.map(total => ({
				...total,
				...this.storage.sql.exec<{ messages_24h: number; messages_7d: number; active_conversations_24h: number; active_conversations_7d: number }>(`
					SELECT COALESCE(SUM(posted_at > ?), 0) AS messages_24h, COUNT(*) AS messages_7d,
					COUNT(DISTINCT CASE WHEN posted_at > ? THEN conv_id END) AS active_conversations_24h,
					COUNT(DISTINCT conv_id) AS active_conversations_7d
					FROM relay_events WHERE traffic = ? AND posted_at > ?`,
					now - 86400_000, now - 86400_000, total.traffic, now - METRICS_WINDOW_MS,
				).toArray()[0],
			})),
		};
	}
}
