import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { RelayMetricsStore, RelayMetricsOutbox, METRICS_WINDOW_MS, type RelayMetricEvent } from '../worker/src/metrics.js';
import { RelayRetention } from '../worker/src/retention.js';

const NOW = Date.UTC(2026, 8, 9);
const databases: DatabaseSync[] = [];
function fixture() {
  const db = new DatabaseSync(':memory:');
  databases.push(db);
  let alarm: number | null = null;
  const storage = {
    sql: { exec(sql: string, ...bindings: (number | string)[]) {
      const rows = db.prepare(sql).all(...bindings);
      return { toArray: () => rows };
    } },
    transactionSync<T>(action: () => T) {
      db.exec('BEGIN');
      try { const result = action(); db.exec('COMMIT'); return result; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    async getAlarm() { return alarm; },
    async setAlarm(at: number) { alarm = at; },
    async deleteAlarm() { alarm = null; },
  } as unknown as DurableObjectStorage;
  return { db, storage, get alarm() { return alarm; } };
}
function event(overrides: Partial<RelayMetricEvent> = {}): RelayMetricEvent {
  return { id: randomUUID(), conv_id: 'aa'.repeat(16), posted_at: NOW,
    envelope_bytes: 100, traffic: 'application', ...overrides };
}
afterEach(() => { for (const db of databases.splice(0)) db.close(); });

describe('durable aggregate relay telemetry', () => {
  it('counts postings and distinct active conversations, deduplicating overlapping retries', () => {
    const f = fixture(), store = new RelayMetricsStore(f.storage, NOW);
    const events = Array.from({ length: 50 }, (_, i) => event({ conv_id: i.toString(16).padStart(32, '0') }));
    store.record(events.slice(25), NOW);
    store.record(events, NOW); // includes a retry of the first delivered batch
    store.record([event({ conv_id: events[0].conv_id })], NOW);
    const row = store.snapshot(NOW).traffic[0];
    expect(row).toMatchObject({ messages: 51, bytes: 5100, messages_24h: 51, active_conversations_7d: 50 });
    expect(JSON.stringify(store.snapshot(NOW))).not.toContain(events[0].conv_id);
  });

  it('keeps lifetime aggregate totals after expiry, never resurrecting expired retry records', async () => {
    const f = fixture(), store = new RelayMetricsStore(f.storage, NOW);
    const a = event(), b = event({ posted_at: NOW + 86400_000 });
    store.record([a], NOW);
    store.record([b], b.posted_at);
    await store.maintain(b.posted_at);
    expect(f.alarm).toBe(NOW + METRICS_WINDOW_MS);
    const restarted = new RelayMetricsStore(f.storage, b.posted_at);
    expect(restarted.snapshot(b.posted_at).traffic[0]).toMatchObject({ messages_24h: 1, messages_7d: 2 });
    const later = NOW + METRICS_WINDOW_MS + 86400_000;
    await restarted.maintain(later);
    expect(f.db.prepare('SELECT * FROM relay_events').all()).toEqual([]);
    expect(f.alarm).toBeNull();
    restarted.record([a, b], later);
    expect(restarted.snapshot(later).traffic[0]).toMatchObject({ messages: 2, messages_7d: 0, active_conversations_7d: 0 });
    expect(restarted.snapshot(later).measurement_started_at).toBe(NOW);
  });

  it('separates probe traffic and applies rolling windows without relying on alarms', () => {
    const f = fixture(), store = new RelayMetricsStore(f.storage, NOW);
    store.record([event(), event({ traffic: 'probe', conv_id: 'bb'.repeat(16) })], NOW);
    expect(store.snapshot(NOW).traffic.map(x => x.messages)).toEqual([1, 1]);
    expect(store.snapshot(NOW + METRICS_WINDOW_MS).traffic.map(x => x.active_conversations_7d)).toEqual([0, 0]);
  });

  it('rejects malformed and future batches atomically', () => {
    const f = fixture(), store = new RelayMetricsStore(f.storage, NOW);
    expect(() => store.record([event(), event({ envelope_bytes: -1 })], NOW)).toThrow();
    expect(() => store.record([event({ posted_at: NOW + 60_001 })], NOW)).toThrow();
    expect(() => store.record(Array.from({ length: 65 }, () => event()), NOW)).toThrow();
    expect(store.snapshot(NOW).traffic[0].messages).toBe(0);
  });

  it('commits the outbox with ciphertext and rolls both back on a failed transaction', async () => {
    const f = fixture(), outbox = new RelayMetricsOutbox(f.storage), retention = new RelayRetention(f.storage, 60);
    await expect(retention.store(1, 'ciphertext', undefined, NOW, () => {
      outbox.enqueue(event());
      throw new Error('simulated write failure');
    })).rejects.toThrow('simulated write failure');
    expect(f.db.prepare('SELECT * FROM messages').all()).toEqual([]);
    expect(outbox.pending(NOW)).toEqual([]);
    await retention.store(1, 'ciphertext', undefined, NOW, () => outbox.enqueue(event()));
    const pending = new RelayMetricsOutbox(f.storage).pending(NOW);
    expect(pending).toHaveLength(1);
    const aggregate = new RelayMetricsStore(fixture().storage, NOW);
    aggregate.record(pending, NOW);
    aggregate.record(pending, NOW); // destination committed, acknowledgement lost
    expect(aggregate.snapshot(NOW).traffic[0].messages).toBe(1);
    outbox.acknowledge(pending);
    expect(outbox.pending(NOW)).toEqual([]);
  });

  it('bounds recovery batches and expires metadata after seven days', () => {
    const f = fixture(), outbox = new RelayMetricsOutbox(f.storage);
    for (let i = 0; i < 100; i++) outbox.enqueue(event());
    const batch = outbox.pending(NOW);
    expect(batch).toHaveLength(64);
    outbox.acknowledge(batch);
    expect(outbox.pending(NOW)).toHaveLength(36);
    expect(outbox.pending(NOW + METRICS_WINDOW_MS)).toEqual([]);
  });
});
