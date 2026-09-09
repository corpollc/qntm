import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { envelopeTTLSeconds, expireConversationStats, RelayRetention, STATS_KEY, STATS_TTL_SECONDS } from '../worker/src/retention.js';

// Real SQLite exercises the schema migration, expiry comparisons, and queries.
// Only the Cloudflare key-value/alarm transport is replaced by an in-memory shim.
const databases: DatabaseSync[] = [];
const START = Date.UTC(2026, 8, 9);
const MSG_A = 'aa'.repeat(16);
const MSG_B = 'bb'.repeat(16);

function fixture(ttl = 60) {
  const db = new DatabaseSync(':memory:');
  databases.push(db);
  const kv = new Map<string, unknown>();
  let alarm: number | null = null;
  const storage = {
    sql: {
      exec(query: string, ...bindings: (string | number)[]) {
        const rows = db.prepare(query).all(...bindings);
        return { toArray: () => rows };
      },
    },
    transactionSync<T>(action: () => T): T {
      db.exec('BEGIN');
      try {
        const result = action();
        db.exec('COMMIT');
        return result;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    async get(key: string) { return kv.get(key); },
    async delete(keys: string | string[]) {
      for (const key of typeof keys === 'string' ? [keys] : keys) kv.delete(key);
    },
    async list({ prefix, limit }: { prefix: string; limit: number }) {
      return new Map([...kv.entries()].filter(([key]) => key.startsWith(prefix)).sort().slice(0, limit));
    },
    async getAlarm() { return alarm; },
    async setAlarm(value: number) { alarm = value; },
    async deleteAlarm() { alarm = null; },
  };
  const retention = new RelayRetention(storage as unknown as DurableObjectStorage, ttl);
  return {
    db, kv, storage, retention,
    get alarm() { return alarm; },
    async fireAlarm(at: number) {
      // Cloudflare consumes the scheduled alarm before calling the handler.
      alarm = null;
      await retention.maintain(at);
    },
  };
}

afterEach(() => { for (const db of databases.splice(0)) db.close(); });

describe('relay retention', () => {
  it('replays beyond expired gaps and multiple pages without skipping the captured head', async () => {
    const f = fixture();
    await f.retention.store(1, 'expired', MSG_A, START - 60_000);
    for (let seq = 4001; seq <= 5105; seq++) {
      await f.retention.store(seq, String(seq), undefined, START);
    }
    const page = f.retention.messages(0, 5104, 128, START);
    expect(page).toHaveLength(128);
    expect(page[0].seq).toBe(4001);
    const replay = [...f.retention.replay(0, 5104, START)];
    expect(replay.map(row => row.seq)).toEqual(Array.from({ length: 1104 }, (_, i) => 4001 + i));
    expect([...f.retention.replay(5104, 5105, START)]).toEqual([{ seq: 5105, envelope_b64: '5105' }]);
  });

  it('cleans envelopes and receipt identities while idle, preserving sequence continuity', async () => {
    const f = fixture();
    f.kv.set('next_seq', 1);
    await f.retention.maintain(START);
    await f.retention.store(1, 'first-ciphertext', MSG_A, START);
    expect(f.alarm).toBe(START + 60_000);
    expect(await f.retention.receipt(MSG_A, 'reader-key', START + 1)).toMatchObject({ receipts: 1 });

    await f.fireAlarm(START + 60_000);
    expect(f.db.prepare('SELECT * FROM messages').all()).toEqual([]);
    expect(f.db.prepare('SELECT * FROM message_metadata').all()).toEqual([]);
    expect(f.alarm).toBeNull();
    expect(f.kv.get('next_seq')).toBe(1);
    await f.retention.store(2, 'next-ciphertext', MSG_B, START + 60_000);
    expect(f.retention.messages(0, 2, 1000, START + 60_000)).toEqual([{ seq: 2, envelope_b64: 'next-ciphertext' }]);
  });

  it('filters expired replay and refuses expired receipt lookup even before a delayed alarm', async () => {
    const f = fixture();
    await f.retention.store(1, 'expired-ciphertext', MSG_A, START);
    await f.retention.store(2, 'live-ciphertext', MSG_B, START + 30_000);
    expect(f.alarm).toBe(START + 60_000); // A later publish does not postpone older expiry.
    expect(f.retention.messages(0, 2, 1000, START + 59_999)).toHaveLength(2);
    expect(f.retention.messages(0, 2, 1000, START + 60_000)).toEqual([{ seq: 2, envelope_b64: 'live-ciphertext' }]);
    expect(await f.retention.messageSequence(MSG_A, START + 60_000)).toBeNull();
    expect(await f.retention.receipt(MSG_A, 'reader', START + 60_000)).toBeNull();
    expect(await f.retention.messageSequence(MSG_B, START + 60_000)).toBe(2);
    await f.fireAlarm(START + 60_000);
    expect(f.alarm).toBe(START + 90_000);
  });

  it('does not extend retention through reads or receipts', async () => {
    const f = fixture();
    await f.retention.store(1, 'ciphertext', MSG_A, START);
    expect(await f.retention.receipt(MSG_A, 'reader', START + 59_000)).toMatchObject({ receipts: 1, shouldDelete: false });
    expect(await f.retention.receipt(MSG_A, 'reader', START + 59_001)).toMatchObject({ receipts: 1 });
    f.retention.messages(0, 1, 1000, START + 59_500);
    expect(f.alarm).toBe(START + 60_000);
    await f.fireAlarm(START + 60_000);
    expect(await f.retention.messageSequence(MSG_A, START + 60_000)).toBeNull();
  });

  it('migrates legacy tables and deletes old index/receipt keys, including already orphaned entries', async () => {
    const f = fixture();
    f.db.exec('CREATE TABLE messages (seq INTEGER PRIMARY KEY, envelope_b64 TEXT NOT NULL, created_at INTEGER NOT NULL)');
    const insert = f.db.prepare('INSERT INTO messages VALUES (?, ?, ?)');
    insert.run(1, 'expired', START / 1000 - 60);
    insert.run(2, 'live', START / 1000 - 30);
    f.kv.set(`msg-seq:${MSG_A}`, 1);
    f.kv.set(`receipt-readers:${MSG_A}`, ['expired-reader']);
    f.kv.set(`msg-seq:${MSG_B}`, 2);
    f.kv.set(`receipt-readers:${MSG_B}`, ['live-reader']);
    f.kv.set('msg-seq:already-purged', 99);
    f.kv.set('receipt-readers:already-purged', ['orphan-reader']);
    f.kv.set('receipt-readers:unmatched', ['another-reader']);
    await f.retention.maintain(START);
    expect(f.kv.size).toBe(0);
    expect(f.retention.messages(0, 2, 1000, START)).toEqual([{ seq: 2, envelope_b64: 'live' }]);
    expect(await f.retention.receipt(MSG_B, 'live-reader', START)).toMatchObject({ receipts: 1 });
    expect(f.alarm).toBe(START + 30_000);
    await f.fireAlarm(START + 30_000);
    expect(f.db.prepare('SELECT * FROM message_metadata').all()).toEqual([]);
  });

  it('continues a bounded legacy metadata migration by alarm without further traffic', async () => {
    const f = fixture();
    f.db.exec('CREATE TABLE messages (seq INTEGER PRIMARY KEY, envelope_b64 TEXT NOT NULL, created_at INTEGER NOT NULL)');
    const insert = f.db.prepare('INSERT INTO messages VALUES (?, ?, ?)');
    for (let n = 1; n <= 70; n++) {
      insert.run(n, 'ciphertext', START / 1000);
      f.kv.set(`msg-seq:${n.toString(16).padStart(32, '0')}`, n);
    }
    await f.retention.maintain(START);
    expect(f.kv.size).toBe(6);
    expect(f.alarm).toBe(START + 1000);
    // Lazy lookup also handles a legacy index beyond the first migration batch.
    expect(await f.retention.messageSequence((70).toString(16).padStart(32, '0'), START)).toBe(70);
    await f.fireAlarm(START + 1000);
    expect(f.kv.size).toBe(0);
    expect(f.alarm).toBe(START + 60_000);
  });

  it('keeps assigned expiry across a configuration change and object restart', async () => {
    const f = fixture();
    await f.retention.store(1, 'ciphertext', MSG_A, START);
    const restarted = new RelayRetention(f.storage as unknown as DurableObjectStorage, 604800);
    await restarted.maintain(START + 30_000);
    expect(f.alarm).toBe(START + 60_000);
    await restarted.maintain(START + 60_000);
    expect(restarted.messages(0, 1, 1000, START + 60_000)).toEqual([]);
  });

  it('rejects invalid retention settings rather than silently extending or disabling expiry', () => {
    expect(envelopeTTLSeconds('')).toBe(604800);
    expect(envelopeTTLSeconds('60')).toBe(60);
    for (const value of ['0', '-1', '59', '600foo', '1.5', 'Infinity', 'NaN']) {
      expect(() => envelopeTTLSeconds(value)).toThrow('ENVELOPE_TTL_SECONDS');
    }
  });
});

describe('relay aggregate activity retention', () => {
  function statsFixture(stats: Record<string, number>) {
    let value: string | null = JSON.stringify(stats);
    let ttl: number | undefined;
    const kv = {
      async get(key: string) { expect(key).toBe(STATS_KEY); return value; },
      async put(key: string, next: string, options: { expirationTtl: number }) {
        expect(key).toBe(STATS_KEY); value = next; ttl = options.expirationTtl;
      },
      async delete(key: string) { expect(key).toBe(STATS_KEY); value = null; },
    };
    return { kv, get value() { return value; }, get ttl() { return ttl; } };
  }

  it('deletes an idle legacy stats key when all channel timestamps have expired', async () => {
    const f = statsFixture({ expiredChannel: START - STATS_TTL_SECONDS * 1000 });
    await expireConversationStats(f.kv as unknown as KVNamespace, START);
    expect(f.value).toBeNull();
  });

  it('drops stale channel IDs without restarting the lifetime of remaining activity', async () => {
    const f = statsFixture({ expiredChannel: START - STATS_TTL_SECONDS * 1000, activeChannel: START - 30_000 });
    await expireConversationStats(f.kv as unknown as KVNamespace, START);
    expect(JSON.parse(f.value!)).toEqual({ activeChannel: START - 30_000 });
    expect(f.ttl).toBe(STATS_TTL_SECONDS - 30);
  });

  it('uses the KV minimum TTL when the last activity is about to expire', async () => {
    const f = statsFixture({ channel: START - STATS_TTL_SECONDS * 1000 + 10_000 });
    await expireConversationStats(f.kv as unknown as KVNamespace, START);
    expect(f.ttl).toBe(60);
  });
});
