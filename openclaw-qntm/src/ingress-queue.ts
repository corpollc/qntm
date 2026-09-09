import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { normalizeAccountId } from 'openclaw/plugin-sdk/account-id';
import { resolveStateDir } from 'openclaw/plugin-sdk/state-paths';
import type { ChannelIngressQueue, ChannelIngressQueueClaimRef } from 'openclaw/plugin-sdk/channel-outbound';
import { inboundId, validateInbound, type QntmInbound } from './checkpoint.js';

export type IngressPayload = { version: number; body: QntmInbound };
type Queue = ChannelIngressQueue<IngressPayload>;
type Options<K extends keyof Queue> = Parameters<NonNullable<Queue[K]>>[1];
type Ref = string | ChannelIngressQueueClaimRef;
type Row = {
  id: string; status: 'pending' | 'claimed' | 'completed' | 'failed';
  payload: string | null; metadata: string | null; received_at: number; updated_at: number;
  lane_key: string | null; attempts: number; last_attempt_at: number | null;
  last_error: string | null; token: string | null; owner_id: string | null;
  claimed_at: number | null; completed_at: number | null; failed_at: number | null;
  reason: string | null; message: string | null;
};

/** Plugin-owned storage; never opens OpenClaw's privileged shared state database. */
export class QntmIngressQueue implements Queue {
  readonly filename: string;
  private readonly db: DatabaseSync;
  private readonly accountId: string;
  private readonly now: () => number;
  constructor(accountId: string, options: { stateDir?: string; now?: () => number; maxPending?: number } = {}) {
    this.accountId = normalizeAccountId(accountId);
    this.now = options.now ?? Date.now;
    this.maxPending = options.maxPending ?? 1024;
    this.filename = path.join(options.stateDir ?? resolveStateDir(), 'plugins', 'qntm', 'accounts', this.accountId, 'ingress.sqlite');
    const directory = path.dirname(this.filename);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(directory, 0o700);
    try { fs.closeSync(fs.openSync(this.filename, 'wx', 0o600)); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    if (!fs.lstatSync(this.filename).isFile()) throw new Error('qntm ingress database must be a regular file');
    fs.chmodSync(this.filename, 0o600);
    this.db = new DatabaseSync(this.filename);
    try {
      this.db.exec('PRAGMA busy_timeout=2000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA max_page_count=65536;');
      const version = this.db.prepare('PRAGMA user_version').get()?.user_version;
      if (version !== 0 && version !== 1) throw new Error('Unsupported qntm ingress database version');
      this.db.exec(`CREATE TABLE IF NOT EXISTS ingress (
        ordinal INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('pending','claimed','completed','failed')),
        payload TEXT, metadata TEXT, received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        lane_key TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_attempt_at INTEGER, last_error TEXT,
        token TEXT, owner_id TEXT, claimed_at INTEGER, completed_at INTEGER, failed_at INTEGER,
        reason TEXT, message TEXT
      ); CREATE INDEX IF NOT EXISTS ingress_status ON ingress(status, received_at, ordinal);
      PRAGMA user_version=1;`);
    } catch (error) { this.db.close(); throw error; }
  }
  private readonly maxPending: number;
  close(): void { this.db.close(); }
  private transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); this.db.exec('COMMIT'); return value; }
    catch (error) {
      // SQLITE_FULL can roll back a transaction itself. Preserve the original
      // failure instead of replacing it with "no transaction is active".
      try { this.db.exec('ROLLBACK'); } catch { /* already rolled back */ }
      throw error;
    }
  }
  private get(id: string): Row | undefined {
    return this.db.prepare('SELECT * FROM ingress WHERE id=?').get(id) as Row | undefined;
  }
  private scope(id: string) { return { id, channelId: 'qntm', accountId: this.accountId, queueName: 'ingress' }; }
  private record(row: Row) {
    let payload: IngressPayload;
    let metadata: unknown;
    try {
      const parsed = JSON.parse(row.payload!);
      if (parsed.version !== 1) throw new Error();
      payload = { version: 1, body: validateInbound(parsed.body) };
      if (inboundId(payload.body) !== row.id) throw new Error();
      metadata = row.metadata === null ? undefined : JSON.parse(row.metadata);
    } catch { throw new Error('Invalid persisted qntm ingress record'); }
    return { ...this.scope(row.id), payload, metadata, receivedAt: row.received_at,
      updatedAt: row.updated_at, laneKey: row.lane_key ?? undefined, attempts: row.attempts,
      lastAttemptAt: row.last_attempt_at ?? undefined, lastError: row.last_error ?? undefined };
  }
  private claimed(row: Row) {
    if (!row.token || !row.owner_id || row.claimed_at === null) throw new Error('Invalid qntm ingress claim');
    return { ...this.record(row), claim: { token: row.token, ownerId: row.owner_id, claimedAt: row.claimed_at } };
  }
  private completed(row: Row) {
    return { ...this.scope(row.id), completedAt: row.completed_at!,
      metadata: row.metadata === null ? undefined : JSON.parse(row.metadata) as unknown };
  }
  private failed(row: Row) {
    return { ...this.scope(row.id), failedAt: row.failed_at!, reason: row.reason!, message: row.message ?? undefined };
  }
  private matches(row: Row | undefined, ref: Ref): row is Row {
    return !!row && (typeof ref === 'string' || (row.status === 'claimed' && row.token === ref.claim.token));
  }
  private rows(status: string, orderBy = 'received', limit: number | 'all' = 'all'): Row[] {
    const order = orderBy === 'id' ? 'id' : 'received_at, ordinal';
    return this.db.prepare(`SELECT * FROM ingress WHERE status=? ORDER BY ${order} LIMIT ?`)
      .all(status, limit === 'all' ? -1 : Math.max(0, Math.floor(limit))) as Row[];
  }
  async enqueue(id: string, payload: IngressPayload, options: Parameters<Queue['enqueue']>[2] = {}) {
    return this.transaction(() => {
      const existing = this.get(id);
      if (existing) {
        switch (existing.status) {
          case 'completed': return { kind: 'completed', duplicate: true, record: this.completed(existing) } as const;
          case 'failed': return { kind: 'failed', duplicate: true, record: this.failed(existing) } as const;
          case 'claimed': return { kind: 'claimed', duplicate: true, record: this.claimed(existing) } as const;
          case 'pending': return { kind: 'pending', duplicate: true, record: this.record(existing) } as const;
        }
      }
      const body = validateInbound(payload.body);
      if (payload.version !== 1 || id !== inboundId(body)) throw new Error('Invalid qntm ingress event');
      const count = this.db.prepare("SELECT count(*) AS n FROM ingress WHERE status IN ('pending','claimed')").get()!.n as number;
      if (count >= this.maxPending) throw new Error('qntm host ingress queue is full');
      const now = this.now();
      this.db.prepare(`INSERT INTO ingress(id,status,payload,metadata,received_at,updated_at,lane_key)
        VALUES(?,'pending',?,?,?,?,?)`).run(id, JSON.stringify({ version: 1, body }),
        options.metadata === undefined ? null : JSON.stringify(options.metadata), options.receivedAt ?? now, now,
        options.laneKey ?? body.conversationId);
      return { kind: 'accepted', duplicate: false, record: this.record(this.get(id)!) } as const;
    });
  }
  async listPending(options: Parameters<Queue['listPending']>[0] = {}) {
    return this.rows('pending', options.orderBy, options.limit).map(row => this.record(row));
  }
  async listClaims() { return this.rows('claimed').map(row => this.claimed(row)); }
  async listFailed(options: Parameters<NonNullable<Queue['listFailed']>>[0] = {}) {
    return this.rows('failed', 'received', options.limit).map(row => ({ ...this.record(row), ...this.failed(row) }));
  }
  private take(row: Row, ownerId = `qntm:${process.pid}`, laneKey = row.lane_key) {
    const now = this.now();
    const token = randomUUID();
    this.db.prepare(`UPDATE ingress SET status='claimed', token=?, owner_id=?, claimed_at=?,
      updated_at=?, lane_key=? WHERE id=? AND status='pending'`).run(token, ownerId, now, now, laneKey, row.id);
    return this.claimed(this.get(row.id)!);
  }
  async claim(id: string, options: Options<'claim'> = {}) {
    return this.transaction(() => {
      const row = this.get(id);
      return row?.status === 'pending' ? this.take(row, options.ownerId) : null;
    });
  }
  async claimNext(options: Parameters<Queue['claimNext']>[0] = {}) {
    return this.transaction(() => {
      const blocked = new Set(options.blockedLaneKeys);
      const candidates = options.candidateIds ? new Set(options.candidateIds) : undefined;
      // Existing claims also block their lane across monitor/process restarts.
      for (const row of this.rows('claimed')) if (row.lane_key) blocked.add(row.lane_key);
      let scanned = 0;
      for (const row of this.rows('pending', options.orderBy)) {
        if (candidates && !candidates.has(row.id)) continue;
        if (++scanned > (options.scanLimit ?? Infinity)) break;
        const record = this.record(row);
        const derived = options.deriveLaneKey?.(record);
        if (derived && row.lane_key && derived !== row.lane_key &&
          options.reconcileStoredLaneKey?.(record, row.lane_key, derived) !== true) continue;
        const lane = derived ?? row.lane_key;
        if (lane && blocked.has(lane)) continue;
        return this.take(row, options.ownerId, lane);
      }
      return null;
    });
  }
  async refreshClaim(ref: ChannelIngressQueueClaimRef, options: Options<'refreshClaim'> = {}) {
    return this.update(ref, row => row.status === 'claimed', 'claimed_at=?, updated_at=?',
      [options.refreshedAt ?? this.now(), options.refreshedAt ?? this.now()]);
  }
  private update(ref: Ref, allowed: (row: Row) => boolean, assignments: string, values: SQLInputValue[]): boolean {
    return this.transaction(() => {
      const id = typeof ref === 'string' ? ref : ref.id;
      const row = this.get(id);
      if (!this.matches(row, ref) || !allowed(row)) return false;
      this.db.prepare(`UPDATE ingress SET ${assignments} WHERE id=?`).run(...values, id);
      return true;
    });
  }
  async complete(ref: Ref, options: Options<'complete'> = {}) {
    const now = options.completedAt ?? this.now();
    return this.update(ref, row => row.status === 'pending' || row.status === 'claimed',
      "status='completed', payload=NULL, metadata=?, completed_at=?, updated_at=?, token=NULL, owner_id=NULL, claimed_at=NULL, last_error=NULL",
      [options.metadata === undefined ? null : JSON.stringify(options.metadata), now, now]);
  }
  async release(ref: Ref, options: Options<'release'> = {}) {
    const now = options.releasedAt ?? this.now();
    // Do not persist host exceptions, which can contain message or credential text.
    return this.update(ref, row => row.status === 'claimed',
      "status='pending', attempts=attempts+?, last_attempt_at=?, last_error=?, updated_at=?, token=NULL, owner_id=NULL, claimed_at=NULL",
      [options.recordAttempt === false ? 0 : 1, now, options.lastError ? 'qntm host delivery failed' : null, now]);
  }
  async fail(ref: Ref, options: Options<'fail'>) {
    const now = options.failedAt ?? this.now();
    return this.update(ref, row => row.status === 'pending' || row.status === 'claimed',
      "status='failed', reason=?, message=?, failed_at=?, updated_at=?, token=NULL, owner_id=NULL, claimed_at=NULL, last_error=NULL",
      ['host_delivery_failed', options.message ? 'qntm host delivery failed' : null, now, now]);
  }
  async resubmit(id: string, options: Options<'resubmit'> = {}) {
    return this.transaction(() => {
      const row = this.get(id);
      if (!row) return { kind: 'not-found' } as const;
      if (row.status === 'completed') return { kind: 'completed', record: this.completed(row) } as const;
      if (row.status !== 'failed') return { kind: 'active', status: row.status } as const;
      const count = this.db.prepare("SELECT count(*) AS n FROM ingress WHERE status IN ('pending','claimed')").get()!.n as number;
      if (count >= this.maxPending) throw new Error('qntm host ingress queue is full');
      const previous = { ...this.record(row), ...this.failed(row) };
      this.db.prepare(`UPDATE ingress SET status='pending', attempts=0, last_attempt_at=NULL,
        failed_at=NULL, reason=NULL, message=NULL, updated_at=? WHERE id=?`).run(options.resubmittedAt ?? this.now(), id);
      return { kind: 'resubmitted', previous, record: this.record(this.get(id)!) } as const;
    });
  }
  async delete(ref: Parameters<Queue['delete']>[0]) {
    return this.transaction(() => {
      const id = typeof ref === 'string' ? ref : ref.id;
      const row = this.get(id);
      if (!this.matches(row, typeof ref !== 'string' && 'claim' in ref ? ref : id)) return false;
      return this.db.prepare('DELETE FROM ingress WHERE id=?').run(id).changes > 0;
    });
  }
  async recoverStaleClaims(options: Parameters<Queue['recoverStaleClaims']>[0] = {}) {
    const now = options.now ?? this.now();
    let recovered = 0;
    for (const row of this.rows('claimed')) {
      if (now - row.claimed_at! < (options.staleMs ?? 300_000)) continue;
      const claim = this.claimed(row);
      if (options.shouldRecover && !await options.shouldRecover(claim)) continue;
      // Recheck the token and heartbeat after the asynchronous owner check.
      recovered += Number(this.update(claim, current => current.claimed_at === row.claimed_at,
        "status='pending', token=NULL, owner_id=NULL, claimed_at=NULL, updated_at=?", [now]));
    }
    return recovered;
  }
  async prune(options: Parameters<Queue['prune']>[0] = {}) {
    return this.transaction(() => {
      const now = options.now ?? this.now();
      const protect = new Set(options.protectIds);
      let removed = 0;
      for (const status of ['pending', 'completed', 'failed'] as const) {
        const ttl = options[`${status}TtlMs`];
        const maximum = options[`${status}MaxEntries`];
        const rows = this.rows(status).sort((a, b) =>
          (status === 'pending' ? a.received_at - b.received_at :
            status === 'completed' ? a.completed_at! - b.completed_at! : a.failed_at! - b.failed_at!));
        let excess = maximum === undefined ? 0 : Math.max(0, rows.length - maximum);
        for (const row of rows) {
          if (protect.has(row.id)) continue;
          const timestamp = status === 'pending' ? row.received_at : status === 'completed' ? row.completed_at! : row.failed_at!;
          if ((ttl !== undefined && now - timestamp >= ttl) || excess > 0) {
            removed += Number(this.db.prepare('DELETE FROM ingress WHERE id=?').run(row.id).changes);
            excess -= 1;
          }
        }
      }
      return removed;
    });
  }
}
