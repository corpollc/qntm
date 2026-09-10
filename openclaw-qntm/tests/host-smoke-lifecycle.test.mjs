import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, expect, test } from 'vitest';
import { cleanupSmoke, createSqliteWriteLock } from './support/smoke-lifecycle.mjs';

const resources = [];
afterEach(async () => { await cleanupSmoke(resources.splice(0).reverse()); });
function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'qntm-smoke-lock-'));
  resources.push(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'sessions.sqlite');
  const writer = new DatabaseSync(path);
  resources.push(() => writer.close());
  writer.exec('PRAGMA journal_mode=WAL; CREATE TABLE sessions (id TEXT)');
  const lock = createSqliteWriteLock(path);
  resources.push(() => lock.close());
  return { writer, lock };
}

test('waits for an existing session writer, then holds the deliberate crash lock', () => {
  const { writer, lock } = fixture();
  writer.exec('BEGIN IMMEDIATE');
  expect(lock.tryAcquire()).toBe(false);
  writer.exec('COMMIT');
  expect(lock.tryAcquire()).toBe(true);
  expect(lock.tryAcquire()).toBe(true);
  expect(() => writer.exec('BEGIN IMMEDIATE')).toThrow(/database is locked/);
  lock.close();
  lock.close();
  writer.exec('BEGIN IMMEDIATE; ROLLBACK');
  expect(() => lock.tryAcquire()).toThrow(/closed/);
});

test('cleans up failed acquisition without rolling back a transaction it never owned', () => {
  const { writer, lock } = fixture();
  writer.exec('BEGIN IMMEDIATE');
  expect(lock.tryAcquire()).toBe(false);
  expect(() => lock.close()).not.toThrow();
  writer.exec("INSERT INTO sessions VALUES ('still owned by host'); COMMIT");
  expect(writer.prepare('SELECT id FROM sessions').get().id).toBe('still owned by host');
});

test('cleans up a connection even when acquisition has not started', () => {
  const { writer, lock } = fixture();
  expect(() => lock.close()).not.toThrow();
  writer.exec('BEGIN IMMEDIATE; ROLLBACK');
});

test('does not retry or mask non-contention database errors', () => {
  const directory = mkdtempSync(join(tmpdir(), 'qntm-smoke-invalid-db-'));
  resources.push(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'sessions.sqlite');
  writeFileSync(path, 'invalid session database'.repeat(200));
  const lock = createSqliteWriteLock(path);
  resources.push(() => lock.close());
  expect(() => lock.tryAcquire()).toThrow(/not a database/);
  expect(() => lock.close()).not.toThrow();
});

test('preserves the original smoke error and runs every cleanup after partial setup', async () => {
  const { writer, lock } = fixture();
  writer.exec('BEGIN IMMEDIATE');
  expect(lock.tryAcquire()).toBe(false);
  const original = new Error('Host admission failed');
  const secondary = new Error('Host shutdown failed');
  const reported = [], closed = [];
  await expect((async () => {
    try { throw original; }
    finally {
      await cleanupSmoke([
        () => lock.close(),
        () => { throw secondary; },
        () => closed.push('relay'),
        () => undefined, // Provider construction never completed.
        () => closed.push('temporary state'),
      ], { failed: true, report: error => reported.push(error) });
    }
  })()).rejects.toBe(original);
  expect(closed).toEqual(['relay', 'temporary state']);
  expect(reported).toHaveLength(1);
  expect(reported[0].errors).toEqual([secondary]);
  writer.exec('ROLLBACK');
});

test('reports cleanup failure as a failure when the smoke itself succeeded', async () => {
  const failure = new Error('Close failed');
  let released = false;
  await expect(cleanupSmoke([
    () => { throw failure; },
    () => { released = true; },
  ])).rejects.toMatchObject({ errors: [failure] });
  expect(released).toBe(true);
});
