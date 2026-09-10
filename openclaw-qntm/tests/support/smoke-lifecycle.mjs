import { DatabaseSync } from 'node:sqlite';

// Test-only lock for the disposable host session store. A reply can reach the
// relay before the host finishes its session writes; callers wait for BUSY,
// then hold the acquired transaction until the deliberate crash is complete.
export function createSqliteWriteLock(path) {
  let database = new DatabaseSync(path);
  let acquired = false;
  return {
    tryAcquire() {
      if (!database) throw new Error('Smoke session lock is closed');
      if (acquired) return true;
      try {
        database.exec('BEGIN IMMEDIATE');
        acquired = true;
        return true;
      } catch (error) {
        // Include extended SQLITE_BUSY codes, but never hide other SQL errors.
        if (error.code === 'ERR_SQLITE_ERROR' && (error.errcode & 0xff) === 5) return false;
        throw error;
      }
    },
    close() {
      const closing = database;
      database = undefined; // Cleanup stays idempotent even if rollback fails.
      if (!closing) return;
      const failures = [];
      if (acquired) {
        try { closing.exec('ROLLBACK'); } catch (error) { failures.push(error); }
      }
      acquired = false;
      try { closing.close(); } catch (error) { failures.push(error); }
      if (failures.length) throw new AggregateError(failures, 'Smoke session lock cleanup failed');
    },
  };
}

// Release every owned resource after partial setup or failure. If the smoke
// already failed, the caller's original exception remains the primary result.
export async function cleanupSmoke(actions, { failed = false, report = console.error } = {}) {
  const failures = [];
  for (const action of actions) {
    try { await action(); } catch (error) { failures.push(error); }
  }
  if (!failures.length) return;
  const error = new AggregateError(failures, 'Native OpenClaw smoke cleanup failed');
  if (failed) report(error);
  else throw error;
}
