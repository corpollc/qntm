import { setTimeout as delay } from 'node:timers/promises';

export async function waitFor(
  predicate: () => boolean,
  timeoutMs = 10_000,
  intervalMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await delay(intervalMs);
  }
  throw new Error(`Timed out after ${timeoutMs}ms`);
}
