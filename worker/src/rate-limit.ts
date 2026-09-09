/** Best-effort, per-isolate protection; this is not a global quota. */
export const MAX_RATE_LIMIT_IPS = 10_000;
export const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_IP_LENGTH = 64;

export class RelayRateLimiter {
	private readonly entries = new Map<string, { count: number; resetAt: number }>();
	private lastNow = 0;
	constructor(private readonly clock: () => number = Date.now) {}

	get size(): number { return this.entries.size; }

	check(ip: string, maxPerMinute: number): boolean {
		// Clamp backward clock adjustments so insertion order remains expiry order.
		const now = this.lastNow = Math.max(this.lastNow, this.clock());
		for (const [key, entry] of this.entries) {
			if (entry.resetAt > now) break;
			this.entries.delete(key);
		}
		if (!ip || ip.length > MAX_IP_LENGTH || !Number.isSafeInteger(maxPerMinute) || maxPerMinute < 1) return false;
		const entry = this.entries.get(ip);
		if (entry) {
			if (entry.count >= maxPerMinute) return false;
			entry.count++;
			return true;
		}
		// Never evict an active counter to admit a new IP: that would let churn
		// reset another client's limit. Unknown IPs receive 429 until space expires.
		if (this.entries.size >= MAX_RATE_LIMIT_IPS) return false;
		this.entries.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
		return true;
	}
}
